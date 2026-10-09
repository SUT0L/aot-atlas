import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path


def normalized(value):
    if isinstance(value, dict):
        return {
            key: (
                ", ".join(part for part in item.split(", ") if part != "ExceptionHandling")
                if key == "source" and isinstance(item, str) else normalized(item)
            )
            for key, item in value.items()
            if key != "input_sha256" and "seconds" not in key and key != "allocated_bytes"
        }

    if isinstance(value, list):
        return [normalized(item) for item in value]

    return value


def template_facts(document, templates):
    graph = document.get("signature_graph", {})
    types = {node["id"]: node for node in graph.get("types", [])}
    type_facts = {}

    def type_fact(index):
        if index == 0:
            return None
        if index in type_facts:
            return type_facts[index]

        assert index in types, ("Template reference has no owning graph node", index)
        fact = {key: value for key, value in types[index].items() if key != "id"}
        fact["element"] = type_fact(fact["element"])
        if fact["kind"] == "Modified":
            fact["value"] = type_fact(fact["value"])
        for edge in ("arguments", "varargs"):
            fact[edge] = [type_fact(child) for child in fact[edge]]

        type_facts[index] = fact
        return fact

    def relation_fact(relation):
        assert relation["signature_id"] > 0
        fact = dict(relation)
        fact["resolved_signature"] = type_fact(fact.pop("signature_id"))
        return fact

    return [
        {
            **template,
            "base_type": relation_fact(template["base_type"]) if template["base_type"] else None,
            "interfaces": [relation_fact(relation) for relation in template["interfaces"]]
        }
        for template in templates["type_templates"]
    ]


def template_facts_oracle():
    # Function-pointer Element is the return type; an overlapping method ID
    # must not replace it. NativeLayout and metadata use this flattened shape.
    common = {
        "element": 0, "value": 0, "optional": False, "native_convention": False,
        "arguments": [], "varargs": [], "sizes": [], "lower_bounds": []
    }
    document = {
        "signature_graph": {
            "types": [
                {**common, "id": 7, "kind": "Named", "name": "B", "type_address": 0x1111},
                {**common, "id": 8, "kind": "Named", "name": "A", "type_address": 0x2222},
                {**common, "id": 9, "kind": "Named", "name": "I", "type_address": 0x3333},
                {**common, "id": 10, "kind": "FunctionPointer", "element": 7, "arguments": [8],
                    "value": 6, "native_convention": True},
                {**common, "id": 11, "kind": "Instantiation", "element": 9, "arguments": [10]}
            ],
            "methods": [{"id": 7, "return_type": 8, "parameters": [], "varargs": []}]
        },
        "type_templates": [{
            "base_type": None,
            "interfaces": [{"signature_id": 11, "native_offset": 17, "signature": "I<delegate*<A,B>>"}]
        }]
    }
    relation = template_facts(document, document)[0]["interfaces"][0]["resolved_signature"]
    function = relation["arguments"][0]
    assert function["kind"] == "FunctionPointer"
    assert function["element"]["type_address"] == 0x1111
    assert function["arguments"][0]["type_address"] == 0x2222
    assert function["value"] == 6 and function["native_convention"]


def check(cli, binary, directory):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    output = directory / "output.json"

    def run(command, source, *arguments, failure=False):
        previous = output.read_bytes() if output.exists() else None
        result = subprocess.run(
            prefix + [command, str(source), str(output), *arguments], capture_output=True, text=True
        )
        assert result.returncode == (1 if failure else 0), (command, result.stdout, result.stderr)
        assert not list(directory.glob("*.tmp")), "Unpublished temporary output remains."

        if failure:
            assert result.stderr.strip(), "Failure has no diagnostic."
            assert (output.read_bytes() if output.exists() else None) == previous, "Failure replaced prior output."
            return None

        return json.loads(output.read_bytes())

    original = binary.read_bytes()
    nt = struct.unpack_from("<I", original, 60)[0]
    optional = nt + 24
    section_count = struct.unpack_from("<H", original, nt + 6)[0]
    section_start = optional + struct.unpack_from("<H", original, nt + 20)[0]
    sections = [
        struct.unpack_from("<IIII", original, section_start + index * 40 + 8)
        for index in range(section_count)
    ]

    def offset(rva):
        for virtual_size, start, file_size, file_start in sections:
            if start <= rva < start + min(virtual_size or file_size, file_size):
                return file_start + rva - start

        raise AssertionError(f"Unmapped fixture RVA {rva:X}")

    def mutated(name, edit):
        data = bytearray(original)
        edit(data)
        path = directory / (name + ".exe")
        path.write_bytes(data)

        return path

    healthy = run("extract", binary)
    assert healthy["analysis_status"]["status"] == "complete"
    assert healthy["exceptions"]["frames"], "Fixture needs a recoverable managed code range."
    assert healthy["gcinfo"]["status"] == "complete"
    assert healthy["gcinfo"]["methods"], "Fixture needs method GC information."

    pdata_rva = struct.unpack_from("<I", original, optional + 136)[0]
    unwind_rva = struct.unpack_from("<I", original, offset(pdata_rva) + 8)[0]
    assert unwind_rva & 1 == 0, "Fixture needs a direct first unwind header."
    first_unwind = offset(unwind_rva)
    healthy_helpers = run("runtime-helpers", binary)

    healthy_properties = run("properties", binary)

    def bad_imports(data):
        struct.pack_into("<II", data, optional + 112 + 8, 0x1000, 0)

    import_damaged = mutated("bad-imports", bad_imports)
    assert normalized(run("properties", import_damaged)) == normalized(healthy_properties), \
        "Unrelated import corruption changed property projection."
    assert healthy_properties["extraction_stages"]["linkage"] == "not_requested", \
        "Property projection still requests linkage."
    run("linkage", import_damaged, failure=True)

    def bad_unwind(data):
        data[first_unwind] = (data[first_unwind] & ~7) | 7

    damaged = mutated("unsupported-unwind", bad_unwind)
    partial = run("extract", damaged)
    assert partial["analysis_status"]["status"] == "partial"
    assert partial["analysis_status"]["failures"][0]["phase"] == "unwind"

    for section in (
        "metadata", "maps", "types", "fields", "frozen", "dispatch", "statics", "resources", "dictionaries"
    ):
        assert normalized(partial[section]) == normalized(healthy[section]), section

    assert "code" not in partial and "exceptions" not in partial
    healthy_templates = template_facts(healthy, healthy["methods"])
    assert template_facts(partial, partial["templates"]) == healthy_templates
    for source in (binary, damaged):
        templates = run("templates", source)
        assert template_facts(templates, templates) == healthy_templates
    run("code", damaged, failure=True)
    run("runtime-helpers", damaged, failure=True)

    metadata_section = next(section for section in healthy["sections"]["sections"] if section["id"] == 313)
    metadata_offset = offset(metadata_section["start"] - healthy["gcinfo"]["image_base"])

    def metadata_only(data):
        data[metadata_offset:metadata_offset + 4] = b"BAD!"

    metadata_damaged = mutated("bad-metadata-independent", metadata_only)
    assert normalized(run("runtime-helpers", metadata_damaged)) == normalized(healthy_helpers), (
        "Runtime helper discovery unnecessarily depends on embedded metadata"
    )
    run("extract", metadata_damaged, failure=True)

    def bad_metadata(data):
        bad_unwind(data)
        data[metadata_offset:metadata_offset + 4] = b"BAD!"

    run("extract", mutated("bad-metadata", bad_metadata), failure=True)

    # Search still returns independent names; code-derived values must be unavailable.
    query = healthy["maps"]["types"][0][3]

    if query:
        healthy_search = run("search", binary, query)
        damaged_search = run("search", damaged, query)
        assert damaged_search["analysis_status"]["status"] == "partial"

        independent = {
            "type", "method", "constructor", "virtual_method", "marshalling", "field", "frozen_string", "cstring"
        }
        excluded = {"reference_count", "unboxed_entrypoint"}

        def matches(search):
            return [
                {key: value for key, value in match.items() if key not in excluded}
                for match in search["matches"] if match["kind"] in independent
            ]

        assert matches(damaged_search) == matches(healthy_search)
        assert all(
            match["reference_count"] is None
            for match in damaged_search["matches"] if "reference_count" in match
        )

    def bad_debug(data):
        struct.pack_into("<I", data, optional + 164, 27)

    debug_damaged = mutated("bad-debug", bad_debug)
    recovered = run("extract", debug_damaged)
    assert recovered["analysis_status"]["status"] == "partial"
    assert recovered["analysis_status"]["managed_unwind"] == "available"
    assert recovered["exceptions"]["frames"] == healthy["exceptions"]["frames"]
    assert normalized(recovered["gcinfo"]["methods"]) == normalized(healthy["gcinfo"]["methods"])
    assert recovered["exceptions"]["region_source"] == "startup::RhRegisterOSModule"
    assert recovered["exceptions"]["registration_file_offset"] == offset(
        healthy_helpers["registration"] - healthy["gcinfo"]["image_base"]
    )
    assert "region_section_index" not in recovered["exceptions"], "Startup provenance was labeled as a section index."

    # A GC blob fault should affect its own method, without losing other methods or EH.
    gc_offset = offset(healthy["gcinfo"]["methods"][0]["gcinfo_rva"])

    def bad_gc(data):
        bit_start = gc_offset * 8 + (11 if data[gc_offset] & 1 else 2)

        for bit in range(bit_start, bit_start + 9):
            data[bit // 8] &= ~(1 << (bit % 8))

    gc_damaged = mutated("bad-gc", bad_gc)
    gc = run("gcinfo", gc_damaged)
    assert gc["status"] == "partial"

    address = healthy["gcinfo"]["methods"][0]["gcinfo_rva"]

    for damaged_method, healthy_method in zip(gc["methods"], healthy["gcinfo"]["methods"], strict=True):
        if healthy_method["gcinfo_rva"] == address:
            assert damaged_method["status"] == "unavailable"
        else:
            assert normalized(damaged_method) == normalized(healthy_method)

    assert normalized(run("exceptions", gc_damaged)) == normalized(healthy["exceptions"])
    aggregate = run("extract", gc_damaged)
    assert aggregate["analysis_status"]["status"] == "partial"
    assert aggregate["gcinfo"]["status"] == "partial"
    assert run("runtime-helpers", binary) == healthy_helpers, "Restored narrow helper discovery changed its facts."

    print(f"{binary.name}: partial extraction, independent search/templates, debug recovery, shared GC blob faults and publication checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NativeAOT extraction availability checks")
    parser.add_argument("cli", type=Path)
    parser.add_argument("binaries", type=Path, nargs="+")
    arguments = parser.parse_args()
    template_facts_oracle()

    with tempfile.TemporaryDirectory(prefix="atlas-availability-") as temporary:
        for binary in arguments.binaries:
            check(arguments.cli.resolve(), binary.resolve(), Path(temporary))
