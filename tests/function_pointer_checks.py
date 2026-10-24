import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path

if not __debug__:
    raise RuntimeError("Tests require Python assertions; disable optimisation.")


def check(cli, binary, directory):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    output = directory / "output.json"

    def run(source, command="fat-function-pointers", failure=False):
        previous = output.read_bytes() if output.exists() else None
        result = subprocess.run(
            prefix + [command, str(source), str(output)], capture_output=True, text=True
        )
        assert result.returncode == (1 if failure else 0), (command, result.stderr)
        assert not list(directory.glob("*.tmp")), "Unpublished temporary output remains."

        if failure:
            assert output.read_bytes() == previous, "A fatal source fault replaced prior output."
            return None

        return json.loads(output.read_bytes())

    data = binary.read_bytes()
    nt = struct.unpack_from("<I", data, 60)[0]
    optional = nt + 24
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    count = struct.unpack_from("<H", data, nt + 6)[0]
    section_start = optional + struct.unpack_from("<H", data, nt + 20)[0]
    sections = [struct.unpack_from("<IIII", data, section_start + 40 * index + 8) for index in range(count)]

    def file_offset(address):
        rva = address - image_base

        for virtual_size, start, file_size, file_start in sections:
            if start <= rva < start + min(virtual_size or file_size, file_size):
                return file_start + rva - start

        raise AssertionError(f"Unmapped fixture address {address:X}")

    def changed(name, offset, replacement):
        modified = bytearray(data)
        modified[offset:offset + len(replacement)] = replacement
        source = directory / (name + ".exe")
        source.write_bytes(modified)

        return source

    def pairs(value, sources):
        pointers = value["pointers"]

        return {
            (
                pointers[reference["pointer"]]["pointer"],
                pointers[reference["pointer"]]["body"],
                pointers[reference["pointer"]]["context"],
                reference["source"], reference["owner"], reference["consumer"]
            )
            for reference in value["references"] if reference["source"] in sources
        }

    rows = run(binary, "sections")["sections"]
    healthy = run(binary)
    aggregate = run(binary, "extract")
    assert aggregate["fat_function_pointers"] == healthy, "Full extraction changed standalone pointer facts."

    for command, section in (("gcinfo", "gcinfo"), ("generic-context", "generic_context")):
        assert run(binary, command) == aggregate[section], (command, "Full/standalone evidence differs.")

    def check_contexts_without_delegates(source):
        contexts = run(source, "generic-context")
        healthy_contexts = aggregate["generic_context"]
        assert contexts["delegate_consumers_status"] == "unavailable" and contexts.get("delegate_consumers_error")

        for key in (
            "image_base", "gcinfo_version", "region_source", "gc_headers_status",
            "declared_method_contexts", "proven_context_parameters", "parameters",
            "unresolved_context_parameters", "unavailable_gc_headers",
            "unresolved_control_flow_owners", "references", "dictionary_context_slot_accesses",
            "dictionary_context_transfers", "initial_dictionary_context_transfers"
        ):
            assert contexts[key] == healthy_contexts[key], (key, "Optional delegate fault changed independent context facts.")

        assert contexts["dictionary_context_relations"] == [
            relation for relation in healthy_contexts["dictionary_context_relations"]
            if relation["kind"] != "delegate_slot"
        ]
        assert not contexts["dictionary_delegate_slots"] and not contexts["initial_dictionary_delegate_slots"]

    trace = next((row for row in rows if row["id"] == 327 and row["length"] > 4), None)

    if trace:
        damaged_source = changed("late-trace", file_offset(trace["start"]) + trace["length"] - 4, bytes(4))
        damaged = run(damaged_source)
        independent = {"class_constructor", "indirect_call"}
        assert pairs(damaged, independent) == pairs(healthy, independent)
        assert damaged["delegate_consumers_status"] == "unavailable" and damaged.get("delegate_consumers_error")
        check_contexts_without_delegates(damaged_source)
        aggregate_damaged = run(damaged_source, "extract")
        assert aggregate_damaged["fat_function_pointers"] == damaged
        assert aggregate_damaged["generic_context"] == run(damaged_source, "generic-context")
        assert aggregate_damaged["analysis_status"]["status"] == "partial"
        assert aggregate_damaged["extraction_stages"]["method_tracing"] == "unavailable"
        assert aggregate_damaged["extraction_stages"]["signature_graph_closure"] == "partial_method_tracing"
        assert any(failure["phase"] == "method_tracing"
                   for failure in aggregate_damaged["analysis_status"]["failures"])
        strict = subprocess.run(prefix + ["extract", str(damaged_source), str(output),
                                          "--require-complete"], capture_output=True, text=True)
        assert strict.returncode == 3, strict.stderr
        strict_output = json.loads(output.read_bytes())
        assert strict_output["analysis_status"] == aggregate_damaged["analysis_status"]
        assert strict_output["fat_function_pointers"] == damaged
        assert strict_output["generic_context"] == aggregate_damaged["generic_context"]

    pdata = struct.unpack_from("<I", data, optional + 136)[0]
    unwind = struct.unpack_from("<I", data, file_offset(image_base + pdata) + 8)[0]
    assert unwind & 1 == 0, "Fixture needs a direct first unwind header."
    offset = file_offset(image_base + unwind)
    damaged_source = changed("bad-unwind", offset, bytes([(data[offset] & ~7) | 7]))

    damaged = run(damaged_source)
    assert pairs(damaged, {"class_constructor"}) == pairs(healthy, {"class_constructor"})
    assert all(reference["source"] == "class_constructor" for reference in damaged["references"])
    assert damaged["gc_headers_status"] == "unavailable" and damaged["failures"]
    assert run(damaged_source, "extract")["fat_function_pointers"] == damaged

    constructors = next(row for row in rows if row["id"] == 310)
    partial = run(changed("bad-cctor-table", file_offset(constructors["start"]), b"\xff"))
    assert partial["constructor_map_status"] == "partial" and partial["failures"]
    assert pairs(partial, {"indirect_call", "delegate_initializer"}) == pairs(
        healthy, {"indirect_call", "delegate_initializer"}
    )

    run(changed("bad-pe", 0, b"!!"), failure=True)
    restored = run(binary)
    assert restored == healthy, "Restored output differs from healthy source."

    print(f"{binary}: full/standalone evidence, trace/unwind source faults, constructor isolation, atomic publication and exact recovery passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binaries", type=Path, nargs="+")
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="atlas-function-pointer-checks-") as temporary:
        for index, binary in enumerate(arguments.binaries):
            directory = Path(temporary) / str(index)
            directory.mkdir()
            check(arguments.cli.resolve(), binary.resolve(), directory)
