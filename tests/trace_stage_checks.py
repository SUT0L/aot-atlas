import argparse
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path


def facts(value):
    if isinstance(value, dict):
        return {
            key: facts(item) for key, item in value.items()
            if key != "input_sha256" and "seconds" not in key and key != "allocated_bytes"
        }

    if isinstance(value, list):
        return [facts(item) for item in value]

    return value


def graph_references(output):
    graph = output.get("signature_graph")

    if graph is None:
        return

    nodes = {node["id"]: node for node in graph["types"]}
    scopes = {
        scope["handle"] for kind in ("scope_definitions", "scope_references") for scope in graph[kind]
    }

    for node in nodes.values():
        assert node["element"] == 0 or node["element"] in nodes

        if node["kind"] == "Modified":
            assert node["value"] == 0 or node["value"] in nodes

        for key in ("arguments", "varargs"):
            assert all(edge == 0 or edge in nodes for edge in node[key])

        assert "scope" not in node or node["scope"] in scopes

    methods = {method["id"]: method for method in graph["methods"]}

    for method in methods.values():
        assert method["return_type"] == 0 or method["return_type"] in nodes

        for key in ("parameters", "varargs"):
            assert all(edge == 0 or edge in nodes for edge in method[key])

    assert all(node == 0 or node in nodes for node in graph["handles"].values())

    encoded = json.dumps(output)
    type_references = {int(item) for item in re.findall(r"(?<!method_)sig_ref_(\d+)", encoded)}
    method_references = {int(item) for item in re.findall(r"method_sig_ref_(\d+)", encoded)}
    assert type_references <= nodes.keys(), "An abbreviated type signature has no published graph node."
    assert method_references <= methods.keys(), "An abbreviated method signature has no published graph method."


def check(cli, binary, directory):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    output = directory / "output.json"

    def run(command, source, failure=False):
        previous = output.read_bytes() if output.exists() else None
        result = subprocess.run(prefix + [command, str(source), str(output)], capture_output=True, text=True)
        assert result.returncode == (1 if failure else 0), (command, result.stdout, result.stderr)
        assert not list(directory.glob("*.tmp")), "Unpublished temporary output remains."

        if failure:
            assert "Stack-trace entrypoint" in result.stderr, result.stderr
            assert output.read_bytes() == previous, "Failed tracing replaced prior output."
            return None

        parsed = json.loads(output.read_bytes())
        graph_references(parsed)

        return parsed

    original = binary.read_bytes()
    nt = struct.unpack_from("<I", original, 60)[0]
    optional = nt + 24
    image_base = struct.unpack_from("<Q", original, optional + 24)[0]
    section_count = struct.unpack_from("<H", original, nt + 6)[0]
    section_start = optional + struct.unpack_from("<H", original, nt + 20)[0]
    sections = [
        struct.unpack_from("<IIII", original, section_start + index * 40 + 8)
        for index in range(section_count)
    ]

    def offset(address):
        rva = address - image_base

        for virtual_size, start, file_size, file_start in sections:
            if start <= rva < start + min(virtual_size or file_size, file_size):
                return file_start + rva - start

        raise AssertionError(f"Unmapped trace fixture address {address:X}")

    trace = next((section for section in run("sections", binary)["sections"] if section["id"] == 327), None)
    independent = ("types", "fields", "frozen", "gvm", "templates", "dictionaries", "dispatch", "statics")
    healthy = {command: run(command, binary) for command in independent}

    for value in healthy.values():
        assert value["extraction_stages"]["method_tracing"] == "not_requested"

    if trace is None or trace["length"] <= 4:
        assert run("methods", binary)["extraction_stages"]["method_tracing"] == "available"
        print(f"{binary}: absent or present-empty trace source; independent queries and requested tracing succeed.")
        return

    changed = bytearray(original)
    last_entrypoint = offset(trace["start"]) + trace["length"] - 4
    changed[last_entrypoint:last_entrypoint + 4] = bytes(4)
    damaged = directory / "late-trace-failure.exe"
    damaged.write_bytes(changed)

    for command in independent:
        assert facts(run(command, damaged)) == facts(healthy[command]), command

    for command in ("methods", "extract", "properties", "code"):
        restored = run(command, binary)
        run(command, damaged, failure=True)
        assert facts(run(command, binary)) == facts(restored), command

    print(f"{binary}: eight independent queries preserve facts through late trace corruption; four tracing queries fail atomically and recover after restoring the source.")


# Type and method IDs are independent namespaces: coincidentally equal numbers do not resolve a reference.
def reference_kind_checks():
    node = {"id": 1, "kind": "Named", "element": 0, "arguments": [], "varargs": []}
    graph = {
        "types": [node],
        "methods": [{"id": 7, "return_type": 1, "parameters": [], "varargs": []}],
        "handles": {},
        "scope_definitions": [],
        "scope_references": []
    }
    graph_references({"signature": "method_sig_ref_7", "signature_graph": graph})

    # Zero denotes an absent native type; it is not serialized as a type node.
    graph["methods"].append({"id": 8, "return_type": 0, "parameters": [0], "varargs": []})
    graph["handles"]["null-alias"] = 0
    graph_references({"signature_graph": graph})

    graph["methods"][1]["parameters"] = [2]

    try:
        graph_references({"signature_graph": graph})
    except AssertionError:
        pass
    else:
        raise AssertionError("An unknown nonzero native edge was accepted.")

    graph["methods"] = []
    graph["types"].append(dict(node, id=7))

    try:
        graph_references({"signature": "method_sig_ref_7", "signature_graph": graph})
    except AssertionError:
        pass
    else:
        raise AssertionError("A type ID incorrectly resolved a missing method ID.")


reference_kind_checks()
parser = argparse.ArgumentParser()
parser.add_argument("cli", type=Path)
parser.add_argument("binaries", type=Path, nargs="+")
args = parser.parse_args()

with tempfile.TemporaryDirectory(prefix="aot-trace-stages-") as temporary:
    for index, binary in enumerate(args.binaries):
        directory = Path(temporary) / str(index)
        directory.mkdir()
        check(args.cli.resolve(), binary.resolve(), directory)
