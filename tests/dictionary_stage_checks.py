import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

if not __debug__:
    raise RuntimeError("Tests require Python assertions; disable optimisation.")


def facts(value):
    if isinstance(value, dict):
        return {
            key: facts(item) for key, item in value.items()
            if key not in {"input_sha256", "extraction_stages", "allocated_bytes"}
            and not key.endswith("_seconds")
        }

    if isinstance(value, list):
        return [facts(item) for item in value]

    return value


def file_offset(data, address):
    nt = struct.unpack_from("<I", data, 60)[0]
    count = struct.unpack_from("<H", data, nt + 6)[0]
    optional = nt + 24
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    table = optional + struct.unpack_from("<H", data, nt + 20)[0]
    rva = address - image_base

    for index in range(count):
        virtual_size, start, size, offset = struct.unpack_from("<IIII", data, table + index * 40 + 8)

        if start <= rva < start + min(virtual_size or size, size):
            return offset + rva - start

    raise AssertionError("Dictionary recipe is not file-backed")


def run(cli, command, binary, output, success=True, json_output=True):
    result = subprocess.run(
        ["dotnet", cli, command, str(binary), str(output)], capture_output=True, text=True
    )
    assert (result.returncode == 0) == success, (command, result.stderr)

    if success:
        return json.loads(output.read_text()) if json_output else output.read_text()

    assert output.read_bytes() == b"existing output"
    assert not list(output.parent.glob(output.name + ".*.tmp")), "Failed extraction left a temporary output"

    return result.stderr


def check(cli, binary, folder):
    original = Path(binary).read_bytes()
    dictionary = run(cli, "dictionaries", binary, folder / "dictionary.json")
    commands = ["types", "fields", "templates", "dispatch", "frozen", "methods"]
    healthy = {command: run(cli, command, binary, folder / (command + ".json")) for command in commands}
    header = run(cli, "header", binary, folder / "healthy.h", json_output=False)
    assert "// dictionary_signatures: complete" in header

    for value in healthy.values():
        assert value["extraction_stages"]["dictionary_bindings"] == "not_requested"
        assert value["extraction_stages"]["dictionary_signatures"] == "complete"

    statics = [recipe for recipe in dictionary["recipes"] if recipe["kind_name"] == "StaticData"]

    if statics:
        recipe = statics[-1]
        position = file_offset(
            original, dictionary["native_layout"] + recipe["offset"] + recipe["length"] - 1
        )
        assert original[position] in (2, 4), "Fixture needs a single-byte static discriminator"

        damaged = bytearray(original)
        damaged[position] = 6
        source = folder / "invalid-static-kind.exe"
        source.write_bytes(damaged)

        for command in commands:
            recovered = run(cli, command, source, folder / ("recovered-" + command + ".json"))
            assert facts(healthy[command]) == facts(recovered), command
            assert recovered["extraction_stages"]["dictionary_signatures"] == "complete"

        for command in ["dictionaries", "extract"]:
            output = folder / ("strict-" + command + ".json")
            output.write_bytes(b"existing output")
            assert "static-data kind" in run(cli, command, source, output, False)

    if dictionary["recipes"]:
        recipe = dictionary["recipes"][0]
        layout = next(layout for layout in dictionary["layouts"] if layout["recipe_start"] == 0)
        position = file_offset(original, dictionary["native_layout"] + recipe["offset"])
        assert original[position] & 1 == 0, "Fixture needs a one-byte recipe kind"

        damaged = bytearray(original)
        damaged[position] = 0xFC
        source = folder / "unsupported-layout.exe"
        source.write_bytes(damaged)
        expected_gap = {
            "layout_offset": layout["offset"],
            "recipe_offset": recipe["offset"],
            "kind": 0x7E,
            "remaining_slots": layout["slot_count"]
        }

        for command in commands + ["dictionaries"]:
            partial = run(cli, command, source, folder / ("partial-" + command + ".json"))
            status = partial["extraction_stages"]
            assert status["dictionary_signatures"] == "partial"
            assert status["signature_graph_closure"] == "partial_dictionary_signatures"
            assert expected_gap in status["dictionary_signature_gaps"]

        partial_header = run(cli, "header", source, folder / "partial.h", json_output=False)
        assert "// dictionary_signatures: partial" in partial_header

        damaged[position] = 0
        source.write_bytes(damaged)

        for command in ["types", "fields", "dictionaries", "extract"]:
            output = folder / ("bad-grammar-" + command + ".json")
            output.write_bytes(b"existing output")
            assert "reserved null" in run(cli, command, source, output, False)

    restored = run(cli, "dictionaries", binary, folder / "restored.json")
    assert facts(restored) == facts(dictionary)

    print(f"{binary}: six narrow workflows, strict atomic failure, observable closure gaps and restored dictionaries passed")


if __name__ == "__main__":
    assert len(sys.argv) >= 3, "Usage: dictionary_stage_checks.py CLI.dll NativeAot.exe [NativeAot.exe ...]"

    with tempfile.TemporaryDirectory(prefix="atlas-dictionary-stages-") as temporary:
        for index, binary in enumerate(sys.argv[2:]):
            folder = Path(temporary) / str(index)
            folder.mkdir()
            check(sys.argv[1], binary, folder)
