import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError("Tests require Python assertions; disable optimisation.")


def run(command):
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=True)


def file_offset(binary, address):
    pe = struct.unpack_from("<I", binary, 60)[0]
    base = struct.unpack_from("<Q", binary, pe + 48)[0]
    count = struct.unpack_from("<H", binary, pe + 6)[0]
    optional_size = struct.unpack_from("<H", binary, pe + 20)[0]

    for index in range(count):
        offset = pe + 24 + optional_size + index * 40
        rva, length, raw = struct.unpack_from("<III", binary, offset + 12)
        if rva <= address - base < rva + length:
            return raw + address - base - rva

    raise AssertionError(f"Unmapped address: {address:#x}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runtime-probe", type=Path)
    arguments = parser.parse_args()
    cli = [str(arguments.cli.resolve())]
    if arguments.cli.suffix == ".dll":
        cli.insert(0, "dotnet")
    binary = str(arguments.binary.resolve())

    with tempfile.TemporaryDirectory(prefix="atlas-typemaps-cli-") as directory:
        output = Path(directory) / "result.json"

        def extract(operation, *extra):
            run([*cli, operation, binary, str(output), *extra])
            return json.loads(output.read_bytes())

        standalone = extract("typemaps")
        complete = extract("extract")
        assert standalone["operation"] == "typemaps"
        assert complete["analysis_status"]["status"] == "complete", "Decoded invalid groups degraded analysis status."

        for name in ("external", "proxy"):
            table = standalone[name]
            assert table == complete["typemaps"][name], "Selective/full extraction differ."
            assert table["status"] == "decoded"
            assert table["mapping_count"] == sum(len(group["entries"]) for group in table["groups"])

        assert standalone["external"]["mapping_count"] == 3
        assert standalone["proxy"]["mapping_count"] == 4

        external = {group["group_type_name"]: group for group in standalone["external"]["groups"]}
        proxy = {group["group_type_name"]: group for group in standalone["proxy"]["groups"]}

        assert {entry["name"] for entry in external["Maps"]["entries"]} == {"alpha", "é😀", "conditional"}
        assert all(entry["target_type_name"] == "Target" for entry in external["Maps"]["entries"])
        assert len(proxy["Maps"]["entries"]) == 4
        assert external["Empty"]["valid"] and not external["Empty"]["entries"]
        assert proxy["Empty"]["valid"] and not proxy["Empty"]["entries"]

        for group in (external["Invalid"], external["Missing"], proxy["Missing"]):
            assert group["state"] == 0 and not group["valid"] and group["throwing_stub"]

        search = extract("search", "alpha")
        matches = [match for match in search["matches"] if match["kind"] == "external_type_mapping"]
        assert len(matches) == 1 and matches[0]["target_name"] == "Target"
        search = extract("search", "Missing")
        groups = [match for match in search["matches"] if match["kind"] in {"external_type_map", "proxy_type_map"}]
        assert len(groups) == 2 and all(group["state"] == 0 and group["throwing_stub"] for group in groups)

        corrupted = bytearray(arguments.binary.read_bytes())
        group_offset = file_offset(corrupted, standalone["external"]["address"] + external["Maps"]["vertex"])
        first = corrupted[group_offset]
        integer_size = next(size for size in range(1, 6) if not first & (1 << (size - 1)))
        corrupted[group_offset + integer_size] = 4  # NativeFormat unsigned state 2
        damaged = Path(directory) / "damaged.exe"
        damaged.write_bytes(corrupted)
        previous = b"previous complete result"
        output.write_bytes(previous)
        for operation in ("typemaps", "extract"):
            result = subprocess.run([*cli, operation, str(damaged), str(output)], capture_output=True, text=True)
            assert result.returncode != 0 and "section 340" in result.stderr and "state 2" in result.stderr
            assert output.read_bytes() == previous, "Malformed maps replaced the previous result."
            assert not list(Path(directory).glob("*.tmp")), "Failed output left temporary files."

    if arguments.runtime_probe:
        rows = set(run([str(arguments.runtime_probe.resolve())]).stdout.splitlines())
        assert rows == {
            "external|alpha|Target", "external|é😀|Target", "external|conditional|Target",
            "proxy|Source|Target", "proxy|Source[]|Target",
            "proxy|System.Collections.Generic.List`1[System.Int32]|Target",
            "proxy|System.Collections.Generic.List`1[T]|Target",
            "invalid|external|duplicate", "invalid|external|missing", "invalid|proxy|missing",
        }, "Actual NativeAOT lookups differ from the declared mapping relationships."
        print("Type maps NativeAOT runtime: retained mappings, trimming and invalid groups passed.")

    print("Type maps CLI: dedicated/full output, trimming, invalid groups, search and malformed-state publication passed.")


if __name__ == "__main__":
    main()
