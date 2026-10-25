import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def identities(rows):
    result = {}
    for row in rows:
        key = (row["assembly"], row["name"])
        require(key not in result, f"Duplicate resource {key!r}")
        result[key] = row
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("golden", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()

    executable = arguments.binary.resolve()
    live_process = subprocess.run([str(executable)], capture_output=True)
    require(live_process.returncode == 0,
            f"Resource producer failed: {live_process.stderr.decode(errors='replace')}")
    live = json.loads(live_process.stdout)

    command = subprocess.run(
        [str(arguments.cli), "resources", str(executable), str(arguments.output)],
        capture_output=True, text=True
    )
    require(command.returncode == 0, f"Published resources command failed: {command.stderr}")
    atlas = json.loads(arguments.output.read_bytes())
    golden = identities(json.loads(arguments.golden.read_bytes()))
    live_rows = identities(live["resources"])
    atlas_rows = identities(atlas["resources"])
    require(set(live_rows) == set(golden) == set(atlas_rows),
            "Compiled, running, and extracted resource identities differ")

    image = executable.read_bytes()
    nt = struct.unpack_from("<I", image, 60)[0]
    image_base = struct.unpack_from("<Q", image, nt + 48)[0]
    digest = hashlib.sha256(image).hexdigest()
    require(live["input_sha256"] == atlas["input_sha256"] == digest,
            "Resource observations refer to different PE bytes")

    for key in golden:
        expected = golden[key]
        actual_live = live_rows[key]
        actual_atlas = atlas_rows[key]
        for field in ("assembly", "name", "length", "data"):
            require(actual_live[field] == actual_atlas[field] == expected[field],
                    f"{key!r}: {field} differs from the source resource")
        require(actual_atlas["address"] == image_base + actual_live["rva"],
                f"{key!r}: extracted data address differs from the running producer")
        require(actual_atlas["address"] == atlas["data_start"] + actual_atlas["offset"]
                and actual_atlas["offset"] + actual_atlas["length"] <= atlas["data_length"],
                f"{key!r}: extracted data extent is outside its resource region")
        require(atlas["index_start"] <= actual_atlas["index_address"]
                < atlas["index_start"] + atlas["index_length"],
                f"{key!r}: index record is outside its resource region")

    print(f"{len(golden)} source labelled resources match live bytes, addresses and published extents.")


if __name__ == "__main__":
    main()
