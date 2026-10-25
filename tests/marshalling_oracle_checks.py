import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def live_layouts(binary):
    process = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
    require(process.returncode == 0, f"Marshalling producer failed: {process.stderr}")
    layouts = {}
    invalid = None
    callback = None

    for line in process.stdout.splitlines():
        parts = line.split("|")
        if parts[0] == "S":
            address = int(parts[1], 16)
            require(address not in layouts, f"Duplicate live layout at 0x{address:X}")
            layouts[address] = {"size": int(parts[2]), "fields": []}
        elif parts[0] == "F":
            address = int(parts[1], 16)
            require(address in layouts, f"Field precedes its live layout at 0x{address:X}")
            layouts[address]["fields"].append({"name": parts[2], "offset": int(parts[3])})
        elif parts[0] == "I":
            require(invalid is None, "Producer repeated its invalid layout")
            invalid = int(parts[1], 16)
        elif parts[0] == "D":
            require(callback is None, "Producer repeated its delegate")
            callback = int(parts[1], 16)
        else:
            raise AssertionError(f"Unexpected producer output: {line}")

    require(len(layouts) == 5 and invalid is not None and callback is not None,
            "Producer omitted a native layout, invalid case or delegate")
    return layouts, invalid, callback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("golden", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()

    command = subprocess.run(
        [str(arguments.cli), "marshalling", str(arguments.binary), str(arguments.output)],
        capture_output=True, text=True
    )
    require(command.returncode == 0, f"Published marshalling command failed: {command.stderr}")
    report = json.loads(arguments.output.read_bytes())
    image = arguments.binary.read_bytes()
    nt = struct.unpack_from("<I", image, 60)[0]
    image_base = struct.unpack_from("<Q", image, nt + 48)[0]
    require(report["input_sha256"] == hashlib.sha256(image).hexdigest(),
            "Marshalling report has the wrong input identity")

    expected = {row["type_name"]: row for row in json.loads(arguments.golden.read_bytes())}
    actual = {row["type_name"]: row for row in report["structs"]}
    require(len(expected) == len(actual) == 6 and set(actual) == set(expected),
            "Published marshalling structs differ from the source fixture")

    live, invalid, callback = live_layouts(arguments.binary)
    for name, row in expected.items():
        published = actual[name]
        for key in ("invalid_layout", "size", "size_source", "fields"):
            require(published[key] == row[key], f"{name}: {key} differs from the declared layout")

        address = published["type"] - image_base
        if row["invalid_layout"]:
            require(address == invalid, "Invalid layout has the wrong live type address")
        else:
            require(address in live and live[address]["size"] == row["size"]
                    and live[address]["fields"] == row["fields"],
                    f"{name}: published fields differ from the running producer")

    require(set(live) == {row["type"] - image_base for row in actual.values()
                          if not row["invalid_layout"]},
            "Running producer and published native layouts cover different types")
    require(len(report["delegates"]) == 1
            and report["delegates"][0]["type_name"] == "MarshallingFixture.Callback"
            and report["delegates"][0]["type"] - image_base == callback,
            "Published delegate differs from the running producer")
    print("Five live native layouts, one invalid layout and one delegate match published marshalling facts.")


if __name__ == "__main__":
    main()
