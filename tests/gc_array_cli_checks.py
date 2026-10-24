import argparse
import json
import subprocess
from pathlib import Path


SHAPES = {
    "Pair": (16, [[16, 2]]),
    "Gap": (24, [[16, 1], [32, 1]]),
    "Tail": (16, [[16, 1]]),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def array_addresses(linker_map):
    names = {prefix + suffix for prefix in ("Pointer", "Constructed") for suffix in SHAPES}
    addresses = {}

    for line in linker_map.read_text(encoding="utf-8", errors="replace").splitlines():
        columns = line.split()
        if len(columns) < 3 or not columns[1].startswith("??_7__Array<"):
            continue

        for name in names:
            if columns[1].endswith(f"_{name}>@@6B@"):
                require(name not in addresses, f"Duplicate linker witness for {name}[]")
                addresses[name] = int(columns[2], 16)

    require(set(addresses) == names, f"Missing array linker witnesses: {sorted(names - addresses.keys())}")
    return addresses


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("linker_map", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()

    result = subprocess.run(
        [str(arguments.cli), "types", str(arguments.binary), str(arguments.output)],
        capture_output=True, text=True
    )
    require(result.returncode == 0, f"Published types command failed: {result.stderr}")
    report = json.loads(arguments.output.read_bytes())
    require(report["operation"] == "types", "Published command returned another product")

    for name, address in array_addresses(arguments.linker_map).items():
        suffix = name.removeprefix("Pointer").removeprefix("Constructed")
        stride, expected_runs = SHAPES[suffix]
        actual_type = report["types"].get(str(address))
        layout = report["gc_layouts"].get(str(address))
        require(actual_type is not None and layout is not None,
                f"{name}[] has no published type and GC layout at 0x{address:X}")
        require(actual_type["name"] == name + "[]", f"{name}[] has the wrong published name")
        require(layout["repeat_stride"] == stride
                and [run[:2] for run in layout["runs"]] == expected_runs,
                f"{name}[] differs from its declared reference fields")

        constructed = name.startswith("Constructed")
        require(layout["source"] == ("descriptor" if constructed else "exact_array_element_shape")
                and layout["construction_proven"] == constructed
                and (layout["series_count"] is not None) == constructed
                and all((run[2] is not None) == constructed for run in layout["runs"]),
                f"{name}[] has the wrong construction or descriptor provenance")

    print("Published types preserve six source labelled array GC layouts and construction provenance.")


if __name__ == "__main__":
    main()
