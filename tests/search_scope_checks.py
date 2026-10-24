"""Check that type-only search has the same type facts with less preparation."""

import argparse
import json
import re
import statistics
import subprocess
from pathlib import Path


ALLOCATION = re.compile(r"operation-thread allocation ([\d,]+) B")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def search(cli, binary, query, output, types_only, repetitions=1):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    allocations = []

    for _ in range(repetitions):
        command = prefix + ["search", str(binary), str(output), query]
        if types_only:
            command.append("--types-only")
        result = subprocess.run(command, capture_output=True, text=True)
        require(result.returncode == 0, f"Search failed: {result.stderr}")
        match = ALLOCATION.search(result.stderr)
        require(match is not None, "Search did not report operation thread allocation")
        allocations.append(int(match.group(1).replace(",", "")))

    return json.loads(output.read_bytes()), int(statistics.median(allocations))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()

    output = Path(__file__).resolve().parents[1] / "artifacts" / "verify"
    for query in ("Dictionary", "NoSuchAtlasName987654"):
        full, full_bytes = search(arguments.cli, arguments.binary, query,
                                  output / "search-full.json", False, 3)
        types, type_bytes = search(arguments.cli, arguments.binary, query,
                                   output / "search-types.json", True, 3)

        expected = [match for match in full["matches"] if match["kind"] == "type"]
        require(types["operation"] == "search" and types["scope"] == "types",
                "The narrow search did not declare its scope")
        require(types["input_sha256"] == full["input_sha256"]
                and types["query"] == full["query"],
                "The two searches used different inputs or queries")
        require(types["matches"] == expected and types["match_count"] == len(expected),
                "Type-only search changed a type name, address, completeness, or order")
        require(types["extraction_stages"]["runtime_types"] == "available"
                and types["extraction_stages"]["member_layouts"] == "not_requested"
                and types["extraction_stages"]["method_tracing"] == "not_requested"
                and types["extraction_stages"]["dispatch"] == "not_requested",
                "Type-only search prepared unrelated code stages")
        require(full_bytes - type_bytes >= 5_000_000,
                f"Type-only search did not avoid the full pipeline: "
                f"{full_bytes} B versus {type_bytes} B")

        if query == "NoSuchAtlasName987654":
            require(full["match_count"] == 0 and types["match_count"] == 0,
                    "The no-match control unexpectedly found a name")

        print(f"{query}: {len(expected)} type matches, "
              f"{full_bytes - type_bytes} B less than full search.")


if __name__ == "__main__":
    main()
