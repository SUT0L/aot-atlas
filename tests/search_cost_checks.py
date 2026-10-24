"""Detect eager reference counting during a no-match search."""

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


def measure(cli, binary, query, output):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    allocations = []

    for _ in range(3):
        result = subprocess.run(prefix + ["search", str(binary), str(output), query],
                                capture_output=True, text=True)
        require(result.returncode == 0, f"Search failed: {result.stderr}")
        match = ALLOCATION.search(result.stderr)
        require(match is not None, "Search did not report operation thread allocation")
        allocations.append(int(match.group(1).replace(",", "")))

    document = json.loads(output.read_bytes())
    require(document["query"] == query, "Search published the wrong query")
    return int(statistics.median(allocations)), document["match_count"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()

    output = Path(__file__).resolve().parents[1] / "artifacts" / "verify" / "search-cost.json"
    empty_bytes, empty_hits = measure(arguments.cli, arguments.binary,
                                      "NoSuchAtlasName987654", output)
    broad_bytes, broad_hits = measure(arguments.cli, arguments.binary, "e", output)

    require(empty_hits == 0 and broad_hits > 1000,
            "The fixture no longer separates an empty query from a broad query")
    require(broad_bytes - empty_bytes >= 20_000,
            f"No-match search allocated too much relative to a broad search: "
            f"{empty_bytes} B versus {broad_bytes} B")
    print(f"No-match search allocated {empty_bytes} B; broad search allocated {broad_bytes} B.")


if __name__ == "__main__":
    main()
