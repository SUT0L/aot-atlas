"""Bound published CLI work on the pinned DictionaryProbe fixture."""

import argparse
import json
import re
import statistics
import subprocess
from pathlib import Path


TOTAL_MS = re.compile(r"Total ([\d.]+) ms")
ALLOCATED = re.compile(r"operation-thread allocation ([\d,]+) B")
CASES = {
    "types": ("types",),
    "search_types": ("search", "NoSuchAtlasName987654", "--types-only"),
    "search_full": ("search", "NoSuchAtlasName987654"),
    "extract": ("extract",),
}
BYTE_LIMITS = {
    "types": 23_000_000,
    "search_types": 23_000_000,
    "search_full": 38_000_000,
    "extract": 46_000_000,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()
    cli = arguments.cli.resolve()
    binary = arguments.binary.resolve()
    require(1_000_000 <= binary.stat().st_size <= 2_000_000,
            "Speed budgets require the 1 to 2 MB DictionaryProbe fixture")

    output = Path(__file__).resolve().parents[1] / "artifacts/verify/speed-budget.json"
    samples = {name: [] for name in CASES}
    documents = {}

    for round_index in range(5):
        order = tuple(CASES) if round_index % 2 == 0 else tuple(reversed(CASES))
        for name in order:
            operation, *options = CASES[name]
            command = [str(cli), operation, str(binary), str(output), *options]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
            require(completed.returncode == 0, f"{name} failed: {completed.stderr}")

            elapsed = TOTAL_MS.search(completed.stderr)
            allocated = ALLOCATED.search(completed.stderr)
            require(elapsed is not None and allocated is not None,
                    f"{name} omitted timing or allocation measurements")
            samples[name].append((float(elapsed.group(1)), int(allocated.group(1).replace(",", ""))))
            documents[name] = json.loads(output.read_bytes())

    expected_hash = documents["extract"]["input_sha256"]
    require(all(document["input_sha256"] == expected_hash for document in documents.values()),
            "Speed cases did not analyse the same input")
    require(len(documents["types"]["types"]) == len(documents["extract"]["types"]["types"]),
            "Speed cases did not produce the same runtime type count")
    require(documents["search_types"]["match_count"] == 0
            and documents["search_full"]["match_count"] == 0,
            "The speed fixture no longer supplies a no-match search")

    medians = {}
    for name, values in samples.items():
        milliseconds = statistics.median(value[0] for value in values)
        bytes_allocated = statistics.median(value[1] for value in values)
        require(bytes_allocated <= BYTE_LIMITS[name],
                f"{name} allocated {bytes_allocated:,.0f} B, budget {BYTE_LIMITS[name]:,} B")
        require(milliseconds <= 750,
                f"{name} took {milliseconds:.1f} ms median on the small fixture")
        medians[name] = milliseconds

    require(medians["search_types"] <= 0.55 * medians["search_full"],
            f"Type-only search lost its time advantage: {medians!r}")
    require(medians["types"] <= 0.45 * medians["extract"],
            f"Types extraction approached full extraction cost: {medians!r}")
    require(medians["search_full"] <= 0.75 * medians["extract"],
            f"No-match search approached full extraction cost: {medians!r}")

    print("Native CLI median milliseconds: "
          + ", ".join(f"{name}={value:.1f}" for name, value in medians.items()))


if __name__ == "__main__":
    main()
