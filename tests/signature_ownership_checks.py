#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile


def facts(value):
    if isinstance(value, dict):
        return {
            key: facts(item) for key, item in value.items()
            if key not in {"extraction_stages", "allocated_bytes"}
            and not key.endswith("_seconds")
        }

    if isinstance(value, list):
        return [facts(item) for item in value]

    return value


def compare(baseline, candidate, fixtures):
    commands = (
        "metadata", "maps", "types", "fields", "dictionaries",
        "templates", "methods", "properties", "extract"
    )

    with tempfile.TemporaryDirectory(prefix="atlas-signature-publication-") as directory:
        destination = pathlib.Path(directory)
        checked = 0

        for fixture in fixtures:
            for command in commands:
                values = []

                for label, binary in (("baseline", baseline), ("candidate", candidate)):
                    path = destination / (label + ".json")
                    result = subprocess.run(
                        ["dotnet", binary, command, fixture, str(path)], capture_output=True, text=True
                    )

                    if result.returncode:
                        raise AssertionError(f"{label} {command} {fixture}: {result.stdout}{result.stderr}")

                    values.append(facts(json.loads(path.read_text())))

                if values[0] != values[1]:
                    raise AssertionError(f"Published graph facts or IDs changed: {command} {fixture}")

                checked += 1

            print(f"{checked} exact output comparisons passed through {fixture}", flush=True)

    return checked


if __name__ == "__main__":
    print(f"{compare(sys.argv[1], sys.argv[2], sys.argv[3:])} outputs preserve all prior facts and graph IDs.")
