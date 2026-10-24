import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def run(*command, root):
    result = subprocess.run([str(part) for part in command], cwd=root,
                            capture_output=True, text=True, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"{command}: {result.stdout}\n{result.stderr}")
    return result.stdout


def shape(report):
    return (
        tuple(sorted((re.sub(r"mt_ref_[0-9A-Fa-f]+", "mt_ref", row["owner_name"]),
                      row["property_name"], row["offset"], row["size"])
                     for row in report["projections"])),
        tuple(sorted(report["rejected"].items())),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("harness", type=Path)
    arguments = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Compiled property runtime observations require Windows")

    root = Path(__file__).resolve().parents[1]
    cli = arguments.cli.resolve()
    harness = arguments.harness.resolve()
    output = root / "artifacts" / "property-shapes"
    baseline = {}

    for framework in ("net8.0", "net9.0", "net10.0"):
        for preference in ("Default", "Size", "Speed"):
            label = f"{framework}-{preference.lower()}"
            cases = {}

            for kind, project in (("dispatch", "PropertyDispatchProbe"),
                                  ("canonical", "PropertyCanonicalProbe")):
                directory = output / label / kind
                command = ["dotnet", "publish", f"tests/{project}/{project}.csproj",
                           "-c", "Release", "-r", "win-x64", "--self-contained",
                           f"-p:ProbeFramework={framework}", "--output", directory]
                if preference != "Default":
                    command.insert(-2, f"-p:OptimizationPreference={preference}")
                run(*command, root=root)
                binary = directory / f"{project}.exe"
                run("dotnet", harness, "--properties", binary, root=root)

                report_path = output / f"{label}-{kind}.json"
                run(cli, "properties", binary, report_path, root=root)
                report = json.loads(report_path.read_bytes())
                if kind == "canonical" and framework in ("net8.0", "net9.0"):
                    nested = [row for row in report["rejection_witnesses"]
                              if row["reason"] == "ReferenceHelper"
                              and "Nested`1" in row["owner_name"]
                              and row["property_name"] == "Value"]
                    if len(nested) != 2 or any(not row.get("helper") for row in nested):
                        raise AssertionError(f"{label}: guarded nested copies lost their call witnesses")
                cases[kind] = shape(report)

            if preference == "Default":
                baseline[framework] = cases
            elif cases != baseline[framework]:
                raise AssertionError(f"{label}: optimisation changed proved property storage or rejection reasons")

            print(f"{label}: {len(cases['dispatch'][0])} dispatch and "
                  f"{len(cases['canonical'][0])} canonical projections, live owners checked")


if __name__ == "__main__":
    main()
