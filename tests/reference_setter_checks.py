"""Keep reference setter storage conservative without a proved helper identity."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()

    if sys.platform == "win32":
        result = subprocess.run([str(arguments.binary)], capture_output=True, text=True)
        require(result.returncode == 0 and "assertions|passed" in result.stdout,
                f"Reference property fixture failed its runtime checks: {result.stderr}")

    root = Path(__file__).resolve().parents[1]
    output = root / "artifacts" / "verify" / "reference-setters.json"
    prefix = ["dotnet", str(arguments.cli)] if arguments.cli.suffix == ".dll" else [str(arguments.cli)]
    result = subprocess.run(prefix + ["properties", str(arguments.binary), str(output)],
                            capture_output=True, text=True)
    require(result.returncode == 0, f"Property extraction failed: {result.stderr}")

    report = json.loads(output.read_bytes())
    helpers = [entry for entry in report["rejection_witnesses"]
               if entry["reason"] == "ReferenceHelper"]
    direct = [entry for entry in helpers if entry.get("first_opcode") == "Lea_r64_m"]
    require(len(direct) == 1 and report["rejected"].get("ReferenceHelper") == len(helpers),
            f"The compiled reference setter lost its explicit helper rejection: {helpers}")

    witness = direct[0]
    require(witness["owner_name"].startswith("Box`1<")
            and witness["property_name"] == "Value"
            and witness["accessor_metadata"] != 0
            and witness["target"] != 0
            and witness["helper"] != 0
            and witness["helper"] != witness["target"]
            and witness["code_status"] == "HelperRequired"
            and witness["first_opcode"] == "Lea_r64_m",
            f"The reference setter has no inspectable helper call: {witness}")
    require(not any(projection["owner"] == witness["owner"]
                    and projection["property"] == witness["property"]
                    and projection["setter"] != 0
                    for projection in report["projections"]),
            "An unproved reference setter became a storage projection")
    require(all(entry.get("helper") and entry.get("target")
                and not any(projection["getter"] == entry["target"]
                            or projection["setter"] == entry["target"]
                            for projection in report["projections"])
                for entry in helpers),
            "A helper mediated accessor was accepted without independent proof")

    print("Reference setter remains rejected with an exact helper call witness.")


if __name__ == "__main__":
    main()
