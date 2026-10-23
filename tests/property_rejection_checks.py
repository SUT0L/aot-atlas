"""Check rejection instances against the compiled property fixture."""

import argparse
from collections import Counter
import json
import subprocess
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check(report):
    counts = Counter(report["rejected"])
    witnesses = report["rejection_witnesses"]
    observed = Counter(entry["reason"] for entry in witnesses)

    require(report["property_definitions"] == 6,
            "The compiled fixture no longer has its six intended property declarations")
    require(report["rejection_witnesses_omitted"] == 0,
            "The small fixture exceeded the rejection witness bound")
    require(observed == counts,
            f"Property rejection counts have no corresponding instances: {counts - observed}")
    require(counts == Counter({"UnsupportedAbi": 8, "UnsupportedCode": 2}),
            f"The fixture's accessor outcomes changed: {counts}")

    names = {"Count", "Label", "Raw", "Next", "Item", "Amount"}
    for witness in witnesses:
        require(witness["owner"] != 0 and witness["contract"] != 0,
                f"Rejected accessor has no runtime owner: {witness}")
        require(witness["property_name"] in names and witness["property"] != 0,
                f"Rejected accessor has no fixture property identity: {witness}")
        require(witness["accessor_metadata"] != 0,
                f"Rejected accessor has no metadata identity: {witness}")

    unsupported_code = [entry for entry in witnesses if entry["reason"] == "UnsupportedCode"]
    require({(entry["owner_name"], entry["property_name"]) for entry in unsupported_code}
            == {("IDefault", "Next"), ("UsesDefault", "Next")},
            "The default interface accessor's two rejected uses lost their identities")
    require(len({entry["target"] for entry in unsupported_code}) == 1,
            "Direct and interface rejections disagree about the accessor target")
    for witness in unsupported_code:
        require(witness["target"] != 0
                and witness["body"] != 0
                and witness["first_instruction"] != 0
                and witness["first_opcode"] == "Sub_rm64_imm8",
                f"Unsupported code has no inspectable machine-code witness: {witness}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    output = root / "artifacts" / "verify" / "property-rejections.json"
    prefix = ["dotnet", str(arguments.cli)] if arguments.cli.suffix == ".dll" else [str(arguments.cli)]
    result = subprocess.run(prefix + ["properties", str(arguments.binary), str(output)],
                            capture_output=True, text=True)
    require(result.returncode == 0, f"Property extraction failed: {result.stderr}")
    report = json.loads(output.read_bytes())
    check(report)

    shortened = dict(report)
    shortened["rejection_witnesses"] = report["rejection_witnesses"][:-1]
    try:
        check(shortened)
    except AssertionError:
        pass
    else:
        raise AssertionError("The rejection check accepted a missing witness")

    print("All ten property rejection instances have inspectable identities and code evidence.")


if __name__ == "__main__":
    main()
