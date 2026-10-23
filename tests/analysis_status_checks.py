import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def extract(cli, binary, output):
    command = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    command.extend(("extract", str(binary), str(output)))
    subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(output.read_bytes())


def product_statuses(report):
    pointers = report["fat_function_pointers"]
    context = report["generic_context"]
    return {
        "metadata": report["analysis_status"]["metadata"],
        "gcinfo": report["gcinfo"]["status"],
        "runtime_helpers": report["runtime_helpers"]["status"].lower(),
        "pointer_descriptors": pointers["descriptor_uses_status"],
        "pointer_gc_headers": pointers["gc_headers_status"],
        "pointer_delegates": pointers["delegate_consumers_status"],
        "dictionary_consumers": pointers["dictionary_consumers_status"],
        "context_gc_headers": context["gc_headers_status"],
        "context_delegates": context["delegate_consumers_status"],
    }


def check_complete(report):
    statuses = product_statuses(report)
    require(report["analysis_status"]["status"] == "complete", f"Healthy aggregate: {statuses}")
    require(all(status == "complete" for status in statuses.values()), f"Healthy products: {statuses}")
    require(report["analysis_status"]["unavailable_outputs"] == [], "Healthy extract omitted an output")
    require(report["fat_function_pointers"]["failures"] == [], "Healthy pointers have failures")
    require(report["generic_context"]["unresolved_context_parameters"] == [], "Healthy context has unresolved parameters")
    require(report["generic_context"]["unresolved_control_flow_owners"] == [], "Healthy context has unresolved owners")


def check_partial(report):
    pointers = report["fat_function_pointers"]
    require(any(failure["source"] == "dictionary_consumer" for failure in pointers["failures"]),
            "Partial fixture lacks dictionary consumer failures")
    require(pointers["descriptor_uses_status"] == "partial", "Descriptor uses concealed consumer failures")
    require(pointers["dictionary_consumers_status"] == "partial", "Dictionary consumers concealed failures")
    require(report["analysis_status"]["failures"] == [], "Partial fixture acquired an unrelated top level failure")
    require(report["analysis_status"]["unavailable_outputs"] == [], "Partial fixture lost an output")
    require(report["analysis_status"]["status"] == "partial", "Aggregate concealed pointer failures")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("complete_binary", type=Path)
    parser.add_argument("partial_binary", type=Path)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="atlas-analysis-status-") as directory:
        output = Path(directory) / "extract.json"
        check_complete(extract(arguments.cli.resolve(), arguments.complete_binary.resolve(), output))
        check_partial(extract(arguments.cli.resolve(), arguments.partial_binary.resolve(), output))

    print("Aggregate analysis status agrees with complete and failed product evidence.")


if __name__ == "__main__":
    main()
