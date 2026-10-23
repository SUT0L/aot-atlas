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
        "generic_context": context["status"],
    }


def check_complete(report):
    statuses = product_statuses(report)
    require(report["analysis_status"]["status"] == "complete", f"Healthy aggregate: {statuses}")
    require(all(status == "complete" for status in statuses.values()), f"Healthy products: {statuses}")
    require(report["analysis_status"]["unavailable_outputs"] == [], "Healthy extract omitted an output")
    require(report["fat_function_pointers"]["failures"] == [], "Healthy pointers have failures")
    require(report["generic_context"]["unresolved_context_parameters"] == [], "Healthy context has unresolved parameters")
    require(report["generic_context"]["unresolved_control_flow_owners"] == [], "Healthy context has unresolved owners")
    require(report["generic_context"]["dictionary_consumer_failures"] == [], "Healthy context has consumer failures")
    require(report["generic_context"]["unresolved_dictionary_owners"] == [], "Healthy context has unresolved dictionaries")


def check_partial(report):
    pointers = report["fat_function_pointers"]
    require(any(failure["source"] == "dictionary_consumer" for failure in pointers["failures"]),
            "Partial fixture lacks dictionary consumer failures")
    require(pointers["descriptor_uses_status"] == "partial", "Descriptor uses concealed consumer failures")
    require(pointers["dictionary_consumers_status"] == "partial", "Dictionary consumers concealed failures")
    context = report["generic_context"]
    require(context["status"] == "partial", "Context concealed dictionary consumer failures")
    require(len(context["dictionary_consumer_failures"]) == 25,
            "Context failure witnesses do not match the compiled fixture")
    require(report["analysis_status"]["failures"] == [], "Partial fixture acquired an unrelated top level failure")
    require(report["analysis_status"]["unavailable_outputs"] == [], "Partial fixture lost an output")
    require(report["analysis_status"]["status"] == "partial", "Aggregate concealed pointer failures")


def check_strict(cli, complete_binary, partial_binary, output):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]

    for source, options, expected_code, expected_status in (
        (complete_binary, ["--require-complete"], 0, "complete"),
        (partial_binary, ["--require-complete"], 3, "partial"),
        (partial_binary, ["--require-complete", "--map-format", "metadata"], 3, "partial"),
        (partial_binary, ["--map-format", "metadata", "--require-complete"], 3, "partial"),
    ):
        output.write_text("prior output", encoding="utf-8")
        result = subprocess.run(prefix + ["extract", str(source), str(output), *options],
                                capture_output=True, text=True)
        require(result.returncode == expected_code,
                f"Strict extract returned {result.returncode} instead of {expected_code}: {result.stderr}")
        report = json.loads(output.read_bytes())
        require(report["analysis_status"]["status"] == expected_status,
                "Strict exit code disagrees with the published report")
        if expected_code != 0:
            require("partial report written" in result.stderr,
                    "Strict failure did not identify the inspectable partial report")
            require(report["generic_context"]["dictionary_consumer_failures"],
                    "Strict failure discarded its partial evidence")

    result = subprocess.run(prefix + ["sections", str(partial_binary), str(output),
                                      "--require-complete"], capture_output=True, text=True)
    require(result.returncode == 2, "Strict mode was accepted for a command without aggregate status")


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
        check_strict(arguments.cli.resolve(), arguments.complete_binary.resolve(),
                     arguments.partial_binary.resolve(), output)

    print("Aggregate and strict CLI status agree with complete and failed product evidence.")


if __name__ == "__main__":
    main()
