import argparse
import json
import subprocess
import tempfile
from pathlib import Path


COMMANDS = (
    "types", "fields", "methods", "dispatch", "gvm", "templates", "dictionaries", "frozen",
    "statics", "marshalling", "pinvoke", "enums", "properties", "maps", "metadata", "extract"
)


def facts(value):
    if isinstance(value, dict):
        return {
            key: facts(item) for key, item in value.items()
            if key not in {"allocated_bytes", "extraction_stages", "signature_context"}
            and "seconds" not in key
        }

    if isinstance(value, list):
        return [facts(item) for item in value]

    return value


def preserve(expected, actual, location, corrected_metadata_paths):
    if isinstance(expected, dict):
        assert isinstance(actual, dict), (location, "Object became another kind")

        for key, value in expected.items():
            assert key in actual, (location, "Prior field disappeared", key)

            if location in corrected_metadata_paths and key in {"signature_nodes", "signature_edges"}:
                continue

            preserve(value, actual[key], location + "." + key, corrected_metadata_paths)
    elif isinstance(expected, list):
        assert isinstance(actual, list) and len(expected) == len(actual), (location, "Prior row count changed")

        for index, (before, after) in enumerate(zip(expected, actual, strict=True)):
            preserve(before, after, f"{location}[{index}]", corrected_metadata_paths)
    else:
        assert expected == actual, (location, "Prior fact or ID changed", expected, actual)


def metadata_counts(metadata):
    graph = metadata["signature_graph"]
    nodes = graph["types"]
    methods = graph["methods"]
    edges = sum(
        len(node[key]) for node in nodes for key in ("arguments", "varargs", "sizes", "lower_bounds")
    ) + sum(len(method[key]) for method in methods for key in ("parameters", "varargs"))

    assert {node["id"] for node in nodes} == set(range(1, len(nodes) + 1)), "Metadata graph IDs are not contiguous."
    assert metadata["signature_nodes"] == len(nodes), "Metadata node summary differs from its emitted graph."
    assert metadata["signature_edges"] == edges, "Metadata edge summary differs from its emitted graph."

    return metadata["signature_nodes"], metadata["signature_edges"]


def run(cli, command, binary, output):
    prefix = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    result = subprocess.run(
        prefix + [command, str(binary), str(output)], capture_output=True, text=True
    )
    assert result.returncode == 0, (command, binary, result.stderr)
    assert not list(output.parent.glob("*.tmp")), "Unpublished temporary output remains."

    return json.loads(output.read_bytes())


def named_fixture(value):
    name, separator, path = value.partition("=")

    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("Fixture must be NAME=PATH.")

    return name, Path(path).resolve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("fixtures", type=named_fixture, nargs="+")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--golden", type=Path)
    source.add_argument("--baseline-cli", type=Path)
    parser.add_argument("--producer-golden", type=Path)
    parser.add_argument("--expected-pointers", type=int, nargs="+")
    arguments = parser.parse_args()

    if arguments.expected_pointers is not None:
        assert len(arguments.expected_pointers) == len(arguments.fixtures), "One pointer count is required per fixture."

    checked = 0

    with tempfile.TemporaryDirectory(prefix="atlas-compatibility-checks-") as temporary:
        for index, (name, binary) in enumerate(arguments.fixtures):
            directory = Path(temporary) / str(index)
            directory.mkdir()
            standalone_counts = None
            corrected_metadata_paths = {name + ".metadata", name + ".extract.metadata"}

            for command in COMMANDS:
                actual = run(arguments.cli.resolve(), command, binary, directory / "actual.json")

                if command == "metadata":
                    standalone_counts = metadata_counts(actual)
                elif command == "extract":
                    metadata = actual["metadata"]
                    assert (metadata["signature_nodes"] >= standalone_counts[0]
                            and metadata["signature_edges"] >= standalone_counts[1]), (
                        name, "Integrated publication lost standalone metadata graph entries"
                    )

                if arguments.golden is not None:
                    expected = json.loads((arguments.golden / name / (command + ".json")).read_bytes())
                else:
                    expected = run(
                        arguments.baseline_cli.resolve(), command, binary, directory / "expected.json"
                    )

                preserve(facts(expected), facts(actual), name + "." + command, corrected_metadata_paths)

                if "extraction_stages" in actual:
                    stages = actual["extraction_stages"]
                    assert stages["dictionary_signatures"] == "complete", (name, command, stages)
                    assert stages["dictionary_bindings"] == (
                        "available" if command in ("dictionaries", "extract") else "not_requested"
                    ), (name, command, stages)

                checked += 1

            pointers = run(arguments.cli.resolve(), "fat-function-pointers", binary, directory / "pointers.json")

            if arguments.producer_golden is not None:
                expected = json.loads((arguments.producer_golden / (name + ".json")).read_bytes())
                assert pointers == expected, (name, "Producer contexts, provenance or availability changed")

            if arguments.expected_pointers is not None:
                assert len(pointers["pointers"]) == arguments.expected_pointers[index], (
                    name, "Anchored producer coverage changed", len(pointers["pointers"])
                )

            print(f"{name}: prior facts and IDs retained; {len(pointers['pointers'])} producer descriptors observed.", flush=True)

    if checked == 0:
        raise RuntimeError("No prior-output comparisons ran.")

    print(f"{checked} prior-output comparisons passed; additive facts remain available.")
