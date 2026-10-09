import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def walk(value):
    if isinstance(value, dict):
        yield value

        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def check(cli, binary, directory, field_name):
    count = 0
    relation_count = 0

    for command in ("fields", "methods", "templates", "extract"):
        target = directory / (command + ".json")
        result = subprocess.run(
            ["dotnet", str(cli), command, str(binary), str(target)], capture_output=True, text=True
        )
        assert result.returncode == 0, (command, binary, result.stderr)

        output = json.loads(target.read_bytes())
        graph = output.get("signature_graph")
        contexts = [row["signature_context"] for row in walk(output) if "signature_context" in row]
        template_relations = [
            row for row in walk(output) if "signature_id" in row and "native_offset" in row
        ]

        if contexts or template_relations:
            assert graph, (binary, command, "No declared graph for signature references")
            types = {node["id"] for node in graph["types"]} | {0}
            methods = {node["id"] for node in graph["methods"]} | {0}

            for relation in template_relations:
                assert relation["signature_id"] > 0 and relation["signature_id"] in types
            relation_count += len(template_relations)

            for context in contexts:
                assert ("type_signature_id" in context) != ("method_signature_id" in context)
                key = "type_signature_id" if "type_signature_id" in context else "method_signature_id"
                assert context[key] in (types if key == "type_signature_id" else methods)

                for axis in ("type_arguments", "method_arguments"):
                    for argument in context[axis]:
                        kind = argument["kind"]

                        if kind == "TypeSignature":
                            assert argument["type_signature_id"] in types and argument["substitutions"] == "none"
                        elif kind == "RuntimeType":
                            assert argument["type_address"] > 0
                        elif kind == "ParameterName":
                            assert argument["name"]
                        else:
                            assert kind == "Unresolved"

            count += len(contexts)

        if field_name and command == "fields":
            selected = [
                row for row in output["fields"]
                if row.get("field_name") == field_name and "signature_context" in row
            ]
            assert len(selected) >= 2, "Fixture must have repeated contextual field declarations."
            roots = {row["signature_context"]["type_signature_id"] for row in selected}
            addresses = {row["signature_context"]["type_arguments"][0]["type_address"] for row in selected}
            assert len(roots) == 1 and len(addresses) >= 2, "Same declaration needs distinct actual type arguments"

    print(
        f"{binary}: {count} contextual uses retain declared graph IDs and argument categories/order; "
        f"{relation_count} template relation roots resolve in their owning graphs."
    )
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binaries", type=Path, nargs="+")
    parser.add_argument("--field", default="")
    parser.add_argument("--expected-contexts", type=int)
    arguments = parser.parse_args()
    total = 0

    with tempfile.TemporaryDirectory(prefix="atlas-context-output-checks-") as temporary:
        for index, binary in enumerate(arguments.binaries):
            directory = Path(temporary) / str(index)
            directory.mkdir()
            total += check(arguments.cli.resolve(), binary.resolve(), directory, arguments.field)

    if arguments.expected_contexts is not None:
        assert total == arguments.expected_contexts, ("Context coverage changed", total)
