"""Exercise every registered CLI command against a published executable."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SHAPES = {
    "code": ("instruction_count", int),
    "dictionaries": ("recipes", list),
    "dispatch": ("virtual_methods", list),
    "dispatch-cells": ("cells", list),
    "enums": ("definitions", list),
    "exceptions": ("frames", list),
    "extract": ("analysis_status", dict),
    "fat-function-pointers": ("pointers", list),
    "fields": ("layouts", list),
    "frozen": ("objects", list),
    "gcinfo": ("methods", list),
    "generic-context": ("status", str),
    "gvm": ("class_rules", list),
    "header": (None, None),
    "inspect": ("rtr", dict),
    "linkage": ("import_modules", list),
    "maps": ("types", list),
    "marshalling": ("structs", list),
    "metadata": ("scopes", list),
    "methods": ("methods", list),
    "pinvoke": ("methods", list),
    "properties": ("projections", list),
    "resolve-dispatch": ("status", str),
    "resources": ("resources", list),
    "runtime-helpers": ("evidence", str),
    "search": ("matches", list),
    "sections": ("sections", list),
    "statics": ("allocations", list),
    "strings": ("strings", list),
    "templates": ("type_templates", list),
    "typemaps": ("schema_version", int),
    "types": ("types", dict),
    "unwind": ("entries", list),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("test_host", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    output = root / "artifacts" / "verify" / "command-contracts"
    output.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["dotnet", str(arguments.test_host), "--registered-cli-commands"],
        capture_output=True, text=True, check=True,
    )
    commands = result.stdout.splitlines()
    require(len(commands) == len(set(commands)), "The CLI registry contains duplicate command names")
    require(set(commands) == set(SHAPES),
            f"Registered commands and output contracts differ: {set(commands) ^ set(SHAPES)}")

    digest = hashlib.sha256(arguments.binary.read_bytes()).hexdigest()
    prefix = ["dotnet", str(arguments.cli)] if arguments.cli.suffix == ".dll" else [str(arguments.cli)]
    documents = {}

    for command in commands:
        path = output / f"{command}.{'h' if command == 'header' else 'json'}"
        path.unlink(missing_ok=True)
        invocation = prefix + [command, str(arguments.binary), str(path)]
        if command == "search":
            invocation.append("Dictionary")
        elif command == "resolve-dispatch":
            invocation.extend(("0x140000000", "0x140000000", "0"))

        result = subprocess.run(invocation, capture_output=True, text=True)
        require(result.returncode == 0,
                f"{command} failed with exit {result.returncode}: {result.stderr}")
        require(path.is_file() and path.stat().st_size > 0,
                f"{command} reported success without publishing its output")

        if command == "header":
            contents = path.read_text(encoding="utf-8")
            require(digest.upper() in contents and "#define" in contents and "#endif" in contents,
                    "Header command did not publish a layout with input provenance")
            continue

        document = json.loads(path.read_bytes())
        documents[command] = document
        field, kind = SHAPES[command]
        require(isinstance(document, dict) and len(document) > 1,
                f"{command} published an empty or invalid document")
        require(document.get("input_sha256") == digest,
                f"{command} published output for the wrong input")
        require(document.get("operation") == command and document.get("schema_version") == 1,
                f"{command} published the wrong operation or schema version")
        require(field in document and isinstance(document[field], kind),
                f"{command} omitted its declared {field} output")

    embedded = documents["extract"]
    for command, document in documents.items():
        key = command.replace("-", "_")
        if key in embedded:
            require(embedded[key].get("operation") == command
                    and embedded[key].get("schema_version") == document["schema_version"],
                    f"extract changed the {command} product envelope")

    for command in ("strings", "search"):
        document = documents[command]
        require(document.get("candidate_section") == ".rdata"
                and document.get("scanned_sections", 0) > 0
                and document.get("minimum_ascii_bytes") == 4
                and document.get("minimum_utf16le_bytes") == 8,
                f"{command} omitted its candidate coverage")

    require(not list(output.glob("*.tmp")), "Unpublished CLI temporary output remains")
    print(f"Checked all {len(commands)} registered CLI command contracts.")


if __name__ == "__main__":
    main()
