import argparse
import json
import subprocess
import tempfile
from pathlib import Path


NAME = b"DictionaryFunctions"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def extract(cli, binary, output):
    command = ["dotnet", str(cli)] if cli.suffix == ".dll" else [str(cli)]
    subprocess.run([*command, "extract", str(binary), str(output)], check=True, capture_output=True, text=True)
    return json.loads(output.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()
    cli = arguments.cli.resolve()
    source = arguments.binary.resolve().read_bytes()
    require(source.count(NAME) == 1, "Fixture must contain exactly one target metadata name")
    position = source.index(NAME)

    with tempfile.TemporaryDirectory(prefix="atlas-metadata-name-") as directory:
        directory = Path(directory)
        output = directory / "extract.json"
        healthy = extract(cli, arguments.binary.resolve(), output)
        matches = [row for row in healthy["maps"]["types"] if row[-1] == NAME.decode()]
        require(len(matches) == 1, "Fixture must map one target runtime type")
        address = str(matches[0][1])
        require(healthy["types"]["types"][address]["name_complete"], "Healthy name must be complete")

        for label, replacement, expected_name in (
            ("invalid_utf8", 0xFF, ""),
            ("control_character", 0x01, "\x01ictionaryFunctions"),
        ):
            damaged = bytearray(source)
            damaged[position] = replacement
            binary = directory / f"{label}.exe"
            binary.write_bytes(damaged)
            report = extract(cli, binary, output)
            actual = report["types"]["types"][address]
            require(actual["name"] == expected_name, f"{label}: wrong damaged name {actual['name']!r}")
            require(not actual["name_complete"], f"{label}: damaged name was marked complete")
            require(report["types"]["types"][str(matches[0][1])]["source"] ==
                    healthy["types"]["types"][address]["source"],
                    f"{label}: type evidence unexpectedly changed")

    print("Damaged metadata names retain their text and incomplete provenance.")


if __name__ == "__main__":
    main()
