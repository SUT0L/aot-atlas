import argparse
import platform
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Run parser and published CLI checks")
    parser.add_argument("--dictionary", type=Path)
    parser.add_argument("--property", type=Path)
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if platform.machine().lower() not in ("amd64", "x86_64"):
        parser.error("AOT Atlas verification requires an x64 host")
    if sys.platform not in ("win32", "linux"):
        parser.error("Native CLI verification requires Windows or Linux")

    windows = sys.platform == "win32"
    rid = "win-x64" if windows else "linux-x64"
    output = root / "artifacts" / "verify"
    cli = output / "cli" / ("aot-atlas.exe" if windows else "aot-atlas")

    def run(*command):
        print("+", *map(str, command), flush=True)
        subprocess.run([str(part) for part in command], cwd=root, check=True)

    run("dotnet", "test", "tests/Atlas.Tests/Atlas.Tests.csproj", "-c", "Release")

    dictionary = arguments.dictionary.resolve() if arguments.dictionary is not None else None
    property_probe = arguments.property.resolve() if arguments.property is not None else None

    if windows:
        if dictionary is None:
            run("dotnet", "publish", "tests/DictionaryProbe/DictionaryProbe.csproj",
                "-c", "Release", "-r", rid, "--self-contained",
                "--output", output / "dictionary")
            dictionary = output / "dictionary" / "DictionaryProbe.exe"
        if property_probe is None:
            run("dotnet", "publish", "tests/PropertyDispatchProbe/PropertyDispatchProbe.csproj",
                "-c", "Release", "-r", rid, "--self-contained",
                "--output", output / "property")
            property_probe = output / "property" / "PropertyDispatchProbe.exe"
    else:
        dictionary = dictionary or root / "artifacts" / "DictionaryProbe.exe"
        property_probe = property_probe or root / "artifacts" / "PropertyDispatchProbe.exe"

    for label, binary in (("dictionary", dictionary), ("property", property_probe)):
        if not binary.is_file():
            parser.error(f"{label} PE fixture is missing: {binary}")

    run("dotnet", "publish", "src/Atlas.Cli/Atlas.Cli.csproj",
        "-c", "Release", "-r", rid, "--self-contained", "--output", output / "cli")

    run(sys.executable, "tests/analysis_status_checks.py", cli, property_probe, dictionary)
    run(sys.executable, "tests/metadata_name_checks.py", cli, dictionary)
    if windows:
        run(sys.executable, "tests/cli_checks.py", "publication", cli, dictionary,
            "--query", "Dictionary")
    else:
        run(sys.executable, "tests/output_failure_checks.py", cli, dictionary)


if __name__ == "__main__":
    main()
