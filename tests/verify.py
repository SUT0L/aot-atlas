import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Verify Atlas outputs against compiler and runtime evidence")
    for name in ("dictionary", "property", "canonical", "metadata", "string", "string-oracle"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if (arguments.string is None) != (arguments.string_oracle is None):
        parser.error("--string and --string-oracle must be supplied together")

    root = Path(__file__).resolve().parents[1]
    command = ["dotnet", "test", str(root / "tests/Verification.proj"), "--no-restore", "-v:minimal",
               f"-p:Python={sys.executable}"]
    for name, property_name in (
        ("dictionary", "DictionaryFixture"),
        ("property", "PropertyFixture"),
        ("canonical", "CanonicalFixture"),
        ("metadata", "MetadataFixture"),
        ("string", "StringFixture"),
        ("string_oracle", "StringOracle"),
        ("output", "VerificationRoot"),
    ):
        value = getattr(arguments, name)
        if value is not None:
            command.append(f"-p:{property_name}={value.resolve()}")
    return subprocess.run(command, cwd=root).returncode


if __name__ == "__main__":
    sys.exit(main())
