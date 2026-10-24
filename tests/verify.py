import argparse
import platform
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Run parser and published CLI checks")
    parser.add_argument("--dictionary", type=Path)
    parser.add_argument("--property", type=Path)
    parser.add_argument("--canonical", type=Path)
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
    run("dotnet", root / "tests" / "Atlas.Tests" / "bin" / "Release" / "net10.0" / "Atlas.Tests.dll",
        "--timed-cancellation")
    run(sys.executable, "tests/compatibility_filter_checks.py")
    run(sys.executable, "tests/optimised_assertion_checks.py")

    dictionary = arguments.dictionary.resolve() if arguments.dictionary is not None else None
    property_probe = arguments.property.resolve() if arguments.property is not None else None
    canonical_probe = arguments.canonical.resolve() if arguments.canonical is not None else None

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
        if canonical_probe is None:
            run("dotnet", "publish", "tests/PropertyCanonicalProbe/PropertyCanonicalProbe.csproj",
                "-c", "Release", "-r", rid, "--self-contained",
                "--output", output / "canonical")
            canonical_probe = output / "canonical" / "PropertyCanonicalProbe.exe"
        run("dotnet", "publish", "tests/PropertySharedProbe/PropertySharedProbe.csproj",
            "-c", "Release", "-r", rid, "--self-contained",
            "--output", output / "property-shared")
        run("dotnet", "publish", "tests/PropertyGcProbe/PropertyGcProbe.csproj",
            "-c", "Release", "-r", rid, "--self-contained",
            "--output", output / "property-gc")
    else:
        dictionary = dictionary or root / "artifacts" / "DictionaryProbe.exe"
        property_probe = property_probe or root / "artifacts" / "PropertyDispatchProbe.exe"
        canonical_probe = canonical_probe or root / "artifacts" / "PropertyCanonicalProbe.exe"

    for label, binary in (("dictionary", dictionary), ("property", property_probe),
                          ("canonical", canonical_probe)):
        if not binary.is_file():
            parser.error(f"{label} PE fixture is missing: {binary}")

    run("dotnet", root / "tests" / "Atlas.Tests" / "bin" / "Release" / "net10.0" / "Atlas.Tests.dll",
        "--extraction-availability", dictionary, property_probe)
    run("dotnet", root / "tests" / "Atlas.Tests" / "bin" / "Release" / "net10.0" / "Atlas.Tests.dll",
        "--analysis-products", dictionary, property_probe)
    if windows:
        run("dotnet", root / "tests" / "Atlas.Tests" / "bin" / "Release" / "net10.0" / "Atlas.Tests.dll",
            "--properties", output / "property-shared" / "PropertySharedProbe.exe",
            output / "property-gc" / "PropertyGcProbe.exe")

    run("dotnet", "publish", "src/Atlas.Cli/Atlas.Cli.csproj",
        "-c", "Release", "-r", rid, "--self-contained", "--output", output / "cli")

    run(sys.executable, "tests/command_contract_checks.py", cli,
        root / "tests" / "Atlas.Tests" / "bin" / "Release" / "net10.0" / "Atlas.Tests.dll",
        dictionary)
    run(sys.executable, "tests/search_cost_checks.py", cli, dictionary)
    run(sys.executable, "tests/search_scope_checks.py", cli, dictionary)
    run(sys.executable, "tests/analysis_status_checks.py", cli, property_probe, dictionary)
    run(sys.executable, "tests/function_pointer_checks.py", cli, dictionary)
    run(sys.executable, "tests/property_rejection_checks.py", cli, property_probe)
    run(sys.executable, "tests/reference_setter_checks.py", cli, canonical_probe)
    run(sys.executable, "tests/metadata_name_checks.py", cli, dictionary)
    if windows:
        run(sys.executable, "tests/cli_checks.py", "publication", cli, dictionary,
            "--query", "Dictionary")
    else:
        run(sys.executable, "tests/output_failure_checks.py", cli, dictionary)

    runtime_source = root / "artifacts" / "runtime-checks" / "repository"
    native_reader = (runtime_source / "src" / "coreclr" / "tools" / "Common" / "Internal"
                     / "Metadata" / "NativeFormat" / "NativeMetadataReader.cs")
    if not native_reader.is_file():
        if not runtime_source.exists():
            runtime_source.parent.mkdir(parents=True, exist_ok=True)
            run("git", "clone", "--filter=blob:none", "--single-branch", "--depth=1",
                "--branch", "v10.0.0", "--no-checkout",
                "https://github.com/dotnet/runtime.git", runtime_source)
        elif not (runtime_source / ".git").exists():
            parser.error(f"Microsoft runtime source is not a Git checkout: {runtime_source}")
        run("git", "-C", runtime_source, "sparse-checkout", "set",
            "src/coreclr/tools/Common/Internal/NativeFormat",
            "src/coreclr/tools/Common/Internal/Metadata/NativeFormat")
        run("git", "-C", runtime_source, "checkout", "--force", "v10.0.0")

    revision = subprocess.check_output(
        ["git", "-C", str(runtime_source), "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if revision != "60629d14374c56f1cb51819049ad1fa529307f8d":
        parser.error(f"Microsoft runtime source must be v10.0.0, found {revision}")

    runtime_project = "tests/RuntimeChecks/RuntimeChecks.csproj"
    if windows:
        run("dotnet", "build", runtime_project, "-c", "Release", "-t:RuntimeChecks",
            f"-p:RuntimeSourceRoot={runtime_source}")
        runtime_reader = (root / "artifacts" / "runtime-checks" / "reader-net10.0" / "bin"
                          / "RuntimeChecks" / "release" / "RuntimeChecks.dll")
    else:
        runtime_output = output / "runtime-reader"
        run("dotnet", "build", runtime_project, "-c", "Release",
            f"-p:RuntimeSourceRoot={runtime_source}", "-p:ReaderSchema=Current",
            f"-p:ArtifactsPath={runtime_output}")
        runtime_reader = runtime_output / "bin" / "RuntimeChecks" / "release" / "RuntimeChecks.dll"

    run("dotnet", runtime_reader, dictionary, property_probe, canonical_probe)


if __name__ == "__main__":
    main()
