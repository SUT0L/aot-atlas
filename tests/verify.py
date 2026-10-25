import argparse
import platform
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Run parser and published CLI checks")
    parser.add_argument("--dictionary", type=Path)
    parser.add_argument("--dictionary-map", type=Path)
    parser.add_argument("--property", type=Path)
    parser.add_argument("--canonical", type=Path)
    parser.add_argument("--string", type=Path)
    parser.add_argument("--string-oracle", type=Path)
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
    dictionary_map = arguments.dictionary_map.resolve() if arguments.dictionary_map is not None else None
    property_probe = arguments.property.resolve() if arguments.property is not None else None
    canonical_probe = arguments.canonical.resolve() if arguments.canonical is not None else None
    string_probe = arguments.string.resolve() if arguments.string is not None else None
    string_oracle = arguments.string_oracle.resolve() if arguments.string_oracle is not None else None
    if windows and dictionary is not None and dictionary_map is None:
        parser.error("--dictionary-map is required with --dictionary on Windows")
    if (string_probe is None) != (string_oracle is None):
        parser.error("--string and --string-oracle must be supplied together")

    if windows:
        if dictionary is None:
            run("dotnet", "publish", "tests/DictionaryProbe/DictionaryProbe.csproj",
                "-c", "Release", "-r", rid, "--self-contained",
                "--output", output / "dictionary")
            dictionary = output / "dictionary" / "DictionaryProbe.exe"
            dictionary_map = output / "dictionary" / "DictionaryProbe.map"
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
        run("dotnet", "publish", "tests/GcArrayShapeProbe/GcArrayShapeProbe.csproj",
            "-c", "Release", "-r", rid, "--self-contained",
            "--output", output / "gc-array")
        run("dotnet", "publish", "tests/ResourceProbe/ResourceProbe.csproj",
            "-c", "Release", "-r", rid, "--self-contained",
            "--output", output / "resource")
        run("dotnet", "publish", "tests/MarshallingProbe/MarshallingProbe.csproj",
            "-c", "Release", "-r", rid, "--self-contained",
            "--output", output / "marshalling")
        if string_probe is None:
            run("dotnet", "publish", "tests/StringProbe/StringProbe.csproj",
                "-c", "Release", "-r", rid, "--self-contained",
                "--output", output / "string")
            string_probe = output / "string" / "StringProbe.exe"
            string_oracle = output / "string" / "StringProbe.oracle"
            probe = subprocess.run([str(string_probe)], cwd=root, check=True,
                                   capture_output=True, text=True)
            string_oracle.write_text(probe.stdout, encoding="utf-8")
    else:
        dictionary = dictionary or root / "artifacts" / "DictionaryProbe.exe"
        property_probe = property_probe or root / "artifacts" / "PropertyDispatchProbe.exe"
        canonical_probe = canonical_probe or root / "artifacts" / "PropertyCanonicalProbe.exe"

    for label, binary in (("dictionary", dictionary), ("property", property_probe),
                          ("canonical", canonical_probe)):
        if not binary.is_file():
            parser.error(f"{label} PE fixture is missing: {binary}")
    if dictionary_map is not None and not dictionary_map.is_file():
        parser.error(f"dictionary linker map is missing: {dictionary_map}")
    if string_probe is not None and (not string_probe.is_file() or not string_oracle.is_file()):
        parser.error("string probe or its source oracle is missing")

    test_assembly = root / "tests" / "Atlas.Tests" / "bin" / "Release" / "net10.0" / "Atlas.Tests.dll"
    required_fixture_modes = [
        ("--extraction-availability", (dictionary, property_probe)),
        ("--analysis-products", (dictionary, property_probe)),
        ("--gc-transition-oracle", (dictionary,)),
        ("--gc-transition-oracle", (property_probe,)),
        ("--gc-transition-oracle", (canonical_probe,)),
        ("--type-graphs", (dictionary,)),
        ("--extraction-phases", (dictionary, property_probe)),
        ("--trace-stages", (dictionary, property_probe)),
        ("--signature-ownership", (dictionary, property_probe)),
        ("--prepared-analysis", (dictionary,)),
    ]
    if windows:
        required_fixture_modes.append((
            "--properties", (output / "property-shared" / "PropertySharedProbe.exe",
                             output / "property-gc" / "PropertyGcProbe.exe")))
        required_fixture_modes.append((
            "--gc-array-elements", (output / "gc-array" / "GcArrayShapeProbe.exe",
                                    output / "gc-array" / "GcArrayShapeProbe.map")))
        required_fixture_modes.append((
            "--marshalling-positive", (output / "marshalling" / "MarshallingProbe.exe",
                                       output / "marshalling" / "MarshallingProbe.map")))
    if dictionary_map is not None:
        required_fixture_modes.append(("--generic-context", (dictionary, dictionary_map)))

    for mode, fixtures in required_fixture_modes:
        run("dotnet", test_assembly, mode, *fixtures)

    run("dotnet", "publish", "src/Atlas.Cli/Atlas.Cli.csproj",
        "-c", "Release", "-r", rid, "--self-contained", "--output", output / "cli")

    run(sys.executable, "tests/command_contract_checks.py", cli, test_assembly, dictionary)
    run(sys.executable, "tests/search_cost_checks.py", cli, dictionary)
    run(sys.executable, "tests/search_scope_checks.py", cli, dictionary)
    run(sys.executable, "tests/speed_budget_checks.py", cli, dictionary)
    run(sys.executable, "tests/analysis_status_checks.py", cli, property_probe, dictionary)
    run(sys.executable, "tests/function_pointer_checks.py", cli, dictionary)
    run(sys.executable, "tests/property_rejection_checks.py", cli, property_probe)
    run(sys.executable, "tests/reference_setter_checks.py", cli, canonical_probe)
    run(sys.executable, "tests/metadata_name_checks.py", cli, dictionary)
    if windows:
        run(sys.executable, "tests/gc_array_cli_checks.py", cli,
            output / "gc-array" / "GcArrayShapeProbe.exe",
            output / "gc-array" / "GcArrayShapeProbe.map",
            output / "gc-array" / "types.json")
        run(sys.executable, "tests/resource_oracle_checks.py", cli,
            output / "resource" / "ResourceProbe.exe",
            root / "tests" / "golden" / "ResourceProbe.resources.json",
            output / "resource" / "resources.json")
        run(sys.executable, "tests/marshalling_oracle_checks.py", cli,
            output / "marshalling" / "MarshallingProbe.exe",
            root / "tests" / "golden" / "MarshallingProbe.layouts.json",
            output / "marshalling" / "marshalling.json")
    if string_probe is not None:
        run(sys.executable, "tests/string_precision_checks.py", cli, string_probe, string_oracle,
            output / "string-precision.json")
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
        run("dotnet", test_assembly, "--metadata-producers",
            *(root / "artifacts" / "runtime-checks" / "probes" / framework
              / "MetadataMembersProbe.exe" for framework in ("net8.0", "net9.0", "net10.0")))
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
