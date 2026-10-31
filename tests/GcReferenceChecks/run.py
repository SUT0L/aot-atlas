import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen


REVISION = "60629d14374c56f1cb51819049ad1fa529307f8d"
SOURCES = {
    "inc/gcinfo.h": "766b5b73d6bfc971027c2a837764c9d52daed43484cccecab5f3805c17e27f85",
    "inc/gcinfotypes.h": "2863743f431996a10bde8c999dc27c0ef8c52e675c6c06754d6b0a2a9e6e1864",
    "inc/gcinfodecoder.h": "79030fbf963da3cb3f121e2208818dbe7e312b439b138441bc667297b716815c",
    "vm/gcinfodecoder.cpp": "48c26a18bdb5ff3e60967cc8e93064e9419f484de38b29f7ddec817682e34971",
}


def run(command, **kwargs):
    print("+", *map(str, command), flush=True)
    return subprocess.run([str(value) for value in command], check=True, **kwargs)


def runtime_sources(repository, output):
    files = []
    for relative, expected_hash in SOURCES.items():
        destination = output / "runtime" / relative
        data = destination.read_bytes() if destination.exists() else b""
        if hashlib.sha256(data).hexdigest() != expected_hash:
            local = repository / "src" / "coreclr" / relative
            data = local.read_bytes() if local.exists() else b""
            if hashlib.sha256(data).hexdigest() != expected_hash:
                url = f"https://raw.githubusercontent.com/dotnet/runtime/{REVISION}/src/coreclr/{relative}"
                print(f"Downloading pinned Microsoft decoder: {relative}", flush=True)
                with urlopen(url, timeout=30) as response:
                    data = response.read()
            if hashlib.sha256(data).hexdigest() != expected_hash:
                raise RuntimeError(f"Pinned Microsoft decoder source hash differs: {relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        files.append(destination)
    return files


def native_library(source_files, here, output, compiler):
    compiler_name = Path(compiler).name.lower()
    msvc = compiler_name in ("cl", "cl.exe")
    version = subprocess.run(
        [compiler, "/Bv" if msvc else "--version"], capture_output=True, check=False)
    compile_flags = ["/nologo", "/std:c++17", "/O2", "/DNDEBUG", "/EHsc", "/LD"] if msvc else [
        "-std=c++17", "-O2", "-DNDEBUG", "-shared"]
    if not msvc and sys.platform != "win32":
        compile_flags.append("-fPIC")
    digest = hashlib.sha256(version.stdout + version.stderr)
    digest.update("\0".join([sys.platform, compiler, *compile_flags]).encode())
    adapters = [here / name for name in (
        "bridge.cpp", "common.h", "daccess.h", "decoder.cpp", "legacy_decoder.cpp")]
    for path in [*source_files, *adapters]:
        digest.update(path.read_bytes())
    suffix = ".dll" if sys.platform == "win32" else ".so"
    library = output / f"gc-reference-{digest.hexdigest()[:20]}{suffix}"
    if library.exists():
        print(f"Microsoft GC decoder build reused: {library.name}", flush=True)
        return library

    include_directories = [here, output / "runtime" / "inc", output / "runtime" / "vm"]
    units = [here / "decoder.cpp", here / "legacy_decoder.cpp"]
    include_prefix = "/I" if msvc else "-I"
    command = [compiler, *compile_flags]
    command.extend(f"{include_prefix}{path}" for path in include_directories)
    command.extend(units)
    command.extend(["/link", f"/OUT:{library}"] if msvc else ["-o", library])
    started = time.perf_counter()
    run(command, cwd=output)
    print(f"Microsoft GC decoder native build: {time.perf_counter() - started:.3f} s", flush=True)
    return library


def main():
    here = Path(__file__).resolve().parent
    root = here.parents[1]
    parser = argparse.ArgumentParser(description="Compare Atlas with the pinned Microsoft NativeAOT GC decoder")
    parser.add_argument("--runtime-source", type=Path, default=root / "artifacts" / "runtime-checks" / "repository")
    parser.add_argument("--output", type=Path, default=root / "artifacts" / "gc-reference")
    parser.add_argument("--compiler", default=os.environ.get("CXX"))
    parser.add_argument("--managed-assembly", type=Path)
    parser.add_argument("--cli", type=Path, required=True,
                        help="Built aot-atlas executable or managed CLI DLL")
    mutation = parser.add_mutually_exclusive_group()
    mutation.add_argument("--inject-slot-offset-error", action="store_true")
    mutation.add_argument("--inject-missing-chunk-start", action="store_true")
    parser.add_argument("binaries", type=Path, nargs="+")
    arguments = parser.parse_args()

    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    compiler = arguments.compiler or shutil.which("clang++") or shutil.which("g++") or shutil.which("cl")
    if not compiler:
        parser.error("GC reference checks require clang++, g++, or an initialized MSVC compiler environment")
    if any(not binary.is_file() for binary in arguments.binaries):
        parser.error("Every GC reference corpus input must be an existing PE file")
    if not arguments.cli.is_file():
        parser.error("--cli must identify a built aot-atlas executable or managed CLI DLL")

    sources = runtime_sources(arguments.runtime_source.resolve(), output)
    library = native_library(sources, here, output, compiler)
    assembly = arguments.managed_assembly
    if assembly is None:
        managed_output = output / "managed"
        run(["dotnet", "build", here / "GcReferenceChecks.csproj", "-c", "Release", "--nologo",
             f"-p:ArtifactsPath={managed_output}"])
        assembly = managed_output / "bin" / "GcReferenceChecks" / "release" / "GcReferenceChecks.dll"
    elif not assembly.is_file():
        parser.error("--managed-assembly must identify the built GC reference checker")
    command = ["dotnet", assembly, library, "--cli", arguments.cli.resolve()]
    if arguments.inject_slot_offset_error:
        command.append("--inject-slot-offset-error")
    if arguments.inject_missing_chunk_start:
        command.append("--inject-missing-chunk-start")
    command.extend(binary.resolve() for binary in arguments.binaries)
    started = time.perf_counter()
    run(command, cwd=root)
    print(f"GC reference batch wall time: {time.perf_counter() - started:.3f} s (one process; build excluded)", flush=True)


if __name__ == "__main__":
    main()
