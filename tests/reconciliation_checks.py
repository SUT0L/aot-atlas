import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    header = arguments.header.resolve()
    if "#define BN_CURRENT_CORE_ABI_VERSION 187" not in header.read_text():
        raise ValueError("The independently obtained Binary Ninja header must describe ABI 187.")

    with tempfile.TemporaryDirectory(prefix="aot-atlas-reconciliation-") as directory:
        temporary = Path(directory)
        library = temporary / "libbinaryninjacore.so"
        subprocess.run([
            "cc", "-shared", "-fPIC", "-std=gnu11", "-pthread", "-include", str(header),
            str(root / "tests/BinjaReconciliationChecks/host.c"), "-o", str(library)
        ], check=True)
        subprocess.run([
            "dotnet", "build", str(root / "tests/BinjaReconciliationChecks/BinjaReconciliationChecks.csproj"),
            "--artifacts-path", str(temporary / "build"),
            "-m:1", "-nodeReuse:false", "-p:UseSharedCompilation=false"
        ], check=True)
        subprocess.run([
            "dotnet", str(temporary / "build/bin/BinjaReconciliationChecks/debug/aot-atlas-binja.dll"),
            str(library)
        ], check=True)
        snapshots = []
        for origin in ("legacy-atlas", "legacy-user"):
            result = subprocess.run([
                "dotnet", str(temporary / "build/bin/BinjaReconciliationChecks/debug/aot-atlas-binja.dll"),
                str(library), origin
            ], check=True, text=True, capture_output=True)
            snapshots.append(result.stdout)
        assert snapshots[0] == snapshots[1], "Legacy histories became distinguishable at the native annotation boundary."
        print("ABI shim: identical legacy Atlas/user native states; exact automatic type provenance retired, unidentifiable user annotations preserved.")
        subprocess.run([
            "dotnet", str(temporary / "build/bin/BinjaReconciliationChecks/debug/aot-atlas-binja.dll"),
            str(library), "private-cache"
        ], check=True)
        subprocess.run([
            "dotnet", str(temporary / "build/bin/BinjaReconciliationChecks/debug/aot-atlas-binja.dll"),
            str(library), "enums"
        ], check=True)
        subprocess.run([
            "dotnet", str(temporary / "build/bin/BinjaReconciliationChecks/debug/aot-atlas-binja.dll"),
            str(library), "operations"
        ], check=True)
        for scenario in ("symbol-kinds", "snapshot-reuse", "forward-types", "missing-receiver"):
            subprocess.run([
                "dotnet", str(temporary / "build/bin/BinjaReconciliationChecks/debug/aot-atlas-binja.dll"),
                str(library), scenario
            ], check=True)


if __name__ == "__main__":
    main()
