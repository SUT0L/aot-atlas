import argparse
import hashlib
import json
from pathlib import Path
import resource
import signal
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command, limit=None):
    def limit_child():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return subprocess.run(command, capture_output=True, text=True,
                          preexec_fn=limit_child if limit is not None else None)


parser = argparse.ArgumentParser(description="Check NativeAOT CLI file-size failures on Unix.")
parser.add_argument("executable", type=Path)
parser.add_argument("binary", type=Path)
arguments = parser.parse_args()
digest = hashlib.sha256(arguments.binary.read_bytes()).hexdigest()

with tempfile.TemporaryDirectory(prefix="aot-atlas-output-errors-") as temporary:
    directory = Path(temporary)
    sentinel = b"previous complete result\n"

    for operation, extension in [("extract", "json"), ("header", "h")]:
        output = directory / ("output." + extension)
        command = [str(arguments.executable.resolve()), operation,
                   str(arguments.binary.resolve()), str(output)]
        healthy = run(command)
        require(healthy.returncode == 0, healthy.stderr)
        expected = output.read_bytes()
        require(len(expected) > 1, "Fixture produced no output.")
        ceiling = 32 * 1024 * 1024 if operation == "extract" else 1024 * 1024
        limit = max(1, min(ceiling, len(expected) // 2))

        output.write_bytes(sentinel)
        failed = run(command, limit)
        require(failed.returncode == 1, f"{operation}: exit {failed.returncode}: {failed.stderr}")
        require("Output file size limit exceeded:" in failed.stderr,
                f"{operation}: missing file-size diagnostic: {failed.stderr}")
        require(output.read_bytes() == sentinel, f"{operation}: prior output changed.")
        require(not list(directory.glob("*.tmp")), f"{operation}: temporary output survived.")

        repaired = run(command)
        require(repaired.returncode == 0, repaired.stderr)
        require(not list(directory.glob("*.tmp")), f"{operation}: retry left temporary output.")

        if operation == "header":
            require(output.read_bytes() == expected, "Header bytes changed after the failed request.")
        else:
            document = json.loads(output.read_bytes())
            require(document["operation"] == operation and document["input_sha256"] == digest,
                    "Retry published another operation or input.")

        print(f"{operation}: file-size limit {limit}, exit 1, prior output preserved, retry passed")
