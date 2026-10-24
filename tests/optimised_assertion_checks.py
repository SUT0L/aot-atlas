import ast
import subprocess
import sys
from pathlib import Path


def has_optimisation_guard(tree):
    for statement in tree.body:
        if not isinstance(statement, ast.If):
            continue
        test = statement.test
        if (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Name) and test.operand.id == "__debug__"
                and any(isinstance(item, ast.Raise) for item in statement.body)):
            return True
    return False


def main():
    directory = Path(__file__).resolve().parent
    guarded = []

    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            continue
        if not has_optimisation_guard(tree):
            raise AssertionError(f"Bare assertions can vanish under Python optimisation: {path}")
        guarded.append(path)

    if not guarded:
        raise AssertionError("No assertion bearing scripts were checked.")

    for path in guarded:
        result = subprocess.run([sys.executable, "-O", str(path), "--help"],
                                capture_output=True, text=True, encoding="utf-8")
        if result.returncode == 0 or "Tests require Python assertions" not in result.stderr:
            raise AssertionError(f"Optimised run did not fail before assertions were stripped: {path}")

    print(f"{len(guarded)} assertion bearing scripts fail closed under Python optimisation.")


if __name__ == "__main__":
    main()
