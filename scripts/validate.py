#!/usr/bin/env python3
"""Fail-closed local validation for the portfolio."""

from __future__ import annotations

import ast
import compileall
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
C2_ROOT = ROOT / "projects" / "c2_lab"

# The C2 lab is deliberately narrow. New imports or calls require an explicit
# review of this allowlist instead of silently expanding its capabilities.
_ALLOWED_DIRECT_IMPORTS = frozenset({"argparse", "json"})
_ALLOWED_FROM_IMPORTS = {
    (0, "__future__"): frozenset({"annotations"}),
    (0, "dataclasses"): frozenset({"asdict", "dataclass", "field"}),
    (0, "pathlib"): frozenset({"Path"}),
    (0, "typing"): frozenset({"Any", "Mapping"}),
    (1, "simulation"): frozenset({"AgentProfile", "LabSafetyError", "Task", "TrainingController", "run_scenario"}),
}
_ALLOWED_NAME_CALLS = frozenset(
    {
        "AgentProfile",
        "LabSafetyError",
        "SimulationEvent",
        "SystemExit",
        "Task",
        "TrainingController",
        "_validate_mapping",
        "_validate_text",
        "any",
        "asdict",
        "dataclass",
        "dict",
        "field",
        "frozenset",
        "isinstance",
        "len",
        "list",
        "main",
        "print",
        "run_scenario",
        "str",
        "type",
    }
)
_ALLOWED_ATTRIBUTE_CALLS = frozenset(
    {
        "ArgumentParser",
        "_record",
        "_synthetic_result",
        "add_argument",
        "append",
        "casefold",
        "dumps",
        "enroll",
        "error",
        "get",
        "items",
        "loads",
        "parse_args",
        "pop",
        "queue",
        "read_text",
        "simulate_all",
        "to_dict",
        "transcript",
    }
)
_DYNAMIC_OR_INTROSPECTION_NAMES = frozenset(
    {
        "__builtins__",
        "__import__",
        "breakpoint",
        "delattr",
        "dir",
        "getattr",
        "globals",
        "hasattr",
        "help",
        "importlib",
        "locals",
        "setattr",
        "vars",
    }
)


class _C2SafetyVisitor(ast.NodeVisitor):
    def __init__(self, source_path: Path) -> None:
        self.source_path = source_path
        self.violations: list[str] = []

    def _violation(self, node: ast.AST, message: str) -> None:
        self.violations.append(f"{self.source_path}:{getattr(node, 'lineno', '?')}: {message}")

    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            if imported.name not in _ALLOWED_DIRECT_IMPORTS or imported.asname:
                self._violation(node, f"import outside C2 allowlist: {imported.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        allowed_names = _ALLOWED_FROM_IMPORTS.get((node.level, node.module))
        imported_names = frozenset(name.name for name in node.names)
        if allowed_names is None or not imported_names.issubset(allowed_names) or any(name.asname for name in node.names):
            module = "." * node.level + (node.module or "")
            self._violation(node, f"from-import outside C2 allowlist: {module}")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in _DYNAMIC_OR_INTROSPECTION_NAMES:
            self._violation(node, f"dynamic or introspection primitive is prohibited: {node.id}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr.startswith("__"):
            self._violation(node, f"dunder attribute access is prohibited: {node.attr}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            if node.func.id not in _ALLOWED_NAME_CALLS:
                self._violation(node, f"call outside C2 allowlist: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr not in _ALLOWED_ATTRIBUTE_CALLS:
                self._violation(node, f"attribute call outside C2 allowlist: {node.func.attr}")
        else:
            self._violation(node, "dynamic callable expressions are prohibited")
        self.generic_visit(node)


def c2_safety_violations(source: str, source_path: Path) -> list[str]:
    """Return AST-detected capability expansions in a C2 lab module."""
    try:
        tree = ast.parse(source, filename=str(source_path))
    except SyntaxError as error:
        return [f"{source_path}:{error.lineno}: syntax error prevents safety inspection"]
    visitor = _C2SafetyVisitor(source_path)
    visitor.visit(tree)
    return visitor.violations


def validate_c2_lab(c2_root: Path = C2_ROOT) -> list[str]:
    """Inspect every C2 lab Python module with a fail-closed AST policy."""
    violations: list[str] = []
    for source_path in sorted(c2_root.rglob("*.py")):
        violations.extend(c2_safety_violations(source_path.read_text(encoding="utf-8"), source_path))
    return violations


def main() -> int:
    violations = validate_c2_lab()
    if violations:
        print("C2 safety validation failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    if not compileall.compile_dir(ROOT / "projects", quiet=1):
        print("Compile check failed", file=sys.stderr)
        return 1

    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
