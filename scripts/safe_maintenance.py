#!/usr/bin/env python3
"""Fail-closed local commit/push guard for Tellnova maintenance automation.

It is intentionally check-only unless --commit is supplied. It never force
pushes, changes remotes, or handles credentials.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from projects.pipeline_exposure.scanner import ExposureScanner, meets_or_exceeds

UNSAFE_NAME_PARTS = (".env", "id_rsa", "credential", "private_key", "private-key")
FIXTURE_PREFIX = "projects/pipeline_exposure/fixtures/unsafe-"
RUNTIME_PATHS = (".pi/goals/", ".pi/subagents/")
RUNTIME_FILES = {".pi/.goals-pool-snapshot.json"}


def run(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=capture, check=False)


def _is_runtime_path(path: str) -> bool:
    return path in RUNTIME_FILES or path.startswith(RUNTIME_PATHS)


def changed_paths() -> list[str]:
    tracked = run("git", "diff", "--name-only", "HEAD", capture=True)
    untracked = run("git", "ls-files", "--others", "--exclude-standard", capture=True)
    if tracked.returncode or untracked.returncode:
        raise RuntimeError("Unable to determine changed files")
    return sorted(
        {
            line
            for line in (tracked.stdout + "\n" + untracked.stdout).splitlines()
            if line and not _is_runtime_path(line)
        }
    )


def staged_paths() -> list[str]:
    staged = run("git", "diff", "--cached", "--name-only", capture=True)
    if staged.returncode:
        raise RuntimeError("Unable to inspect staged files")
    return [line for line in staged.stdout.splitlines() if line]


def uninspectable_changed_files(paths: list[str]) -> list[str]:
    """Reject files the changed-file scanner cannot inspect completely."""
    scanner = ExposureScanner()
    failures: list[str] = []
    for relative_path in paths:
        candidate = ROOT / relative_path
        if candidate.is_symlink():
            failures.append(f"symbolic link is not eligible for automation: {relative_path}")
            continue
        if not candidate.exists() or not candidate.is_file():
            continue  # A deletion has no new content to inspect.
        try:
            size = candidate.stat().st_size
        except OSError as error:
            failures.append(f"unable to inspect changed file {relative_path}: {error}")
            continue
        if size > scanner.max_file_bytes:
            failures.append(f"changed file exceeds {scanner.max_file_bytes} byte inspection limit: {relative_path}")
    return failures


def changed_file_exposure_findings(paths: list[str]) -> list[str]:
    scanner = ExposureScanner()
    candidates = [ROOT / path for path in paths if (ROOT / path).is_file()]
    findings = scanner.scan_files(candidates, display_root=ROOT)
    return [f"{finding.path}:{finding.line} ({finding.rule_id})" for finding in findings if meets_or_exceeds(finding, "high")]


def validate(paths: list[str]) -> list[str]:
    failures: list[str] = []
    if run(sys.executable, "scripts/validate.py").returncode:
        failures.append("portfolio validation failed")
    if run(
        "git",
        "diff",
        "--check",
        "--",
        ".",
        ":(exclude).pi/goals/**",
        ":(exclude).pi/subagents/**",
        ":(exclude).pi/.goals-pool-snapshot.json",
    ).returncode:
        failures.append("git diff --check failed for project files")
    if run(sys.executable, "-m", "projects.pipeline_exposure", ".github", "--fail-on", "high").returncode:
        failures.append("high-severity CI/CD exposure finding detected in .github")
    try:
        existing_staged_paths = staged_paths()
    except RuntimeError as error:
        failures.append(str(error))
    else:
        if existing_staged_paths:
            failures.append("pre-existing staged changes require human review")
    failures.extend(uninspectable_changed_files(paths))
    try:
        high_findings = changed_file_exposure_findings(paths)
    except OSError as error:
        failures.append(f"unable to scan changed files for exposure indicators: {error}")
    else:
        if high_findings:
            failures.append("high-severity exposure finding in changed file(s): " + ", ".join(high_findings))
    for path in paths:
        lower = path.casefold()
        if path.startswith(FIXTURE_PREFIX):
            failures.append("intentionally unsafe scanner fixtures are never auto-committed")
        if any(part in lower for part in UNSAFE_NAME_PARTS) or lower.endswith((".pem", ".key", ".p12", ".pfx")):
            failures.append(f"sensitive-looking path is not eligible for automation: {path}")
    return failures


def ensure_github_origin() -> str:
    remote = run("git", "remote", "get-url", "origin", capture=True)
    if remote.returncode:
        raise RuntimeError("Configured origin remote is required for a push")
    url = remote.stdout.strip()
    if not (url.startswith("https://github.com/") or url.startswith("git@github.com:")):
        raise RuntimeError("Automation only permits a configured GitHub origin")
    return url


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate safe maintenance changes before an optional local commit/push.")
    parser.add_argument("--check", action="store_true", help="Validate only (the default behavior).")
    parser.add_argument("--commit", action="store_true", help="Create a local commit after all safety gates pass.")
    parser.add_argument("--push", action="store_true", help="Push the guarded local commit to origin/main; requires --commit.")
    parser.add_argument("--message", default="chore(maintenance): validated portfolio updates", help="Commit message for guarded automation.")
    args = parser.parse_args()
    if args.push and not args.commit:
        parser.error("--push requires --commit")

    try:
        paths = changed_paths()
    except RuntimeError as error:
        print(f"Guard failed: {error}", file=sys.stderr)
        return 1
    if not paths:
        print("Guard passed: no changes to commit.")
        return 0

    failures = validate(paths)
    if failures:
        print("Guard blocked automation:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Guard passed for {len(paths)} changed file(s).")
    if not args.commit:
        return 0

    if run("git", "add", "--all", "--", *paths).returncode:
        print("Guard failed while staging validated changes", file=sys.stderr)
        return 1
    try:
        staged_after_add = staged_paths()
    except RuntimeError as error:
        print(f"Guard failed: {error}", file=sys.stderr)
        return 1
    unexpected_staged = sorted(set(staged_after_add) - set(paths))
    if unexpected_staged:
        print("Guard blocked commit because unexpected staged files appeared: " + ", ".join(unexpected_staged), file=sys.stderr)
        return 1
    if run("git", "diff", "--cached", "--check").returncode:
        print("Guard failed staged diff check", file=sys.stderr)
        return 1
    if run("git", "commit", "-m", args.message).returncode:
        print("Guard failed while creating local commit", file=sys.stderr)
        return 1
    if not args.push:
        print("Guard created a validated local commit.")
        return 0

    try:
        ensure_github_origin()
    except RuntimeError as error:
        print(f"Guard blocked push: {error}", file=sys.stderr)
        return 1
    if run("git", "push", "origin", "HEAD:main").returncode:
        print("Guard created a local commit but remote push was rejected or unavailable.", file=sys.stderr)
        return 1
    print("Guard created and pushed a validated commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
