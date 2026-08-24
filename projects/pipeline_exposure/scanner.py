"""Offline, redacting scanner for common CI/CD exposure indicators."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from pathlib import Path
from typing import Iterable

_TEXT_SUFFIXES = {".yml", ".yaml", ".json", ".env", ".toml", ".ini", ".cfg", ".conf", ".properties", ".txt"}
_IGNORED_PARTS = {".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"}
_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_SECRET_RULES = (
    ("private-key-material", "critical", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "Private-key material appears in a tracked file."),
    ("aws-access-key", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access-key identifier appears in a tracked file."),
    ("github-token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "GitHub token-like value appears in a tracked file."),
    (
        "inline-secret-assignment",
        "high",
        re.compile(r"(?i)\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*[\"']?[^\s\"'#]{8,}"),
        "Inline secret-like assignment appears in a tracked file.",
    ),
)
_ACTION_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s@]+)@([^\s#]+)")
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_PR_TARGET = re.compile(r"^\s*pull_request_target\s*:")
_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.IGNORECASE)
_CURL_PIPE = re.compile(r"\bcurl\b[^\n|]*\|\s*(?:ba)?sh\b", re.IGNORECASE)
_ASSIGNMENT_VALUE = re.compile(
    r"(?i)(\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*[\"']?)([^\s\"'#]+)"
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    excerpt: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _redact(text: str) -> str:
    """Preserve context while never emitting the detected value itself."""
    text = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "<redacted-aws-access-key>", text)
    text = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "<redacted-github-token>", text)
    text = re.sub(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", "<redacted-private-key-header>", text)
    return _ASSIGNMENT_VALUE.sub(r"\1<redacted>", text).strip()


class ExposureScanner:
    """Scan local configuration files without network access or secret retention."""

    def __init__(self, max_file_bytes: int = 1_000_000) -> None:
        self.max_file_bytes = max_file_bytes

    def scan(self, root: str | Path) -> list[Finding]:
        root_path = Path(root).resolve()
        if not root_path.exists():
            raise FileNotFoundError(f"Scan root does not exist: {root_path}")
        findings: list[Finding] = []
        for path in self._candidate_files(root_path):
            relative_path = path.relative_to(root_path).as_posix() if root_path.is_dir() else path.name
            findings.extend(self._scan_file(path, relative_path))
        return sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))

    def scan_files(self, paths: Iterable[str | Path], display_root: str | Path | None = None) -> list[Finding]:
        """Scan explicit local files regardless of suffix for a commit-time gate.

        Unlike :meth:`scan`, this method accepts source and documentation files
        because a credential can be accidentally pasted outside CI config.
        """
        root_path = Path(display_root).resolve() if display_root is not None else None
        findings: list[Finding] = []
        for candidate in paths:
            path = Path(candidate).resolve()
            if path.is_symlink() or not path.is_file():
                continue
            try:
                relative_path = path.relative_to(root_path).as_posix() if root_path else path.name
            except ValueError:
                relative_path = path.name
            findings.extend(self._scan_file(path, relative_path))
        return sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))

    def _candidate_files(self, root: Path) -> Iterable[Path]:
        if root.is_file():
            if root.suffix.lower() in _TEXT_SUFFIXES or root.name.startswith(".env"):
                yield root
            return
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            relative_parts = path.relative_to(root).parts
            if any(part in _IGNORED_PARTS for part in relative_parts):
                continue
            if path.suffix.lower() in _TEXT_SUFFIXES or path.name.startswith(".env"):
                yield path

    def _scan_file(self, path: Path, relative_path: str) -> list[Finding]:
        if path.stat().st_size > self.max_file_bytes:
            return []
        content = path.read_text(encoding="utf-8", errors="replace")
        findings: list[Finding] = []
        for number, line in enumerate(content.splitlines(), start=1):
            for rule_id, severity, pattern, message in _SECRET_RULES:
                if pattern.search(line):
                    findings.append(Finding(rule_id, severity, relative_path, number, message, _redact(line)))

            action_match = _ACTION_USES.match(line)
            if action_match and not _FULL_SHA.fullmatch(action_match.group(2)):
                findings.append(
                    Finding(
                        "unpinned-github-action",
                        "medium",
                        relative_path,
                        number,
                        f"GitHub Action {action_match.group(1)!r} is not pinned to a full commit SHA.",
                        _redact(line),
                    )
                )
            if _PR_TARGET.match(line):
                findings.append(
                    Finding(
                        "pull-request-target",
                        "high",
                        relative_path,
                        number,
                        "pull_request_target can expose elevated workflow context to untrusted code.",
                        _redact(line),
                    )
                )
            if _WRITE_ALL.match(line):
                findings.append(
                    Finding(
                        "write-all-permissions",
                        "high",
                        relative_path,
                        number,
                        "Workflow grants write-all permissions; scope each permission explicitly.",
                        _redact(line),
                    )
                )
            if _CURL_PIPE.search(line):
                findings.append(
                    Finding(
                        "piped-remote-script",
                        "high",
                        relative_path,
                        number,
                        "Remote content is piped directly into a shell; download, verify, and pin it first.",
                        _redact(line),
                    )
                )
        return findings


def scan_path(root: str | Path) -> list[Finding]:
    """Convenience wrapper used by the CLI and tests."""
    return ExposureScanner().scan(root)


def meets_or_exceeds(finding: Finding, minimum: str) -> bool:
    return _SEVERITY_ORDER[finding.severity] >= _SEVERITY_ORDER[minimum]
