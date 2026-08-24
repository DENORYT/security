# CI/CD Pipeline Exposure Management

This package scans local repository configuration for high-signal indicators of leaked credentials and risky GitHub Actions workflow patterns. It is fully offline: it does not call a provider API, upload file content, or retain findings outside the current process.

## Run it

```bash
python -m projects.pipeline_exposure . --format text
python -m projects.pipeline_exposure . --format json --fail-on high
```

The scanner checks common text configuration files for:

- private-key headers, AWS-style access-key identifiers, GitHub token-like strings, and inline secret-like assignments;
- GitHub Actions references not pinned to a full commit SHA;
- `pull_request_target`, `permissions: write-all`, and piping remote content directly to a shell.

Detected values are redacted in output. Findings report a path, line, severity, rule ID, and remediation-oriented explanation.

## Remediation workflow

1. Revoke and rotate any genuine exposed credential immediately.
2. Remove it from current and historical repository content according to your organization's procedure.
3. Move secrets to the CI platform's secret store and use least-privilege credentials.
4. Pin GitHub Actions to reviewed full commit SHAs.
5. Replace broad permissions with per-job, least-privilege scopes.
6. Avoid privileged `pull_request_target` execution for untrusted pull-request code.
7. Download, verify, and pin install artifacts instead of piping remote content to a shell.

## Limits

This is a heuristic pre-commit/CI aid, not a replacement for secret rotation, enterprise scanning, or a security review. It may produce false positives and deliberately does not inspect binary, ignored, symlinked, or very large files.
