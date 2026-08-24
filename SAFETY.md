# Safety Policy

This portfolio is designed for defensive engineering, controlled training, and offline simulation.

## Allowed scope

- Parsing and scoring HTTP request metadata for defensive decisions.
- Detecting accidental CI/CD secret exposure and unsafe workflow configuration.
- Dry-run incident-response plans that only record simulated actions in memory.
- Deterministic tabletop simulations that model control-flow without any network or host-control capability.

## Prohibited scope

Do not add or enable:

- Network listeners, beaconing, remote control, or data exfiltration.
- Shell/process execution, payload launchers, persistence, credential collection, or evasion.
- Exploit delivery, brute force, scanning of third-party systems, or bypass guidance.
- Live destructive response actions, including account disabling, host isolation, deletion, or firewall changes.
- Real secrets, API keys, access tokens, or private certificates in fixtures, documentation, commits, or logs.

## Required safeguards for changes

1. Keep the default behavior local and non-destructive.
2. Add or update a test for every security-sensitive behavior.
3. Redact sensitive values from scanner output and test fixtures.
4. Document assumptions, false positives, and operational limits.
5. Run the full test suite and `python scripts/validate.py` before committing.

If a requested feature would cross a prohibited boundary, stop and redesign it as an offline simulation or seek explicit security review.
