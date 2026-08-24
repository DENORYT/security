# Portfolio Architecture

All projects are independent standard-library Python packages below `projects/`. A shared test suite in `tests/` exercises public behavior rather than relying on external services.

## Trust boundaries

| Component | Input | Output | Hard boundary |
| --- | --- | --- | --- |
| WAF Guard | Local JSON representation of an HTTP request | Explainable allow/challenge/block decision | Does not proxy traffic or mutate a network service. |
| C2 Training Lab | Local scenario JSON | Synthetic transcript | No network APIs, subprocesses, command execution, or host changes. |
| Pipeline Exposure Scanner | Local filesystem paths | Redacted findings | Never uploads scanned content or prints detected secret values. |
| SOAR Playbook | Local alert JSON | Dry-run or in-memory simulated action log | No live connectors, webhooks, account changes, or containment calls. |

## Validation model

`python scripts/validate.py` checks source safety invariants, validates every Python file can compile, runs unit tests, and detects malformed generated state. GitHub Actions executes the same validation on pushes and pull requests.

## Operational limits

The WAF model is an explainable teaching model, not a production model. Pattern-based CI/CD findings can have false positives. SOAR containment items are approval requests, not execution. The C2 simulator is intentionally not a C2 implementation.
