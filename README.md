# Defensive Security Engineering Portfolio

A practical, safety-first portfolio of four small security engineering projects. Each project is runnable with the Python standard library, has regression tests, and is intentionally scoped for defensive training and local evaluation.

> **Safety boundary:** This repository does not include deployable command-and-control, payload delivery, persistence, credential theft, evasive techniques, exploit code, network listeners, or live response integrations. The C2 item is a deterministic, offline simulation only.

## Projects

| Area | Project | What it demonstrates |
| --- | --- | --- |
| Defensive ML | [`projects/waf_guard`](projects/waf_guard/README.md) | Explainable request-risk scoring using a small Bernoulli Naive Bayes classifier plus deterministic guardrails. |
| Security training | [`projects/c2_lab`](projects/c2_lab/README.md) | A no-network, no-command-execution control-flow simulator for tabletop and detection labs. |
| DevSecOps | [`projects/pipeline_exposure`](projects/pipeline_exposure/README.md) | Offline CI/CD configuration scanner for exposed secrets and risky GitHub Actions settings. |
| SOC automation | [`projects/soar_playbook`](projects/soar_playbook/README.md) | Dry-run incident-response planner with auditable, in-memory simulated actions. |

## Quick start

Requires Python 3.11 or newer. No third-party dependencies are needed.

```bash
python -m unittest discover -s tests -v
python -m projects.waf_guard --request projects/waf_guard/examples/benign-request.json
python -m projects.c2_lab --scenario projects/c2_lab/examples/training-scenario.json
python -m projects.pipeline_exposure projects/pipeline_exposure/fixtures --format text
python -m projects.soar_playbook --alert projects/soar_playbook/examples/credential-exposure.json
```

## Repository standards

- Read [SAFETY.md](SAFETY.md) before extending any project.
- Report vulnerabilities privately under [SECURITY.md](SECURITY.md).
- Follow the local validation and change-review expectations in [CONTRIBUTING.md](CONTRIBUTING.md).
- The architecture and trust boundaries are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Tellnova maintenance automation is documented in [.tellnova/AUTOMATION.md](.tellnova/AUTOMATION.md). It is deliberately fail-closed: it validates, scans, and reviews before it may make a local commit or push.

## Development philosophy

These projects prioritize clarity, observable decisions, predictable tests, and safe defaults over claims of production readiness. They are portfolio exercises and starting points for a controlled lab—not replacements for a mature WAF, a managed secrets scanner, or an incident-response platform.

## License

MIT. See [LICENSE](LICENSE).
