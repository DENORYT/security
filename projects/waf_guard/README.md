# WAF Guard — Explainable Request Risk Scoring

`waf_guard` is a defensive, local policy engine that classifies an HTTP request as `ALLOW`, `CHALLENGE`, or `BLOCK`. It combines a tiny Bernoulli Naive Bayes classifier trained on curated binary signals with deterministic high-confidence guardrails.

## Run it

```bash
python -m projects.waf_guard --request projects/waf_guard/examples/benign-request.json
python -m projects.waf_guard --request projects/waf_guard/examples/suspicious-request.json
```

The output includes the action, aggregate risk score, model probability, detected features, and human-readable reasons.

## Design

Signals include path traversal sequences, SQL-like syntax, script-like markup, sensitive-path probes, unusual HTTP methods, heavy encoding, and scanner-like user agents. The model is deliberately small enough to inspect in [`engine.py`](engine.py): probabilities use Laplace smoothing and are retrained deterministically from embedded, synthetic feature rows on each run.

## Limits and safe operation

This is a portfolio exercise, **not** a production reverse proxy or a substitute for a managed WAF. It does not listen on a port, forward traffic, retain requests, or modify an upstream service. Tune policy thresholds against a labelled, authorized data set before relying on any decision. False positives and false negatives are expected.

See the repository [Safety Policy](../../SAFETY.md) before extending detection logic.
