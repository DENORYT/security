# C2 Training Lab — Offline Simulation Only

This project is a **safe alternative** to a deployable command-and-control framework. It helps describe controller/agent control flow in a tabletop, detection-engineering, or logging lab without creating remote control capability.

## What it does

- Reads a local JSON scenario.
- Enrolls synthetic agent profiles in memory.
- Queues only three benign task types: inventory snapshot, training check-in, and evidence label.
- Emits a deterministic synthetic transcript.

```bash
python -m projects.c2_lab --scenario projects/c2_lab/examples/training-scenario.json
```

## Non-negotiable safety constraints

The simulator has **no networking**, no listeners, no outbound connections, no subprocess invocation, no host inspection, no filesystem mutation, no credential handling, and no instruction execution. Its validation rejects unsafe task kinds and unsafe parameter terms. The tests explicitly guard these invariants.

The output's `simulated` status means exactly that: all observations are fabricated lab records. It is unsuitable for deployment and is intentionally incapable of controlling a device.

See [SAFETY.md](../../SAFETY.md) for repository-wide boundaries.
