# Automated Incident Response Playbook (SOAR)

This project turns a local alert into an auditable incident-response plan. It is **dry-run by default** and has no live SIEM, EDR, identity, ticketing, email, webhook, cloud, or network integration.

## Run it

```bash
# Default: creates a plan only
python -m projects.soar_playbook --alert projects/soar_playbook/examples/credential-exposure.json

# Explicit lab-only mode: records safe synthetic statuses in an in-memory ledger
python -m projects.soar_playbook --alert projects/soar_playbook/examples/credential-exposure.json --simulate
```

The engine opens a conceptual case, requests evidence preservation, notifies an analyst, and—for high severity or credential exposure—creates approval-gated containment or credential-rotation requests. It never performs those actions.

## Safety model

- **Dry-run** returns planned actions and no audit side effects.
- **In-memory simulation** records only transient `simulated` / `awaiting_approval` states.
- Any containment or credential rotation request needs an explicit named approval in the lab interface and still remains a simulation.
- There are no credentials, network clients, external connectors, or destructive calls in this package.

## Operational notes

A real SOAR implementation needs organization-specific ownership, authorization, logging retention, escalation paths, idempotency controls, connector authentication, and post-incident review. This project intentionally demonstrates the decision layer only.
