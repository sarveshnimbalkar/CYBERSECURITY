# CloudGuard college project delivery plan

CloudGuard turns Falco container alerts into explainable incidents for an analyst to triage. The built-in simulation shows the workflow; a real Linux sensor and held-out evaluation are needed for detection claims.

## Current deliverable

- Ten transparent detection heuristics, Falco alert ingestion, incident grouping and SOC dashboard.
- Optional Isolation Forest trained on a labeled benign baseline. Training requires an admin key; the saved model is HMAC checked before loading.
- Separate sensor/viewer/analyst/admin API roles, Basic dashboard accounts, body caps, process-local rate limit and mutation origin check.
- Durable SQLite spool in the Falco forwarder, sequential retry idempotency, dead-letter handling, heartbeats and visible queue/drop counters.
- Audit entries for analyst incident changes and model training.
- A Render Blueprint for a public HTTPS dashboard with private API and database. It is a deployment template, not a verified live service.

## Three-day proof plan

| Day | Work | Evidence to save |
|---|---|---|
| 1 | Deploy the Render Blueprint after reviewing paid plans and secrets; run authenticated smoke checks | Public URL, commit SHA, service health, private-service settings, sensor role denial test |
| 2 | Run Falco on a disposable Linux test host and send harmless alerts through the forwarder; verify retries and sensor status | Captured Falco JSON, heartbeat counters, incident evidence, forwarded event ID |
| 3 | Replay held-out benign and attack traces, measure outcomes, and rehearse a short presentation | Confusion counts, precision/recall, false alerts per container-hour, detection latency, CPU/memory and limitations |

## Three-minute presentation

1. Explain the noisy-alert triage problem and show the data flow.
2. Send a harmless Falco alert from the test host, then open its incident and trace evidence back to the alert.
3. Show the sensor heartbeat, queue depth and drop count. Explain how stale status changes the coverage claim.
4. Show model status and training source. State clearly whether the baseline was synthetic or captured.
5. Acknowledge and resolve an incident. Explain that these are human triage actions, not container containment.
6. Show the held-out measurements only if collected; otherwise state that detection quality remains unvalidated.

## Completion criteria and remaining work

The first section is implemented in code and covered by local tests. A live Render URL, real Falco sensor, measured model quality, distributed rate limiting, individual users, migrations, tamper-evident audit exports, Kubernetes telemetry, and safe containment still require separate work. The full inventory and proof requirements are in [the cybersecurity concept roadmap](docs/CYBERSECURITY_CONCEPTS.md). Do not claim these planned capabilities during the presentation until there is code and evidence.
