# Threat model for CloudGuard itself

Last reviewed: 2026-10-24. This document covers the security platform, not only the workloads it monitors.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| Telemetry and raw Falco alerts | Can contain commands, paths, IPs, identities, and sensitive operational data |
| Incidents and analyst decisions | Incorrect or altered status can hide a real attack |
| API key and dashboard credentials | Control ingestion and dashboard access |
| Model file and training data | Tampering can suppress or fabricate anomaly alerts |
| PostgreSQL database | Stores evidence, incidents, and credentials/configuration context |

```text
Falco process / forwarder ──[untrusted network boundary]──> FastAPI ──[database boundary]──> PostgreSQL
Browser ──[authentication boundary]──> Next.js proxy ──[service-key boundary]──> FastAPI
Synthetic demo API ──[explicit demo-mode boundary]──> FastAPI pipeline
Model artifact ──[local file trust boundary]──> Python model loader
```

## Threats, present controls, and remaining gaps

| Threat | Present control | Remaining action |
|---|---|---|
| Unauthorized API reads/writes | API key on application routes; backend bound locally in Compose | Separate writer/analyst identities, key rotation, authorization by action |
| Dashboard account compromise | Server-side Basic challenge; API key stays server-side | HTTPS, MFA/session-based login, account lockout, audit trail |
| Telemetry spoofing/replay | Only a caller with API key can ingest | Per-sensor identity, signed event IDs, timestamps with tolerance, replay cache |
| Denial of service through large or frequent events | Route allowlist in dashboard proxy | Request-size limits, rate limits, queue/backpressure, quotas |
| Model poisoning | Synthetic and live baseline sources are separate | Approve training windows, quarantine suspect events, restrict promotion rights |
| Model file tampering | Model path is local and version checked | Restrict filesystem writes; checksum/signature before loading serialized model |
| Altered evidence or incident status | Database records events and detections | Immutable/hash-chained audit export, actor identity, before/after values |
| Secret leakage | Compose reads secrets from environment; no browser API key | External secret store, rotation, log scrubbing, no secrets in raw event payload |
| Database compromise | Database port is not published in Compose | TLS between services where needed, backups, restricted DB role, encryption at rest |
| Sensor outage or dropped alerts | Dashboard health check | Sensor heartbeats, drop counters, durable forwarder queue and alert on gaps |
| Insecure automatic response | No container action is executed | If response is added, require approval, narrow privileges, dry run, rollback, and audit |

## Security invariants

1. A browser never receives the backend API key.
2. Demo events are explicitly labeled and cannot be enabled accidentally in the production API.
3. A rule's ATT&CK ID represents a supported hypothesis, not proof of successful attack.
4. Every incident must retain the underlying event and detection records.
5. A failed sensor or model must be visible as degraded coverage; it must not silently report “all clear.”

Before remote deployment, test these invariants with an external network scan and an authenticated/unauthenticated API review. Use [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final) for container security boundaries and [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) for incident-response process design.
