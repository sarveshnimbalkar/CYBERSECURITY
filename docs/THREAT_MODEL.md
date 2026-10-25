# Threat model for CloudGuard itself

Last reviewed: 2026-10-25. This document covers the security platform, not only the workloads it monitors.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| Telemetry and raw Falco alerts | Can contain commands, paths, IPs, identities, and sensitive operational data |
| Incidents and analyst decisions | Incorrect or altered status can hide a real attack |
| API key and dashboard credentials | Control ingestion and dashboard access |
| Model file and training data | Tampering can suppress or fabricate anomaly alerts |
| PostgreSQL database | Stores evidence, incidents, and credentials/configuration context |

```text
Falco / forwarder ──[public HTTPS sensor ingress]──> Next.js ──[private network]──> FastAPI ──[database boundary]──> PostgreSQL
Browser ──[Basic authentication boundary]──> Next.js proxy ──[role-key boundary]──> FastAPI
Synthetic demo API ──[explicit demo-mode boundary]──> FastAPI pipeline
Model artifact ──[local file trust boundary]──> Python model loader
```

## Threats, present controls, and remaining gaps

| Threat | Present control | Remaining action |
|---|---|---|
| Unauthorized API reads/writes | Scoped sensor, viewer, analyst and admin keys; private backend in the Render template | Individual identities, rotation, expiry and authorization review |
| Dashboard account compromise | Server-side Basic challenge, role keys stay server-side, mutation origin check | Public HTTPS deployment verification, MFA/session login, account lockout |
| Telemetry spoofing/replay | Sensor key required; Falco event IDs deduplicate normal sequential retries | Per-sensor keys, timestamp tolerance, concurrent deduplication and replay protection |
| Denial of service through large or frequent events | 128 KiB backend and public-ingress cap, process-local per-key limit, SQLite forwarder spool | Distributed edge rate/connection limits, spool quotas and load testing |
| Model poisoning | Synthetic and live baseline sources are separate | Approve training windows, quarantine suspect events, restrict promotion rights |
| Model file tampering | HMAC checked before deserializing the joblib file; separate persistent model volume | Separate signing key, file write restrictions and approved model promotion |
| Altered evidence or incident status | Database records events/detections and role/IP/before/after audit entries for mutations | Immutable/hash-chained audit export and individual actor identity |
| Secret leakage | Compose reads secrets from environment; no browser API key | External secret store, rotation, log scrubbing, no secrets in raw event payload |
| Database compromise | Database port is not published in Compose | TLS between services where needed, backups, restricted DB role, encryption at rest |
| Sensor outage or dropped alerts | Sensor heartbeat, queue/drop/parse counters and SQLite forwarder spool | Independent alert on stale heartbeat, disk-full alarms and end-to-end loss measurement |
| Insecure automatic response | No container action is executed | If response is added, require approval, narrow privileges, dry run, rollback, and audit |

## Security invariants

1. A browser never receives the backend API key.
2. Demo events are explicitly labeled and cannot be enabled accidentally in the production API.
3. A rule's ATT&CK ID represents a supported hypothesis, not proof of successful attack.
4. Every incident must retain the underlying event and detection records.
5. A failed sensor or model must be visible as degraded coverage; it must not silently report “all clear.”

Before remote deployment, test these invariants with an external network scan and an authenticated/unauthenticated API review. Use [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final) for container security boundaries and [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) for incident-response process design.
