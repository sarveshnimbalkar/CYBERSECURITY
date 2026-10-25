# Cybersecurity concepts for CloudGuard

Last reviewed: 2026-10-25. Scope: container runtime detection, incident triage, and the security of CloudGuard itself. “Implemented” means code exists, not that effectiveness has been proven on real workloads. “Prototype” means a limited implementation exists. “Planned” means it requires new telemetry, controls, or evaluation.

This is a broad, project-specific inventory rather than every concept in cybersecurity. Priorities reflect what would make CloudGuard more credible as a security tool.

| Priority | Meaning |
|---|---|
| P0 | Needed before exposing CloudGuard to a real environment |
| P1 | Strong next feature for a defensible security demonstration |
| P2 | Valuable after sensor coverage and evaluation are established |

## Runtime threat detection

| Concept | Status | Required work and proof | Priority |
|---|---|---|---|
| Falco alert normalization | Prototype | Validate against captured Falco JSON from several rule versions; report parse failures and missing fields | P1 |
| Raw syscall or eBPF telemetry | Planned | Add an authenticated, loss-aware collector for process, file, and network events; do not equate Falco alerts with all syscalls | P1 |
| Process ancestry and suspicious shells | Prototype | Capture executable path, parent chain, UID, TTY, image, and known legitimate shell use | P1 |
| Reverse-shell behavior | Prototype | Correlate the same PID/process lineage with an outbound connection and destination context | P1 |
| Privilege escalation indicators | Prototype | Distinguish root execution from actual privilege transition or exploit; add capability and namespace context | P1 |
| Container escape opportunities | Prototype | Detect runtime socket mounts/access and privileged container actions; confirm with host-side events before claiming escape | P1 |
| Credential-file access | Prototype | Monitor service-account tokens, cloud credentials, and kubeconfig reads with per-workload allowlists | P1 |
| Persistence mechanisms | Prototype | Monitor cron writes; add systemd timers, authorized keys, image modification, and Kubernetes jobs when telemetry exists | P1 |
| Security-tool impairment and log deletion | Prototype | Capture before/after file metadata and actor identity; distinguish normal rotation from tampering | P1 |
| Cryptomining/resource hijacking | Prototype | Correlate miner process, sustained CPU, pool indicators, and workload baseline | P1 |
| Ransomware/data destruction | Prototype | Add file entropy, rename patterns, write rate per process, and canary files before using a ransomware label | P1 |
| Exfiltration | Planned | Collect per-flow bytes, destination, DNS, protocol, and sensitive-file read correlation; benchmark normal bulk transfers | P1 |
| Command and control | Planned | Detect beacon periodicity, unusual destinations, and process-network relationships; avoid port-only judgments | P2 |
| Container/Kubernetes discovery | Planned | Collect API audit and process events for enumeration of pods, secrets, nodes, and services | P2 |
| Lateral movement | Planned | Correlate service-account use, cross-pod connections, Kubernetes exec, and remote access | P2 |
| Cloud metadata access | Planned | Detect access to metadata endpoints with workload identity context and expected traffic baselines | P2 |
| Kubernetes control-plane abuse | Planned | Ingest Kubernetes audit events for RBAC changes, privileged pods, hostPath mounts, and secret reads | P1 |

## Detection engineering and threat intelligence

| Concept | Status | Required work and proof | Priority |
|---|---|---|---|
| Behavioral rules vs indicators of compromise | Prototype | Keep behavior rules separate from IP/hash reputation feeds; record feed provenance and expiry | P1 |
| MITRE ATT&CK mapping | Prototype | Map only when observed evidence supports a technique; state that mapping is a hypothesis, not proof | P1 |
| Rule tuning and allowlists | Prototype | Add per-image/process exceptions with an owner, reason, expiry, and regression case | P1 |
| Multi-event correlation | Prototype | Correlate process identity, container ID, network flow, and time window; measure false correlations | P1 |
| Severity, confidence, and risk | Prototype | Calibrate from labeled events and asset context; separate observed severity from estimated impact | P1 |
| Suppression and deduplication | Prototype | Add rule-specific grouping keys and preserve every underlying event while reducing duplicate incidents | P1 |
| Detection coverage | Planned | Track ATT&CK techniques, required data sources, active sensors, and tested detections in a coverage matrix | P1 |
| Threat intelligence enrichment | Planned | Add signed/dated feeds, confidence, staleness, false-positive controls, and source attribution | P2 |
| Detection-as-code | Planned | Version rules, review changes, replay labeled traces, and retain rule version on each detection | P1 |
| Sensor health and blind spots | Prototype | Heartbeats report age, queue depth, drops, parse failures and restarts; add clock-skew measurement and an independent alert when heartbeats stop | P0 |

## Identity, platform protection, and supply chain

| Concept | Status | Required work and proof | Priority |
|---|---|---|---|
| API authentication | Prototype | Sensor, viewer, analyst and admin keys are separate; add individual identities, expiry and rotation | P0 |
| Role-based access control and least privilege | Prototype | Server-side sensor, viewer, analyst and admin scopes exist; add individual users and a dedicated responder workflow | P0 |
| TLS and service authentication | Prototype | Render template exposes the dashboard and sensor ingress over managed HTTPS; deploy and verify it, then add per-sensor identity or mTLS | P0 |
| Secret management | Prototype | Move secrets to a vault or orchestrator secret store; never expose them to browser code or logs | P0 |
| Audit logging and tamper evidence | Prototype | Incident mutations and training record role, action, IP, before/after and time; add individual identity and tamper-evident export | P0 |
| Rate limiting and input integrity | Prototype | 128 KiB request cap, schema checks, per-key process limit and Falco retry IDs exist; add distributed edge limits and concurrent replay control | P0 |
| Container isolation | Planned | Verify non-root, read-only filesystem, dropped capabilities, seccomp, AppArmor/SELinux, and limited mounts | P1 |
| Kubernetes Pod Security Standards | Planned | Use Baseline or Restricted policy according to workload needs; document exceptions | P1 |
| Network segmentation | Prototype | Render template uses a private API and database with public dashboard/ingress; verify deployed network policy and egress | P1 |
| Image provenance and signing | Planned | Pin images by digest, verify signatures, and restrict registry sources | P2 |
| SBOM and dependency vulnerabilities | Planned | Generate an SBOM, scan dependencies/images, and patch with a documented SLA | P2 |
| Backup and recovery | Planned | Encrypt backups, test restore, and define retention for incidents/evidence | P1 |

## Incident response and forensics

| Concept | Status | Required work and proof | Priority |
|---|---|---|---|
| Triage workflow | Prototype | Add analyst identity, notes, evidence links, assignment, and escalation timestamps | P1 |
| Evidence integrity and chain of custody | Planned | Hash raw evidence, record collection time/source, preserve originals, and log every access | P1 |
| Accurate attack timeline | Prototype | Render actual event/detection timestamps; include clock source and correlation confidence | P1 |
| Playbooks | Planned | Create scenario-specific investigation steps and evidence checklists; version playbooks | P1 |
| Human-approved containment | Planned | Require approval, narrowly scoped action, audit record, dry run, timeout, and rollback | P1 |
| Recovery and lessons learned | Planned | Track resolution cause, recovery actions, false-positive feedback, and rule/model improvements | P2 |

## Model security and validation

| Concept | Status | Required work and proof | Priority |
|---|---|---|---|
| Benign baseline provenance | Prototype | Record workload, collection window, source, exclusions, and who approved labels | P1 |
| Data/model poisoning resistance | Prototype | Training and live-baseline labeling require admin; model artifact is HMAC checked before deserialization; add sample review and promotion approval | P1 |
| Adversarial evasion | Planned | Test renamed processes, alternate paths, low-and-slow activity, and missing telemetry | P1 |
| Concept drift | Planned | Monitor feature shifts by workload and retrain only after review | P2 |
| Threshold calibration | Planned | Set thresholds using held-out benign and attack traces, not demo examples | P1 |
| Explainability | Prototype | Show rule evidence and ML feature contribution/nearest baseline examples; avoid claiming causal proof | P1 |
| Precision, recall, and false-positive rate | Planned | Publish confusion counts by scenario and workload, plus events per container-hour | P1 |
| Latency and sensor overhead | Planned | Report median/p95 detection time, dropped events, CPU, and memory | P1 |

## Documentation maintenance contract

When a security feature changes, update this inventory, the [detection catalog](DETECTION_CATALOG.md), the [threat model](THREAT_MODEL.md), and the root README if user-facing behavior changes. For each new rule, record input fields, trigger, ATT&CK evidence, known false positives, tuning options, one positive case, and one benign case. Do not mark a concept “implemented” based only on a simulated UI card.

Reference anchors: [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/), [NIST Application Container Security Guide](https://csrc.nist.gov/pubs/sp/800/190/final), [NIST Incident Response SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
