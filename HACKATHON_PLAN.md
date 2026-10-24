# CloudGuard hackathon plan

## One-sentence pitch

“CloudGuard turns container security alerts into explainable incidents that an analyst can triage quickly, with an optional anomaly score trained on a labeled benign baseline.”

## Three-minute live demo

1. **Problem (20 seconds):** A small team receives noisy container alerts and needs to know which event matters, why, and what to inspect next.
2. **Live input (45 seconds):** On a Linux host running Falco, generate a harmless shell event inside a disposable test container. Forward Falco JSON to `/api/falco/events`. Show the source as `falco` in CloudGuard.
3. **Detection trace (45 seconds):** Open the incident and show the Falco rule, local rule matches, evidence, risk factors, source, and timestamps. Explain the difference between an observed fact and a heuristic.
4. **Model (35 seconds):** Show model status and its training source. If using the synthetic baseline, say so. Explain that the model adds a review signal and needs independent validation.
5. **Workflow (25 seconds):** Acknowledge and resolve an incident. These are analyst status changes; no container action occurs.
6. **Results and limits (10 seconds):** Show measured latency and false-positive numbers from your benchmark, then state the next step.

Keep a recorded Falco JSON alert and a screen recording as backup if the live Linux host fails.

## Evidence needed before claiming “accurate”

Build a labeled evaluation set with benign workload traces and attacks that were **not** used to tune the rules or train the model. Report:

| Measurement | How to report it |
|---|---|
| Precision and recall | Per scenario and overall, with confusion counts |
| False positives | Alerts per container-hour on routine workloads |
| Detection latency | Median and 95th percentile from event time to incident creation |
| Ingestion reliability | Received alerts, failed sends, duplicates, and drops |
| Runtime overhead | Falco and CloudGuard CPU/memory during load |
| Ablation | Rules only, model only, and combined pipeline |

The dashboard’s “events with alerts” ratio is an activity statistic. It cannot substitute for precision or recall.

## Strongest next improvements

1. **Reliability:** Add a durable queue, retries, idempotent event IDs, and dead-letter handling. The current forwarder can lose an alert on a failed POST.
2. **Better model:** Use process ancestry, executable path, container image, per-image baselines, rolling network and file rates, and an explicit missing-data mask. Calibrate the alert threshold on a held-out benign set. Track model version and training window for every score.
3. **Trust and access:** Give telemetry writers and analysts separate identities, rotate keys, record analyst actions, and rate-limit ingestion.
4. **Safer response:** Add a human approval screen before any containment. Implement a narrow action such as stopping one test container, with audit evidence and a reversible path, only in an isolated lab.
5. **Deployment:** Add Alembic migrations, CI, health checks, TLS, and a real Falco deployment manifest for a Linux/Kubernetes environment.

## Claims to make precisely

- **Implemented:** authenticated Falco alert ingestion, ten local heuristics, optional Isolation Forest, incident grouping, dashboard, and synthetic demo scenarios.
- **Demonstrated only with synthetic data:** model training and the built-in attack scenarios.
- **Not implemented:** automatic containment, complete eBPF syscall collection, robust delivery guarantees, multi-user roles, and validated real-world model accuracy.
