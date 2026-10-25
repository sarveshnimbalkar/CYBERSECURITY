# CloudGuard

CloudGuard is a container security alert triage prototype. It accepts Falco JSON alerts or labeled synthetic events, applies ten transparent detection rules, optionally scores events with a trained Isolation Forest, groups detections into incidents, and shows them in a SOC dashboard. It does **not** isolate containers or execute response actions.

## What is implemented

```text
Falco JSON alerts ── authenticated forwarder ──┐
                                                ├── FastAPI ingestion ── rules + optional ML ── incidents ── dashboard
Labeled synthetic events ── demo API ───────────┘
```

- Rule checks: shell execution, reverse-shell indicators, privilege changes, unusual external destinations, cryptomining indicators, rapid file modification, runtime socket access, credential-file access, cron persistence, and security-artifact tampering. See the [detection catalog](docs/DETECTION_CATALOG.md).
- Falco alerts become incidents even when their fields do not map to one of the ten local rules. Falco produces **alerts**, not a complete stream of every syscall.
- The Isolation Forest is optional. Training requires at least 200 events from a known benign baseline period. Demo training uses a separately labeled synthetic baseline. The model is not claimed to be validated on real attacks.
- Incident acknowledgement, resolution, and false-positive status are manual analyst actions.

## Run with Docker Compose

1. Copy `.env.example` to `.env` in the repository root.
2. Set unique, long values for `CLOUDGUARD_API_KEY`, `SECRET_KEY`, `POSTGRES_PASSWORD`, and `DASHBOARD_PASSWORD`. Use URL-safe characters for the database password because it is embedded in a connection URL.
3. Set `DEMO_MODE_ENABLED=true` for the hackathon demonstration.
4. Run `docker compose up --build` from the repository root.
5. Open `http://localhost:3000` and enter the configured dashboard credentials when prompted.

The dashboard proxies API calls through the Next.js server, which keeps the backend API key out of browser JavaScript. The backend is bound to local port 8000 for direct development requests; PostgreSQL is internal to Compose. Put the dashboard behind HTTPS before any remote deployment because browser Basic authentication requires transport encryption.

Direct API requests need `X-API-Key: <CLOUDGUARD_API_KEY>`. API docs are at `http://localhost:8000/api/docs`.

## Demo sequence

1. Open **Demo** and select **Seed benign events & train model**. The UI reports the model's training source and sample count.
2. Run **All 10 Scenarios**. The file modification scenario emits 55 events so it exceeds the rule's >50 events/minute threshold.
3. Open **Incidents**. Show the fired rule, evidence, risk breakdown, and analyst status actions.
4. Explain that the dashboard's “events with alerts” ratio is the share of events with at least one detection. It is not recall or accuracy.

The simulator does not launch attacks or create real containers. Its records are marked `simulated` or `baseline_simulated`.

## Verify the implementation

```bash
cd backend
python -m unittest discover -s tests -v

cd ../frontend
npm ci
npm run build
npm run lint
```

The integration check covers API authorization, model training, all ten scenarios and their expected rules, unique incident numbers, and Falco JSON ingestion.

The [cybersecurity concept roadmap](docs/CYBERSECURITY_CONCEPTS.md) tracks what is implemented, what needs telemetry, and what requires validation. The [threat model](docs/THREAT_MODEL.md) covers CloudGuard's own attack surface. The [security tooling guide](docs/SECURITY_TOOLING.md) records useful skills, MCP integrations, scanners, their current setup status, and when to use them.

## Falco ingestion

CloudGuard accepts the standard Falco JSON alert shape at `POST /api/falco/events`. Falco's JSON contains `time`, `rule`, `priority`, `output`, and `output_fields`. Relevant fields such as `container.id`, `proc.name`, `proc.cmdline`, `fd.rip`, and `fd.rport` are normalized when present. The original alert is retained as evidence.

One way to forward newline-delimited Falco JSON from a host is:

```bash
export CLOUDGUARD_API_KEY='your-key'
falco --json-output | python backend/tools/falco_forwarder.py
```

Set `CLOUDGUARD_FALCO_ENDPOINT` if the API is not at `http://127.0.0.1:8000/api/falco/events`. The forwarder requires a trusted network path. It currently logs failed sends and continues; add durable queueing before relying on it for uninterrupted capture. Falco rule output formats vary, so enrich Falco `output_fields` with process and container fields for stronger correlation.

Falco configuration and field availability are described in the [official output documentation](https://falco.org/docs/concepts/outputs/channels/) and [field reference](https://falco.org/docs/reference/rules/supported-fields/).

## Train with a real baseline

During a confirmed benign collection period, send normalized events to `POST /api/events` with `source="baseline_live"`, then call `POST /api/model/train`. The model trains on up to 5,000 labeled baseline events and requires at least 200. Falco alerts alone are unsuitable as a normal baseline because Falco emits alerts rather than all routine activity. `GET /api/model/status` shows whether a model is loaded and which source trained it. For the demo, the UI calls `POST /api/demo/seed-baseline` followed by `POST /api/model/train?include_simulated=true`. Synthetic training is only allowed when demo mode is enabled.

Anomaly scoring is an investigation signal. The present feature set and threshold have not been measured against a labeled real-world dataset. Training on compromised or unrepresentative traffic can make the model unreliable.

## Current limits and next evidence to collect

- No automatic containment. Add an explicit approval workflow, narrowly scoped runtime permissions, and rollback before any live response action.
- No reliable event queue or retry store. Add buffering and idempotent event IDs before large-scale ingestion.
- No measured precision, recall, false-positive rate, or detection latency. Evaluate against labeled benign and attack traces, including unseen containers and noisy workloads.
- Database tables are created at startup; there is no migration history yet. Add Alembic migrations before schema evolution in shared deployments.
- API access uses one shared key, and dashboard access uses one Basic account. Add individual identities, roles, key rotation, and audit trails for a multi-user deployment.
