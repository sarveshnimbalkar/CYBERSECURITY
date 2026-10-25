# CloudGuard

CloudGuard is a container security alert triage prototype. It accepts Falco JSON alerts or labeled synthetic events, applies ten transparent detection rules, optionally scores events with a trained Isolation Forest, groups detections into incidents, and shows them in a SOC dashboard. It does **not** isolate containers or execute response actions.

## What is implemented

```text
Falco JSON alerts ── authenticated forwarder ──┐
                                                ├── FastAPI ingestion ── rules + optional ML ── incidents ── dashboard
Labeled synthetic events ── demo API ───────────┘
```

- Rule checks: shell execution, reverse-shell indicators, privilege changes, unusual external destinations, cryptomining indicators, rapid file modification, runtime socket access, credential-file access, cron persistence, and security-artifact tampering. See the [detection catalog](docs/DETECTION_CATALOG.md).
- Scoped API keys for sensors, viewers, analysts, and administrators. The dashboard can use separate Basic accounts for each role; server-side routes enforce the role independently. Role accounts are shared identities, not individual user accounts.
- Collector heartbeats expose last seen time, reported sent/dropped/parse counts, queue depth, and staleness. The Falco forwarder spools failed deliveries in SQLite, retries them, and uses event IDs to avoid duplicate ingestion on normal retries.
- Analyst incident changes and model training create actor-aware audit entries. The API caps write bodies at 128 KiB and applies a process-local request limit; an internet-facing deployment still needs an edge rate and connection limit.
- Falco alerts become incidents even when their fields do not map to one of the ten local rules. Falco produces **alerts**, not a complete stream of every syscall.
- The Isolation Forest is optional. Training requires at least 200 events from a known benign baseline period. Demo training uses a separately labeled synthetic baseline. The model is not claimed to be validated on real attacks.
- Incident acknowledgement, resolution, and false-positive status are manual analyst actions.

## Run with Docker Compose

1. Copy `.env.example` to `.env` in the repository root.
2. Set unique, long values for `CLOUDGUARD_SENSOR_API_KEY`, `CLOUDGUARD_ADMIN_API_KEY`, `SECRET_KEY`, `POSTGRES_PASSWORD`, and `DASHBOARD_PASSWORD`. Each backend key must be at least 32 characters in production. Use URL-safe characters for the database password because it is embedded in a connection URL. Optionally configure viewer/analyst API keys and matching dashboard usernames/passwords for limited-access accounts.
3. Set `DEMO_MODE_ENABLED=true` for a controlled college demonstration.
4. Run `docker compose up --build` from the repository root.
5. Open `http://localhost:3000` and enter the configured dashboard credentials when prompted.

The dashboard proxies API calls through the Next.js server, which keeps backend keys out of browser JavaScript. The backend is bound to local port 8000 for direct development requests; PostgreSQL is internal to Compose. Set `DASHBOARD_PUBLIC_ORIGIN` to the browser-visible origin if it differs from `http://localhost:3000`; mutation requests are checked against it. Put the dashboard and sensor-to-API traffic behind HTTPS before any remote deployment because Basic credentials and API keys require transport encryption.

Direct API requests need `X-API-Key` with a role-appropriate key. The sensor key can ingest and report a heartbeat but cannot read incidents. Viewer can read; analyst can also change incident status; admin can train the model and run demo actions. A sensor cannot submit `baseline_live` or simulated training data. API docs are at `http://localhost:8000/api/docs` in development and disabled in production.

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

The integration checks cover scoped authorization, sensor health, audit entries, request size rejection, retry idempotency, model training, all ten scenarios and their expected rules, unique incident numbers, and Falco JSON ingestion.

The [cybersecurity concept roadmap](docs/CYBERSECURITY_CONCEPTS.md) tracks what is implemented, what needs telemetry, and what requires validation. The [threat model](docs/THREAT_MODEL.md) covers CloudGuard's own attack surface. The [security tooling guide](docs/SECURITY_TOOLING.md) records useful skills, MCP integrations, scanners, their current setup status, and when to use them. The [college delivery plan](COLLEGE_PROJECT_PLAN.md) lists the evidence still needed.

## Public cloud deployment

The [Render deployment guide](docs/DEPLOY_RENDER.md) explains the paid Blueprint in [`render.yaml`](render.yaml). It creates a public HTTPS dashboard, private API and PostgreSQL services, and a persistent model disk. The public sensor endpoint is `https://YOUR-DASHBOARD.onrender.com/api/ingest/falco`; the forwarder sends heartbeats to the matching `/api/ingest/heartbeat` route. Review plan costs and secrets before creating resources. A live deployment and external security check have not yet been performed.

## Falco ingestion

CloudGuard accepts the standard Falco JSON alert shape at `POST /api/falco/events`. Falco's JSON contains `time`, `rule`, `priority`, `output`, and `output_fields`. Relevant fields such as `container.id`, `proc.name`, `proc.cmdline`, `fd.rip`, and `fd.rport` are normalized when present. The original alert is retained as evidence.

One way to forward newline-delimited Falco JSON from a host is:

```bash
export CLOUDGUARD_SENSOR_API_KEY='your-sensor-key'
falco --json-output | python backend/tools/falco_forwarder.py
```

Set `CLOUDGUARD_FALCO_ENDPOINT` if the API is not at `http://127.0.0.1:8000/api/falco/events`, `CLOUDGUARD_SENSOR_ID` to a stable collector name, and `CLOUDGUARD_SPOOL_PATH` to a protected persistent location. Failed sends remain in the local SQLite spool and replay when the forwarder runs again. Invalid alerts rejected with HTTP 400, 413, or 422 go into its `dead_letter` table for inspection; oversized input lines are counted as dropped. The spool contains raw alerts and must be access-controlled and backed up if evidence retention matters. A disk failure or exhausted spool filesystem can still lose input. Falco rule output formats vary, so enrich Falco `output_fields` with process and container fields for stronger correlation. `GET /api/sensors` reports heartbeat age and collector counters; these counters are self-reported and do not independently prove complete syscall coverage.

Falco configuration and field availability are described in the [official output documentation](https://falco.org/docs/concepts/outputs/channels/) and [field reference](https://falco.org/docs/reference/rules/supported-fields/).

## Train with a real baseline

During a confirmed benign collection period, send normalized events to `POST /api/events` with `source="baseline_live"`, then call `POST /api/model/train`. The model trains on up to 5,000 labeled baseline events and requires at least 200. Falco alerts alone are unsuitable as a normal baseline because Falco emits alerts rather than all routine activity. `GET /api/model/status` shows whether a model is loaded and which source trained it. For the demo, the UI calls `POST /api/demo/seed-baseline` followed by `POST /api/model/train?include_simulated=true`. Synthetic training is only allowed when demo mode is enabled.

Anomaly scoring is an investigation signal. The present feature set and threshold have not been measured against a labeled real-world dataset. Training on compromised or unrepresentative traffic can make the model unreliable.

## Current limits and next evidence to collect

- No automatic containment. Add an explicit approval workflow, narrowly scoped runtime permissions, and rollback before any live response action.
- The forwarder now has a local SQLite retry spool and Falco event IDs. It is not a distributed queue, and the API has not been load-tested for high-volume delivery or concurrent duplicate races.
- No measured precision, recall, false-positive rate, or detection latency. Evaluate against labeled benign and attack traces, including unseen containers and noisy workloads.
- Database tables are created at startup; there is no migration history yet. Add Alembic migrations before schema evolution in shared deployments.
- Role keys and optional role-specific dashboard accounts are shared by role. Add individual identities, key rotation, a durable tamper-evident audit export, and an identity provider for multi-user deployment.
