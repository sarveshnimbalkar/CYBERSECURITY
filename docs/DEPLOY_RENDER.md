# Deploy CloudGuard on Render

The repository includes a Render Blueprint in [`render.yaml`](../render.yaml). It defines a public dashboard, a private FastAPI service, a private PostgreSQL database, and a persistent model disk. **Review Render's live prices before creating the Blueprint:** the selected service, database, and disk plans are paid resources. The Blueprint has not been deployed or externally verified by this repository change.

## Create the deployment

1. Push the tested commit to `main` and connect the GitHub repository to Render.
2. In Render, create a Blueprint from `render.yaml`. Review the plan costs and set a unique, long `DASHBOARD_PASSWORD` when prompted. Render generates `SECRET_KEY`, `SENSOR_API_KEY`, and `ADMIN_API_KEY`; keep them out of source control.
3. Wait for the database, private API, and dashboard to become healthy. Open the dashboard's `https://...onrender.com/healthz` route, then open its root URL and sign in as `admin` with the dashboard password.
4. Retrieve `SENSOR_API_KEY` from the private API's Render environment settings. Store it only on the Falco forwarder host. For a real Linux sensor, set `CLOUDGUARD_FALCO_ENDPOINT=https://YOUR-DASHBOARD.onrender.com/api/ingest/falco` and `CLOUDGUARD_SENSOR_API_KEY` before starting the forwarder. This public route accepts only Falco alerts; `/api/ingest/heartbeat` accepts only sensor heartbeats. Both proxy to the private API and require the sensor key.
5. Check `GET /api/sensors` from the authenticated dashboard after a heartbeat. Send one harmless captured Falco alert and confirm its source, event ID, incident, and evidence. Inspect the sensor's queue/drop counters and confirm no raw key appears in the browser network responses.

For a controlled college demonstration using only synthetic scenarios, change `DEMO_MODE_ENABLED` to `true` on the private API and redeploy, then use the Demo page. Set it back to `false` when the demonstration is over. Synthetic scenarios do not prove real detection accuracy.

## Operations and security checks

- The public entry point is Render's managed HTTPS dashboard. The private API and database must not have public URLs. Verify this in the deployed Render service settings and with an external network check. Render's managed TLS and private networking are platform features; this repository has not yet confirmed a live deployment.
- The public sensor ingress uses a shared sensor key. Add a provider-level connection and rate limit before hostile internet exposure. The backend's limit is per process and applies only after a valid key; it does not stop unauthenticated flooding. Rotate the key immediately if exposed.
- Restrict the forwarder's SQLite spool file: it stores raw alerts. Monitor free disk space, `dead_letter`, queue depth, drop counters, and heartbeat staleness. A heartbeat is self-reported and cannot prove that all syscalls were observed.
- Keep the model disk mounted and `SECRET_KEY` stable across restarts. The model file has an HMAC seal checked before joblib deserialization; changing the secret invalidates the old model and requires retraining. The database needs backups and a tested restore; Render's service creation alone does not establish recovery.
- Set the dashboard's `DASHBOARD_PUBLIC_ORIGIN` to its exact `https://` origin if mutation calls return 403 after deployment. Review the Basic authentication model before granting access to multiple people: it uses shared role accounts, with no MFA or individual attribution.
- Schema tables are created on startup. Before evolving a shared deployment, add migrations and rehearse a backup/restore. Record Render service plan, deploy SHA, region, and external verification results in the college submission.

Platform references: [Render Blueprint specification](https://render.com/docs/blueprint-spec), [managed TLS](https://render.com/docs/tls), [private services](https://render.com/docs/private-services), [private networking](https://render.com/docs/private-network), and [persistent disks](https://render.com/docs/disks).
