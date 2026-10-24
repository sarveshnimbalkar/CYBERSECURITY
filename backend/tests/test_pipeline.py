"""Critical integration checks for authorization, training, and alert ingestion."""
import os
import tempfile
import unittest
from pathlib import Path


class PipelineIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        folder = Path(cls.scratch.name)
        os.environ.update({
            "DATABASE_URL": "sqlite+aiosqlite:///" + str(folder / "cloudguard.db").replace("\\", "/"),
            "API_KEY": "integration-test-key",
            "DEMO_MODE_ENABLED": "true",
            "DEBUG": "false",
            "MODEL_PATH": str(folder / "model.joblib"),
        })
        from app.main import app
        from fastapi.testclient import TestClient
        cls.client = TestClient(app)
        cls.client.__enter__()
        cls.headers = {"X-API-Key": "integration-test-key"}

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        cls.scratch.cleanup()

    def test_pipeline_contract(self):
        self.assertEqual(self.client.get("/api/incidents").status_code, 401)
        health = self.client.get("/api/health", headers=self.headers)
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json()["demo_mode"])

        seeded = self.client.post("/api/demo/seed-baseline", headers=self.headers)
        self.assertEqual(seeded.status_code, 200)
        trained = self.client.post("/api/model/train?include_simulated=true", headers=self.headers)
        self.assertEqual(trained.status_code, 200)
        self.assertEqual(trained.json()["baseline_source"], "baseline_simulated")

        all_scenarios = self.client.post("/api/demo/simulate-all", headers=self.headers)
        self.assertEqual(all_scenarios.status_code, 200)
        scenario_catalog = self.client.get("/api/demo/scenarios", headers=self.headers).json()
        self.assertEqual(all_scenarios.json()["scenarios_run"], len(scenario_catalog))
        self.assertEqual(len(scenario_catalog), 10)
        incidents = self.client.get("/api/incidents", headers=self.headers).json()
        self.assertTrue(any(item["detection_rule"] == "RULE-006" for item in incidents))
        self.assertEqual(len({item["incident_number"] for item in incidents}), len(incidents))
        detections = [detection for item in incidents for detection in
                      self.client.get(f"/api/incidents/{item['id']}/detections", headers=self.headers).json()]
        expected = {item["id"]: set(item["expected_rules"]) for item in scenario_catalog}
        for result in all_scenarios.json()["results"]:
            event_ids = set(result["event_ids"])
            observed = {item["rule_id"] for item in detections if item["event_id"] in event_ids}
            self.assertTrue(expected[result["scenario"]].issubset(observed), result["scenario"])

        falco_alert = {
            "time": "2026-10-24T12:00:00Z",
            "rule": "Terminal shell in container",
            "priority": "Critical",
            "output": "shell opened",
            "hostname": "node-1",
            "output_fields": {"container.id": "abc123", "proc.name": "bash", "evt.type": "execve"},
        }
        ingested = self.client.post("/api/falco/events", headers=self.headers, json=falco_alert)
        self.assertEqual(ingested.status_code, 201)
        self.assertEqual(ingested.json()["source"], "falco")

        credential_alert = {
            "time": "2026-10-24T12:01:00Z",
            "rule": "Unexpected service-account token read",
            "priority": "Warning",
            "output": "token read by cat",
            "hostname": "node-1",
            "output_fields": {
                "container.id": "abc123", "proc.name": "cat", "evt.type": "openat",
                "evt.arg.flags": "O_RDONLY",
                "fd.name": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            },
        }
        credential_event = self.client.post("/api/falco/events", headers=self.headers, json=credential_alert)
        self.assertEqual(credential_event.status_code, 201)
        self.assertEqual(credential_event.json()["event_type"], "FILE_READ")
        incident_rows = self.client.get("/api/incidents", headers=self.headers).json()
        credential_detections = [d for item in incident_rows for d in
                                 self.client.get(f"/api/incidents/{item['id']}/detections", headers=self.headers).json()
                                 if d["event_id"] == credential_event.json()["id"]]
        self.assertIn("RULE-008", {d["rule_id"] for d in credential_detections})


if __name__ == "__main__":
    unittest.main()
