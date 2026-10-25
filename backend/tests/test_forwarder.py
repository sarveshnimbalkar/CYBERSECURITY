"""The forwarder must keep failed alerts and replay their stable IDs."""
import json
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from tools.falco_forwarder import Spool, run_worker


class ForwarderSpoolTest(unittest.TestCase):
    def test_persists_and_replays_after_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "spool.sqlite3"
            first = Spool(path)
            first.enqueue({"rule": "Shell in container", "time": "2026-10-25T10:00:00Z"})
            pending_id = json.loads(first.oldest()[1])["event_id"]
            self.assertEqual(first.metrics()["queue_depth"], 1)

            restarted = Spool(path)
            self.assertEqual(restarted.metrics()["restarts"], 1)
            stop = Event()
            stop.set()
            sent = []
            with patch("tools.falco_forwarder.post_json", side_effect=lambda endpoint, key, payload: sent.append((endpoint, payload))):
                run_worker(restarted, "http://127.0.0.1:8000/api/falco/events", "test-key", "node-1", stop)
            delivered = [payload for endpoint, payload in sent if endpoint.endswith("/falco/events")]
            self.assertEqual(len(delivered), 1)
            self.assertEqual(delivered[0]["event_id"], pending_id)
            self.assertEqual(restarted.metrics()["queue_depth"], 0)
            self.assertEqual(restarted.metrics()["sent_events"], 1)


if __name__ == "__main__":
    unittest.main()
