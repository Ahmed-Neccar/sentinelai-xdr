import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_sensor import replay_spool, spool_events  # noqa: E402


class FakeApi:
    def __init__(self) -> None:
        self.fail = True
        self.sent: list[dict] = []

    def post(self, path: str, payload: dict) -> dict:
        if self.fail:
            raise RuntimeError("simulated API interruption")
        self.sent.extend(payload["events"])
        return {"accepted": len(payload["events"])}


class SpoolReplayTests(unittest.TestCase):
    def temporary_spool(self) -> tempfile.TemporaryDirectory[str]:
        workspace_data = Path(__file__).resolve().parents[2] / ".data"
        workspace_data.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(dir=workspace_data)

    def test_failed_replay_keeps_file_and_recovery_replays_then_removes_it(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            events = [{"dedup_key": f"event-{i}", "event_type": "net.conn"} for i in range(3)]
            path = spool_events(spool, events)
            api = FakeApi()

            self.assertEqual(replay_spool(api, "session", spool, batch_size=2), 0)
            self.assertTrue(path.exists())

            api.fail = False
            self.assertEqual(replay_spool(api, "session", spool, batch_size=2), 3)
            self.assertEqual(api.sent, events)
            self.assertFalse(path.exists())

    def test_malformed_spool_is_retained_for_manual_recovery(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            path = spool / "unsent-bad.json"
            path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
            self.assertEqual(replay_spool(FakeApi(), "session", spool, batch_size=25), 0)
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
