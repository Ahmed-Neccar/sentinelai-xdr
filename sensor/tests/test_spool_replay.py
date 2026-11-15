import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import live_sensor  # noqa: E402
from live_sensor import Backoff, replay_spool, spool_events  # noqa: E402


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

    def test_malformed_spool_is_set_aside_and_does_not_block_the_next_batch(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            bad = spool / "unsent-0000-bad.json"
            bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
            good = spool / "unsent-9999-good.json"
            events = [{"dedup_key": "ok", "event_type": "net.conn"}]
            good.write_text(json.dumps(events), encoding="utf-8")
            api = FakeApi()
            api.fail = False
            self.assertEqual(replay_spool(api, "session", spool, batch_size=25), 1)
            self.assertEqual(api.sent, events)
            self.assertFalse(bad.exists())
            self.assertTrue((spool / "bad-unsent-0000-bad.json").exists())  # kept for inspection
            self.assertFalse(good.exists())

    def test_unparseable_json_is_set_aside_too(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            (spool / "unsent-broken.json").write_text('{"half": ', encoding="utf-8")
            api = FakeApi()
            api.fail = False
            self.assertEqual(replay_spool(api, "session", spool, batch_size=25), 0)
            self.assertTrue((spool / "bad-unsent-broken.json").exists())

    def test_a_batch_is_written_atomically(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            path = spool_events(spool, [{"dedup_key": "a"}])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), [{"dedup_key": "a"}])
            self.assertEqual(list(spool.glob(".tmp-*")), [])
            # A crash while writing leaves only a temporary file; it is never replayed as a batch.
            (spool / ".tmp-crashed").write_text("[{", encoding="utf-8")
            api = FakeApi()
            api.fail = False
            self.assertEqual(replay_spool(api, "session", spool, batch_size=25), 1)

    def test_the_queue_is_bounded_and_drops_the_oldest_first(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            original = live_sensor.SPOOL_MAX_FILES
            live_sensor.SPOOL_MAX_FILES = 3
            try:
                for index in range(5):
                    spool_events(spool, [{"dedup_key": f"batch-{index}"}])
            finally:
                live_sensor.SPOOL_MAX_FILES = original
            kept = sorted(spool.glob("unsent-*.json"))
            self.assertEqual(len(kept), 3)
            keys = [json.loads(path.read_text(encoding="utf-8"))[0]["dedup_key"] for path in kept]
            self.assertEqual(keys, ["batch-2", "batch-3", "batch-4"])

    def test_the_queue_is_bounded_by_size_too(self) -> None:
        with self.temporary_spool() as directory:
            spool = Path(directory)
            original = live_sensor.SPOOL_MAX_BYTES
            live_sensor.SPOOL_MAX_BYTES = 1500
            try:
                for index in range(10):
                    spool_events(spool, [{"dedup_key": f"{index}", "pad": "x" * 300}])
            finally:
                live_sensor.SPOOL_MAX_BYTES = original
            total = sum(path.stat().st_size for path in spool.glob("unsent-*.json"))
            self.assertLessEqual(total, 1500)
            self.assertGreaterEqual(len(list(spool.glob("unsent-*.json"))), 1)


class BackoffTests(unittest.TestCase):
    def test_the_wait_grows_and_is_capped(self) -> None:
        backoff = Backoff(base=10, cap=80, jitter=0)
        self.assertEqual([backoff.failure() for _ in range(6)], [10, 20, 40, 80, 80, 80])

    def test_success_resets_the_wait(self) -> None:
        backoff = Backoff(base=10, cap=80, jitter=0)
        backoff.failure()
        backoff.failure()
        backoff.success()
        self.assertEqual(backoff.failure(), 10)

    def test_jitter_spreads_the_waits_inside_its_bounds(self) -> None:
        waits = []
        for _ in range(200):
            backoff = Backoff(base=10, cap=300, jitter=0.2)
            waits.append(backoff.failure())
        self.assertTrue(all(8.0 <= wait <= 12.0 for wait in waits))
        self.assertGreater(len(set(round(wait, 3) for wait in waits)), 50)


if __name__ == "__main__":
    unittest.main()
