import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import controller  # noqa: E402
from controller import MAX_RESTARTS_PER_HOUR, SensorSupervisor  # noqa: E402


class FakeProcess:
    def __init__(self, returncode=None) -> None:
        self.returncode = returncode

    def poll(self):
        return self.returncode


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_supervisor():
    with mock.patch.object(controller, "get_or_create_sensor_id", return_value="sensor-test"):
        supervisor = SensorSupervisor()
    clock = Clock()
    supervisor.clock = clock
    starts: list[dict] = []

    def fake_start(payload):
        starts.append(dict(payload))
        supervisor.process = FakeProcess(None)
        supervisor.started_at = clock()
        supervisor.exited_at = 0.0
        supervisor.crashed = False
        supervisor.stop_requested = False
        supervisor.next_restart_at = None
        supervisor.restart_state = "watching"
        return {}

    supervisor.start = fake_start  # type: ignore[method-assign]
    supervisor.last_start_payload = {"interface": "eth0", "windows_events": True}
    supervisor.process = FakeProcess(None)
    supervisor.started_at = clock()
    supervisor.restart_state = "watching"
    return supervisor, clock, starts


class WatchdogTests(unittest.TestCase):
    def test_a_crash_is_restarted_with_the_same_settings_after_a_wait(self) -> None:
        supervisor, clock, starts = make_supervisor()
        clock.now += 600  # it ran for ten minutes, then died
        supervisor.process.returncode = 1
        supervisor.watchdog_tick()
        self.assertEqual(supervisor.restart_state, "waiting")
        self.assertEqual(starts, [])
        clock.now += 5
        supervisor.watchdog_tick()
        self.assertEqual(starts, [])  # still inside the wait
        clock.now += 10
        supervisor.watchdog_tick()
        self.assertEqual(starts, [{"interface": "eth0", "windows_events": True}])
        self.assertEqual(supervisor.restart_state, "watching")

    def test_a_clean_exit_or_a_requested_stop_is_not_restarted(self) -> None:
        supervisor, clock, starts = make_supervisor()
        supervisor.process.returncode = 0
        clock.now += 1000
        supervisor.watchdog_tick()
        supervisor.watchdog_tick()
        self.assertEqual(starts, [])
        supervisor, clock, starts = make_supervisor()
        supervisor.stop_requested = True
        supervisor.process.returncode = 1
        clock.now += 1000
        supervisor.watchdog_tick()
        self.assertEqual(starts, [])

    def test_stop_cancels_a_pending_restart(self) -> None:
        supervisor, clock, starts = make_supervisor()
        clock.now += 600
        supervisor.process.returncode = 1
        supervisor.watchdog_tick()
        supervisor.process = None
        supervisor.stop()
        clock.now += 1000
        supervisor.watchdog_tick()
        self.assertEqual(starts, [])
        self.assertEqual(supervisor.restart_state, "off")

    def test_an_immediate_crash_waits_at_least_a_minute(self) -> None:
        supervisor, clock, starts = make_supervisor()
        clock.now += 3  # died almost at once: probably a settings problem
        supervisor.process.returncode = 1
        supervisor.watchdog_tick()
        clock.now += 30
        supervisor.watchdog_tick()
        self.assertEqual(starts, [])
        clock.now += 40
        supervisor.watchdog_tick()
        self.assertEqual(len(starts), 1)

    def test_it_gives_up_after_too_many_restarts_in_an_hour(self) -> None:
        supervisor, clock, starts = make_supervisor()
        for _ in range(MAX_RESTARTS_PER_HOUR):
            clock.now += 700
            supervisor.process.returncode = 1
            supervisor.watchdog_tick()  # schedules
            clock.now += 400
            supervisor.watchdog_tick()  # restarts
            # shorten the real time so all restarts fall inside one hour
            supervisor.restart_times = [clock.now - 10 for _ in supervisor.restart_times]
        self.assertEqual(len(starts), MAX_RESTARTS_PER_HOUR)
        supervisor.process.returncode = 1
        clock.now += 700
        supervisor.watchdog_tick()
        self.assertEqual(supervisor.restart_state, "gave_up")
        self.assertIn("not restarted again", supervisor.last_error or "")
        clock.now += 1000
        supervisor.watchdog_tick()
        self.assertEqual(len(starts), MAX_RESTARTS_PER_HOUR)

    def test_a_revoked_sensor_is_never_restarted(self) -> None:
        supervisor, clock, starts = make_supervisor()
        clock.now += 600
        supervisor.process.returncode = 1
        with mock.patch.object(controller.Path, "read_text", return_value="Sensor access was revoked; stopping capture: x\n".replace("Sensor access", "Sensor access")):
            supervisor.watchdog_tick()
        clock.now += 1000
        supervisor.watchdog_tick()
        self.assertEqual(starts, [])
        self.assertEqual(supervisor.restart_state, "revoked")

    def test_a_failed_restart_keeps_watching_and_reports_why(self) -> None:
        supervisor, clock, starts = make_supervisor()
        supervisor.start = mock.Mock(side_effect=RuntimeError("A sensor session from this computer is already online."))  # type: ignore[method-assign]
        clock.now += 600
        supervisor.process.returncode = 1
        supervisor.watchdog_tick()
        clock.now += 20
        supervisor.watchdog_tick()
        self.assertIn("Automatic restart failed", supervisor.last_error or "")
        self.assertEqual(supervisor.restart_state, "waiting")


if __name__ == "__main__":
    unittest.main()
