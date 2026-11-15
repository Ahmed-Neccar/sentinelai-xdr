import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_sensor import capture_prerequisite_problem  # noqa: E402


class LinuxPrerequisiteTests(unittest.TestCase):
    def test_windows_has_its_own_check(self) -> None:
        self.assertIsNone(capture_prerequisite_problem("Windows", which=lambda name: None))

    def test_linux_without_tcpdump_is_refused_with_the_fix(self) -> None:
        message = capture_prerequisite_problem("Linux", which=lambda name: None)
        self.assertIn("tcpdump", message or "")
        self.assertIn("CAP_NET_RAW", message or "")

    def test_linux_with_tcpdump_is_fine(self) -> None:
        self.assertIsNone(capture_prerequisite_problem("Linux", which=lambda name: "/usr/sbin/tcpdump"))


if __name__ == "__main__":
    unittest.main()
