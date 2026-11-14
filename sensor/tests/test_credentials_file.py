import json
import sys
from pathlib import Path

import pytest

# live_sensor imports its sibling modules by bare name, as it does when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_sensor import credentials_from_file  # noqa: E402


def test_reads_the_file_the_panel_downloads(tmp_path) -> None:
    path = tmp_path / "sensor-credentials.json"
    path.write_text(
        json.dumps({"email": " sensor-lab-1a2b3c@sensors.local ", "password": "p" * 43, "name": "Lab"}),
        encoding="utf-8",
    )
    assert credentials_from_file(path) == ("sensor-lab-1a2b3c@sensors.local", "p" * 43)
    # Windows editors often save with a byte-order mark.
    path.write_text(json.dumps({"email": "a@b", "password": "x"}), encoding="utf-8-sig")
    assert credentials_from_file(path) == ("a@b", "x")


@pytest.mark.parametrize(
    "content",
    ["", "not json", "[]", '{"email": "a@b"}', '{"email": "nope", "password": "x"}', '{"email": "a@b", "password": ""}'],
)
def test_bad_files_are_rejected_without_echoing_their_content(tmp_path, content: str) -> None:
    path = tmp_path / "sensor-credentials.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(RuntimeError) as error:
        credentials_from_file(path)
    assert "sensor-credentials.json" in str(error.value)
    assert content == "" or content not in str(error.value)


def test_missing_file_is_reported(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="cannot read"):
        credentials_from_file(tmp_path / "absent.json")


def test_restricting_permissions_never_blocks_reading(tmp_path, monkeypatch) -> None:
    import live_sensor

    calls: list[list[str]] = []

    def failing_run(cmd, **kwargs):
        calls.append(cmd)
        raise OSError("icacls missing")

    monkeypatch.setattr(live_sensor.platform, "system", lambda: "Windows")
    monkeypatch.setenv("USERNAME", "alice")
    monkeypatch.setenv("USERDOMAIN", "PC")
    monkeypatch.setattr(live_sensor.subprocess, "run", failing_run)
    path = tmp_path / "sensor-credentials.json"
    path.write_text(json.dumps({"email": "a@b", "password": "x"}), encoding="utf-8")
    assert credentials_from_file(path) == ("a@b", "x")
    assert calls and calls[0][0] == "icacls" and "/inheritance:r" in calls[0] and "PC\\alice:(F)" in calls[0]


def test_restriction_is_skipped_off_windows(tmp_path, monkeypatch) -> None:
    import live_sensor

    monkeypatch.setattr(live_sensor.platform, "system", lambda: "Linux")
    assert live_sensor.restrict_credentials_file(tmp_path / "x") is False
