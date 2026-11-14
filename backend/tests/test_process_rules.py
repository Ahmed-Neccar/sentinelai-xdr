from datetime import UTC, datetime

import pytest
from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.engine import evaluate_rule

SPECS = {item["rule_id"]: item for item in BUILTIN_RULES}
WHEN = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def _process(child: str, parent: str, source: str = "windows.security") -> dict:
    return {
        "id": "p-1",
        "event_time": WHEN,
        "event_type": "process.start",
        "host_id": "pc-1",
        "attributes": {
            "source_name": source,
            "process_name": child,
            "parent_process_name": parent,
        },
    }


def _hits(rule_id: str, event: dict) -> int:
    return len(evaluate_rule(SPECS[rule_id], [event]))


@pytest.mark.parametrize(
    ("rule_id", "child", "parent"),
    [
        (
            "wmi_spawns_powershell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
        ),
        (
            "wmi_spawns_cmd",
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
        ),
        (
            "wscript_spawns_powershell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\wscript.exe",
        ),
        (
            "cscript_spawns_powershell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\cscript.exe",
        ),
        (
            "mshta_spawns_powershell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\mshta.exe",
        ),
    ],
)
def test_parent_child_rules_match_their_pair_only(rule_id: str, child: str, parent: str) -> None:
    assert _hits(rule_id, _process(child, parent)) == 1
    assert _hits(rule_id, _process(child, r"C:\Windows\explorer.exe")) == 0
    assert _hits(rule_id, _process(r"C:\Windows\notepad.exe", parent)) == 0
    assert _hits(rule_id, _process(child, parent, source="other.source")) == 0


@pytest.mark.parametrize(
    ("rule_id", "path", "other"),
    [
        (
            "process_from_temp_folder",
            r"C:\Users\Ann\AppData\Local\Temp\setup.exe",
            r"C:\Program Files\App\app.exe",
        ),
        (
            "process_from_downloads_folder",
            r"C:\Users\Ann\Downloads\tool.exe",
            r"C:\Windows\System32\cmd.exe",
        ),
        ("process_from_public_folder", r"C:\Users\Public\run.exe", r"C:\Users\Ann\Documents\x.exe"),
    ],
)
def test_user_writable_folder_rules(rule_id: str, path: str, other: str) -> None:
    assert _hits(rule_id, _process(path, r"C:\Windows\explorer.exe")) == 1
    assert (
        _hits(rule_id, _process(path.upper(), r"C:\Windows\explorer.exe")) == 1
    )  # case-insensitive
    assert _hits(rule_id, _process(other, r"C:\Windows\explorer.exe")) == 0


def test_the_new_rules_are_well_formed() -> None:
    assert len(SPECS) == len(BUILTIN_RULES)  # unique ids
    for rule_id in (
        "wmi_spawns_powershell",
        "wmi_spawns_cmd",
        "wscript_spawns_powershell",
        "cscript_spawns_powershell",
        "mshta_spawns_powershell",
        "process_from_temp_folder",
        "process_from_downloads_folder",
        "process_from_public_folder",
    ):
        spec = SPECS[rule_id]
        assert spec["severity"] in {"low", "medium", "high"} and spec["mitre"]
        assert "evidence" in spec["description"].lower() or "review" in spec["description"].lower()
