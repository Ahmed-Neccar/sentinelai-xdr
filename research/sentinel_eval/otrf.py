"""Real attack telemetry: converts OTRF Security-Datasets (Mordor) captures for the rules.

The datasets are public Windows event captures of lab attacks (https://github.com/OTRF/Security-Datasets).
Each zip holds JSON Lines from several channels. Only the Security channel events the SentinelAI
Windows sensor collects are converted, into the form the detection engine consumes (the same event
types and attribute names as ``sensor/windows_security.py``).

Files are only read as data: nothing in them is executed, and nothing is extracted to disk.

What this can and cannot show: the captures contain an attack and the ordinary operating-system
noise of the lab host around it, but they carry no per-event label. So the measurement here is
whether the rule written for the technique fires ("hit"), plus how many other findings the capture
produces (which mixes noise with parts of the attack and is not a false positive rate).
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# Windows event id -> engine event type (mirrors sensor/windows_security.py ENDPOINT_EVENT_TYPES)
ENDPOINT_TYPES = {
    4697: "endpoint.persistence.service_install",
    4698: "endpoint.persistence.scheduled_task",
    4699: "endpoint.persistence.scheduled_task_deleted",
    4702: "endpoint.persistence.scheduled_task_changed",
    4719: "endpoint.security.audit_policy_change",
    1102: "endpoint.security.log_cleared",
    4720: "endpoint.identity.account_created",
    4728: "endpoint.identity.group_member_added",
    4732: "endpoint.identity.group_member_added",
    4756: "endpoint.identity.group_member_added",
}
PROCESS_EVENT_ID = 4688


@dataclass(frozen=True)
class Capture:
    file: str
    technique: str
    expected: tuple[str, ...]  # any of these rules firing counts as a hit
    note: str
    path: str = ""  # folder of the capture in the OTRF repository
    diagnosis: str = ""  # why it missed, written after looking at the capture (post hoc)


# The expected rules were fixed from each capture's documented technique BEFORE running the rules.
# `diagnosis` was written afterwards, for the captures that missed.
CAPTURES = (
    Capture("empire_schtasks_creation_standard_user.zip", "T1053.005 scheduled task creation",
            ("windows_scheduled_task_created",), "task creation by a standard user", "persistence"),
    Capture("empire_psexec_dcerpc_tcp_svcctl.zip", "T1569.002 service execution (PsExec-style)",
            ("windows_service_installed",), "remote service installation", "lateral_movement",
            "Hizmet kurulumu Windows tarafından yalnızca Sistem günlüğünde 7045 olarak yazıldı; Güvenlik günlüğünde 4697 yok (bunun için \"Güvenlik Sistemi Uzantısı\" denetimi açık olmalı). Sensör yalnızca Güvenlik günlüğünü okuduğu için olay kurala hiç ulaşmadı: bu bir toplama boşluğudur, kural hatası değil."),
    Capture("empire_wmic_add_user_backdoor.zip", "T1136.001 local account creation",
            ("windows_account_created",), "account added with wmic", "lateral_movement"),
    Capture("auditpol_system_user_auditpolicy_modification.zip", "T1562.002 audit policy modification",
            ("windows_audit_policy_changed",), "audit policy changed with auditpol", "defense_evasion"),
    Capture("empire_launcher_vbs.zip", "T1059.005 VBScript launcher",
            ("wscript_spawns_powershell", "cscript_spawns_powershell"), "script host starting PowerShell", "execution"),
    Capture("cmd_mshta_vbscript_execute_psh.zip", "T1218.005 mshta executing a script",
            ("mshta_spawns_powershell",), "mshta starting PowerShell", "defense_evasion"),
    Capture("empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip", "T1047 remote WMI execution",
            ("wmi_spawns_powershell", "wmi_spawns_cmd"), "process started by the WMI provider host", "lateral_movement",
            "WmiPrvSE'in powershell.exe başlatması yalnızca Sysmon (olay 1) kaydında var. Bu kaydın Güvenlik günlüğünde WmiPrvSE süreci görünüyor ama PowerShell alt süreci yok; kuralın eşleşecek bir şeyi olmadı: bu bir veri kaynağı boşluğudur (sensör Sysmon okumaz)."),
    Capture("covenant_sharpwmi_create_dcerpc_wmi.zip", "T1047 remote WMI process creation",
            ("wmi_spawns_powershell", "wmi_spawns_cmd"), "process started by the WMI provider host", "lateral_movement",
            "Güvenlik 4688 olayı WmiPrvSE.exe'nin GruntHTTP2.exe'yi (implant) başlattığını gösteriyor. WMI kuralları alt süreç olarak yalnızca powershell.exe ve cmd.exe'yi eşlediği için rastgele bir alt süreç ıskalanıyor: kural burada fazla dar. \"WmiPrvSE'in herhangi bir alt süreci\" kuralı bunu yakalardı; ancak yalnızca bu tek kayda göre ayarlanmış olacağı için eklenmedi. Önce ayrı bir kayıtla doğrulanması ve iyi huylu yönetim araçlarının maliyetinin ölçülmesi gerekir."),
)


def _time(row: dict) -> datetime | None:
    value = row.get("@timestamp")
    if value:
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            pass
    value = row.get("EventTime")
    if value:
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


def convert(row: dict, number: int) -> dict | None:
    """One captured Security event as an engine event, or None when the sensor would not collect it."""
    if row.get("Channel") != "Security":
        return None
    try:
        event_id = int(row.get("EventID"))
    except (TypeError, ValueError):
        return None
    when = _time(row)
    host = row.get("Hostname")
    if when is None or not host:
        return None
    base = {
        "id": f"otrf{number}",
        "event_time": when,
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "host_id": str(host),
        "username": None,
        "severity": "low",
        "entity": str(host),
    }
    if event_id == PROCESS_EVENT_ID:
        child = row.get("NewProcessName")
        parent = row.get("ParentProcessName") or row.get("CreatorProcessName")
        if not child:
            return None
        return {
            **base,
            "event_type": "process.start",
            "attributes": {
                "source_name": "windows.security",
                "process_name": child,
                "parent_process_name": parent,
            },
        }
    if event_id in ENDPOINT_TYPES:
        return {
            **base,
            "event_type": ENDPOINT_TYPES[event_id],
            "attributes": {"source_name": "windows.security"},
        }
    return None


def load_capture(path: Path) -> tuple[list[dict], dict]:
    """Read one zip; return the converted events and simple counts."""
    events: list[dict] = []
    counts = {"lines": 0, "security_events": 0}
    with zipfile.ZipFile(path) as archive:
        members = [name for name in archive.namelist() if name.endswith(".json")]
        for member in members:
            with archive.open(member) as handle:
                for number, line in enumerate(handle, start=1):
                    counts["lines"] += 1
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if row.get("Channel") == "Security":
                        counts["security_events"] += 1
                    event = convert(row, counts["lines"])
                    if event is not None:
                        events.append(event)
    return events, counts
