"""Read new Windows Security logon events without installing a third-party agent."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
AUTH_EVENT_IDS = (4624, 4625, 4801)
PROCESS_EVENT_ID = 4688
ENDPOINT_EVENT_IDS = (
    4697,
    4698,
    4699,
    4702,
    4719,
    1102,
    4720,
    4722,
    4723,
    4724,
    4725,
    4726,
    4728,
    4729,
    4732,
    4733,
    4738,
    4740,
    4756,
    4757,
)
ENDPOINT_EVENT_TYPES = {
    4697: ("endpoint.persistence.service_install", "medium", "service_install"),
    4698: ("endpoint.persistence.scheduled_task", "medium", "scheduled_task_create"),
    4699: ("endpoint.persistence.scheduled_task_deleted", "low", "scheduled_task_delete"),
    4702: ("endpoint.persistence.scheduled_task_changed", "medium", "scheduled_task_update"),
    4719: ("endpoint.security.audit_policy_change", "high", "audit_policy_change"),
    1102: ("endpoint.security.log_cleared", "high", "security_log_cleared"),
    4720: ("endpoint.identity.account_created", "medium", "account_created"),
    4722: ("endpoint.identity.account_enabled", "low", "account_enabled"),
    4723: ("endpoint.identity.password_change", "medium", "password_change_attempted"),
    4724: ("endpoint.identity.password_reset", "medium", "password_reset"),
    4725: ("endpoint.identity.account_disabled", "low", "account_disabled"),
    4726: ("endpoint.identity.account_deleted", "medium", "account_deleted"),
    4728: ("endpoint.identity.group_member_added", "medium", "group_member_added"),
    4729: ("endpoint.identity.group_member_removed", "low", "group_member_removed"),
    4732: ("endpoint.identity.group_member_added", "medium", "group_member_added"),
    4733: ("endpoint.identity.group_member_removed", "low", "group_member_removed"),
    4738: ("endpoint.identity.account_changed", "low", "account_changed"),
    4740: ("endpoint.identity.account_locked", "low", "account_locked"),
    4756: ("endpoint.identity.group_member_added", "medium", "group_member_added"),
    4757: ("endpoint.identity.group_member_removed", "low", "group_member_removed"),
}


def _events(xml_text: str) -> list[ET.Element]:
    # wevtutil returns one or more adjacent Event XML documents.
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", xml_text).strip()
    if not cleaned:
        return []
    try:
        root = ET.fromstring(f"<Events>{cleaned}</Events>")
    except ET.ParseError as exc:
        raise RuntimeError(f"Could not parse Windows Security log output: {exc}") from exc
    return list(root.findall(f"{EVENT_NS}Event"))


def _query(xpath: str, *, limit: int = 5, reverse: bool = True) -> list[ET.Element]:
    result = subprocess.run(
        [
            "wevtutil.exe",
            "qe",
            "Security",
            f"/q:{xpath}",
            "/f:xml",
            f"/c:{limit}",
            f"/rd:{str(reverse).lower()}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        message = detail[-1] if detail else f"wevtutil exited with {result.returncode}"
        raise RuntimeError(f"Cannot read the Windows Security log: {message}")
    return _events(result.stdout)


def _system_value(event: ET.Element, name: str) -> str | None:
    node = event.find(f"{EVENT_NS}System/{EVENT_NS}{name}")
    return node.text if node is not None else None


def _record_id(event: ET.Element) -> int:
    value = _system_value(event, "EventRecordID")
    return int(value or 0)


class WindowsSecurityLog:
    """Poll selected new Windows Security events; do not replay old log history."""

    def __init__(self, *, collect_processes: bool = False, collect_endpoint: bool = False) -> None:
        self.event_ids = list(AUTH_EVENT_IDS)
        if collect_processes:
            self.event_ids.append(PROCESS_EVENT_ID)
        if collect_endpoint:
            self.event_ids.extend(ENDPOINT_EVENT_IDS)
        newest = _query("*[System]", limit=1)
        self.cursor = max((_record_id(event) for event in newest), default=0)

    def poll(self) -> list[dict]:
        event_filter = " or ".join(f"EventID={event_id}" for event_id in self.event_ids)
        xpath = f"*[System[({event_filter}) and EventRecordID > {self.cursor}]]"
        # Read oldest-first in bounded pages so a burst cannot cause us to skip
        # earlier events when the Security log receives more than one page.
        records = _query(xpath, limit=1000, reverse=False)
        output: list[dict] = []
        for event in sorted(records, key=_record_id):
            record_id = _record_id(event)
            event_id = int(_system_value(event, "EventID") or 0)
            if record_id <= self.cursor or event_id not in self.event_ids:
                continue
            self.cursor = max(self.cursor, record_id)
            system = event.find(f"{EVENT_NS}System")
            created = system.find(f"{EVENT_NS}TimeCreated") if system is not None else None
            time_text = created.attrib.get("SystemTime") if created is not None else None
            if not time_text:
                continue
            event_time = datetime.fromisoformat(time_text.replace("Z", "+00:00"))

            data: dict[str, str] = {}
            event_data = event.find(f"{EVENT_NS}EventData")
            if event_data is not None:
                for item in event_data.findall(f"{EVENT_NS}Data"):
                    key = item.attrib.get("Name")
                    if key and item.text:
                        data[key] = item.text

            source_ip = data.get("IpAddress")
            try:
                source_ip = str(ipaddress.ip_address(source_ip)) if source_ip else None
            except ValueError:
                source_ip = None

            computer = _system_value(event, "Computer") or "Windows host"
            if event_id in ENDPOINT_EVENT_TYPES:
                event_type, severity, activity = ENDPOINT_EVENT_TYPES[event_id]
                allowlisted = {
                    4697: ("ServiceName", "ServiceFileName", "ServiceType", "StartType", "AccountName", "SubjectUserName"),
                    4698: ("TaskName", "SubjectUserName"),
                    4699: ("TaskName", "SubjectUserName"),
                    4702: ("TaskName", "SubjectUserName"),
                    4719: ("SubjectUserName", "SubjectDomainName", "SubcategoryId", "SubcategoryGuid", "AuditPolicyChanges"),
                    1102: ("SubjectUserName", "SubjectDomainName", "SubjectLogonId"),
                    4720: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4722: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4723: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4724: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4725: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4726: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4728: ("SubjectUserName", "MemberName", "TargetUserName"),
                    4729: ("SubjectUserName", "MemberName", "TargetUserName"),
                    4732: ("SubjectUserName", "MemberName", "TargetUserName"),
                    4733: ("SubjectUserName", "MemberName", "TargetUserName"),
                    4738: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4740: ("SubjectUserName", "TargetUserName", "TargetDomainName"),
                    4756: ("SubjectUserName", "MemberName", "TargetUserName"),
                    4757: ("SubjectUserName", "MemberName", "TargetUserName"),
                }[event_id]
                output.append(
                    {
                        "event_time": event_time.astimezone(UTC).isoformat(),
                        "event_type": event_type,
                        "host_id": computer,
                        "severity": severity,
                        "source_name": "windows.security",
                        "windows_event_id": event_id,
                        "windows_record_id": record_id,
                        "activity": activity,
                        "username": data.get("SubjectUserName"),
                        "target_username": data.get("TargetUserName"),
                        "group_name": data.get("TargetUserName")
                        if event_id in (4728, 4729, 4732, 4733, 4756, 4757)
                        else None,
                        "member_name": data.get("MemberName"),
                        "service_name": data.get("ServiceName"),
                        "service_file_name": data.get("ServiceFileName"),
                        "service_account": data.get("AccountName"),
                        "task_name": data.get("TaskName"),
                        "change_summary": " ".join(data[key] for key in allowlisted if data.get(key)),
                        "dedup_key": f"windows-security:{computer}:{record_id}",
                    }
                )
                continue

            if event_id == PROCESS_EVENT_ID:
                output.append(
                    {
                        "event_time": event_time.astimezone(UTC).isoformat(),
                        "event_type": "process.start",
                        "host_id": computer,
                        "severity": "informational",
                        "source_name": "windows.security",
                        "windows_event_id": event_id,
                        "windows_record_id": record_id,
                        "activity": "process_creation",
                        "process_name": data.get("NewProcessName"),
                        "parent_process_name": data.get("CreatorProcessName") or data.get("ParentProcessName"),
                        "process_id": data.get("NewProcessId"),
                        "parent_process_id": data.get("ProcessId"),
                        "dedup_key": f"windows-security:{computer}:{record_id}",
                    }
                )
                continue

            success = event_id in (4624, 4801)
            raw = {
                "event_time": event_time.astimezone(UTC).isoformat(),
                "event_type": "auth.success" if success else "auth.failure",
                "host_id": computer,
                "src_ip": source_ip,
                "username": data.get("TargetUserName"),
                "severity": "informational",
                "outcome": "success" if success else "failure",
                "source_name": "windows.security",
                "windows_event_id": event_id,
                "windows_record_id": record_id,
                "activity": "workstation_unlock" if event_id == 4801 else "logon",
                "logon_type": data.get("LogonType"),
                "workstation": data.get("WorkstationName"),
                "failure_reason": data.get("FailureReason") if not success else None,
                "dedup_key": f"windows-security:{computer}:{record_id}",
            }
            output.append(raw)
        return output
