from xml.etree import ElementTree as ET

from sensor import windows_security

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event_xml(event_id: int, record_id: int, fields: dict[str, str] | None = None) -> ET.Element:
    root = ET.Element(f"{{{NS}}}Event")
    system = ET.SubElement(root, f"{{{NS}}}System")
    ET.SubElement(system, f"{{{NS}}}EventID").text = str(event_id)
    ET.SubElement(system, f"{{{NS}}}EventRecordID").text = str(record_id)
    ET.SubElement(system, f"{{{NS}}}Computer").text = "lab-host"
    ET.SubElement(system, f"{{{NS}}}TimeCreated", {"SystemTime": "2026-10-23T10:00:00Z"})
    data = ET.SubElement(root, f"{{{NS}}}EventData")
    for name, value in (fields or {}).items():
        ET.SubElement(data, f"{{{NS}}}Data", {"Name": name}).text = value
    return root


def test_endpoint_event_collection_is_opt_in_and_omits_task_content(monkeypatch) -> None:
    current = [event_xml(4698, 2, {"TaskName": "\\SyntheticTask", "TaskContent": "secret command content", "SubjectUserName": "operator"})]

    def query(xpath: str, **kwargs):
        if xpath == "*[System]":
            return [event_xml(1102, 1)]
        return current

    monkeypatch.setattr(windows_security, "_query", query)
    collector = windows_security.WindowsSecurityLog(collect_endpoint=True)
    result = collector.poll()

    assert len(result) == 1
    assert result[0]["event_type"] == "endpoint.persistence.scheduled_task"
    assert result[0]["task_name"] == "\\SyntheticTask"
    assert "secret command content" not in str(result[0])
    assert result[0]["dedup_key"] == "windows-security:lab-host:2"


def test_endpoint_events_are_not_collected_without_opt_in(monkeypatch) -> None:
    def query(xpath: str, **kwargs):
        if xpath == "*[System]":
            return [event_xml(1102, 1)]
        return [event_xml(1102, 2)]

    monkeypatch.setattr(windows_security, "_query", query)
    collector = windows_security.WindowsSecurityLog()
    assert 1102 not in collector.event_ids
    assert 4720 not in collector.event_ids
    assert collector.poll() == []


def test_account_and_group_change_events_are_curated_and_opt_in(monkeypatch) -> None:
    current = [
        event_xml(
            4732,
            2,
            {
                "SubjectUserName": "operator",
                "TargetUserName": "Administrators",
                "MemberName": "S-1-5-21-1234",
                "MemberSid": "S-1-5-21-1234",
                "SensitiveField": "must not be collected",
            },
        ),
        event_xml(
            4720,
            3,
            {"SubjectUserName": "operator", "TargetUserName": "new-user"},
        ),
    ]

    def query(xpath: str, **kwargs):
        if xpath == "*[System]":
            return [event_xml(1102, 1)]
        return current

    monkeypatch.setattr(windows_security, "_query", query)
    records = windows_security.WindowsSecurityLog(collect_endpoint=True).poll()

    assert records[0]["event_type"] == "endpoint.identity.group_member_added"
    assert records[0]["group_name"] == "Administrators"
    assert records[0]["member_name"] == "S-1-5-21-1234"
    assert "must not be collected" not in str(records)
    assert records[1]["event_type"] == "endpoint.identity.account_created"
