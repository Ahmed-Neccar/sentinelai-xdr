from __future__ import annotations

import csv
import io
import json
from typing import Any

from pydantic import ValidationError

from app.ingestion.normalize import (
    SCHEMA_VERSION,
    first,
    parse_dt,
    parse_ip,
    parse_port,
    parse_severity,
    redact,
)
from app.ingestion.schema import NormalizedEventV1

MAX_FIELD = 8192


class RowError(Exception):
    def __init__(self, row_number: int, message: str) -> None:
        super().__init__(message)
        self.row_number = row_number
        self.message = message


def validate_normalized_event(value: dict[str, Any], row_number: int) -> dict[str, Any]:
    try:
        return NormalizedEventV1.model_validate(value).model_dump(mode="python")
    except ValidationError as exc:
        fields = sorted({".".join(map(str, error["loc"])) for error in exc.errors()})
        summary = ", ".join(fields[:5]) or "event"
        raise RowError(
            row_number, f"Event does not match normalized schema v1: {summary}"
        ) from None


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_FIELD:
        return value[:MAX_FIELD]
    return value


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalize_generic(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    event_time = parse_dt(
        first(raw.get("event_time"), raw.get("timestamp"), raw.get("@timestamp"), raw.get("ts"))
    )
    if event_time is None:
        raise RowError(row_number, "Missing or invalid event timestamp")
    event_type = first(raw.get("event_type"), raw.get("type"), raw.get("category"))
    if not event_type:
        raise RowError(row_number, "Missing event_type")
    src_ip = parse_ip(first(raw.get("src_ip"), raw.get("id.orig_h"), raw.get("src")))
    dst_ip = parse_ip(first(raw.get("dst_ip"), raw.get("id.resp_h"), raw.get("dst")))
    if raw.get("src_ip") and src_ip is None:
        raise RowError(row_number, "Invalid src_ip")
    if raw.get("dst_ip") and dst_ip is None:
        raise RowError(row_number, "Invalid dst_ip")
    return {
        "event_time": event_time,
        "event_type": str(event_type)[:128],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": parse_port(first(raw.get("src_port"), raw.get("id.orig_p"))),
        "dst_port": parse_port(first(raw.get("dst_port"), raw.get("id.resp_p"))),
        "host_id": _clip(first(raw.get("host_id"), raw.get("host"), raw.get("hostname"))),
        "severity": parse_severity(raw.get("severity")),
        "attributes": {
            "username": _clip(raw.get("username")),
            "message": _clip(raw.get("message")),
            "protocol": _clip(first(raw.get("protocol"), raw.get("proto"))),
            "bytes": raw.get("bytes"),
            "outcome": _clip(raw.get("outcome")),
            "source_name": _clip(raw.get("source_name")),
            "windows_event_id": raw.get("windows_event_id"),
            "windows_record_id": raw.get("windows_record_id"),
            "activity": _clip(raw.get("activity")),
            "logon_type": _clip(raw.get("logon_type")),
            "workstation": _clip(raw.get("workstation")),
            "failure_reason": _clip(raw.get("failure_reason")),
            "actor": _clip(raw.get("actor")),
            "action": _clip(raw.get("action")),
            "target_username": _clip(raw.get("target_username")),
            "group_name": _clip(raw.get("group_name")),
            "member_name": _clip(raw.get("member_name")),
            "service": _clip(raw.get("service")),
            "account_id": _clip(raw.get("account_id")),
            "region": _clip(raw.get("region")),
            "error_code": _clip(raw.get("error_code")),
            "user_agent": _clip(raw.get("user_agent")),
            "cloud_resource": _clip(raw.get("cloud_resource")),
            "tenant_id": _clip(raw.get("tenant_id")),
            "resource_id": _clip(raw.get("resource_id")),
            "subscription_id": _clip(raw.get("subscription_id")),
            "category": _clip(raw.get("category")),
            "cloud_status": _clip(raw.get("cloud_status")),
            "correlation_id": _clip(raw.get("correlation_id")),
            "app_name": _clip(raw.get("app_name")),
            "risk_level": _clip(raw.get("risk_level")),
            "device_id": _clip(raw.get("device_id")),
            "service_name": _clip(raw.get("service_name")),
            "service_file_name": _clip(raw.get("service_file_name")),
            "service_account": _clip(raw.get("service_account")),
            "task_name": _clip(raw.get("task_name")),
            "change_summary": _clip(raw.get("change_summary")),
            "process_name": _clip(raw.get("process_name")),
            "parent_process_name": _clip(raw.get("parent_process_name")),
            "process_id": _clip(raw.get("process_id")),
            "parent_process_id": _clip(raw.get("parent_process_id")),
            "adapter": "generic",
        },
        "raw_payload": redact(raw),
        "schema_version": SCHEMA_VERSION,
        "dedup_key": _clip(raw.get("dedup_key")),
    }


def normalize_zeek_conn(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    orig = _dict_or_empty(raw.get("id"))
    event_time = parse_dt(raw.get("ts"))
    if event_time is None:
        raise RowError(row_number, "Zeek conn record missing ts")
    return {
        "event_time": event_time,
        "event_type": "zeek.conn",
        "src_ip": parse_ip(first(orig.get("orig_h"), raw.get("id.orig_h"))),
        "dst_ip": parse_ip(first(orig.get("resp_h"), raw.get("id.resp_h"))),
        "src_port": parse_port(first(orig.get("orig_p"), raw.get("id.orig_p"))),
        "dst_port": parse_port(first(orig.get("resp_p"), raw.get("id.resp_p"))),
        # Zeek uid identifies this connection, not either endpoint host.
        "host_id": None,
        "severity": "informational",
        "attributes": {
            "protocol": raw.get("proto"),
            "service": raw.get("service"),
            "bytes": (raw.get("orig_bytes") or 0) + (raw.get("resp_bytes") or 0),
            "conn_state": raw.get("conn_state"),
            "connection_id": _clip(raw.get("uid")),
            "adapter": "zeek.conn",
        },
        "raw_payload": redact(raw),
        "schema_version": SCHEMA_VERSION,
        "dedup_key": _clip(raw.get("uid")),
    }


def normalize_aws_cloudtrail(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    identity = _dict_or_empty(raw.get("userIdentity"))
    principal = first(identity.get("userName"), identity.get("principalId"), identity.get("arn"))
    event_name = raw.get("eventName")
    event_source = raw.get("eventSource")
    if not event_name or not event_source:
        raise RowError(row_number, "CloudTrail record requires eventName and eventSource")
    event_id = raw.get("eventID")
    curated = {
        key: raw.get(key)
        for key in (
            "eventTime",
            "eventSource",
            "eventName",
            "eventID",
            "awsRegion",
            "sourceIPAddress",
            "userAgent",
            "errorCode",
            "errorMessage",
            "recipientAccountId",
        )
        if raw.get(key) is not None
    }
    curated["userIdentity"] = {
        key: identity.get(key)
        for key in ("type", "principalId", "arn", "accountId", "userName")
        if identity.get(key) is not None
    }
    normalized = normalize_generic(
        {
            "event_time": raw.get("eventTime"),
            "event_type": "cloud.aws.cloudtrail",
            "src_ip": parse_ip(raw.get("sourceIPAddress")),
            "host_id": None,
            "username": principal,
            "source_name": "aws.cloudtrail",
            "action": event_name,
            "service": event_source,
            "actor": principal,
            "account_id": raw.get("recipientAccountId") or identity.get("accountId"),
            "region": raw.get("awsRegion"),
            "outcome": "failure" if raw.get("errorCode") else "success",
            "error_code": raw.get("errorCode"),
            "user_agent": raw.get("userAgent"),
            "dedup_key": f"cloudtrail:{event_id}" if event_id else None,
        },
        row_number,
    )
    normalized["attributes"]["adapter"] = "aws_cloudtrail"
    normalized["raw_payload"] = redact(curated)
    return normalized


def normalize_azure_activity(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    operation = raw.get("operationName")
    if isinstance(operation, dict):
        operation = first(operation.get("value"), operation.get("localizedValue"))
    category = raw.get("category")
    if isinstance(category, dict):
        category = first(category.get("value"), category.get("localizedValue"))
    status = _dict_or_empty(raw.get("status"))
    status = first(status.get("value"), status.get("localizedValue"))
    sub_status = _dict_or_empty(raw.get("subStatus"))
    sub_status = first(sub_status.get("value"), sub_status.get("localizedValue"))
    if not operation:
        raise RowError(row_number, "Azure Activity Log record requires operationName")
    curated = {
        key: raw.get(key)
        for key in (
            "eventTimestamp",
            "caller",
            "callerIpAddress",
            "resourceId",
            "subscriptionId",
            "tenantId",
            "correlationId",
            "eventDataId",
            "level",
        )
        if raw.get(key) is not None
    }
    curated.update(
        {
            "operationName": operation,
            "category": category,
            "status": status,
            "subStatus": sub_status,
        }
    )
    actor = raw.get("caller")
    status_text = str(status or "").strip().lower()
    outcome = (
        "success"
        if status_text in {"succeeded", "success"}
        else "failure"
        if status_text in {"failed", "failure"}
        else "unknown"
    )
    normalized = normalize_generic(
        {
            "event_time": first(raw.get("eventTimestamp"), raw.get("submissionTimestamp")),
            "event_type": "cloud.azure.activity",
            "src_ip": parse_ip(raw.get("callerIpAddress")),
            "host_id": None,
            "username": actor,
            "source_name": "azure.activity",
            "action": operation,
            "actor": actor,
            "subscription_id": raw.get("subscriptionId"),
            "tenant_id": raw.get("tenantId"),
            "category": category,
            "cloud_status": status,
            "correlation_id": raw.get("correlationId"),
            "outcome": outcome,
            "message": sub_status,
            "dedup_key": f"azure-activity:{raw.get('eventDataId')}"
            if raw.get("eventDataId")
            else None,
        },
        row_number,
    )
    normalized["attributes"]["adapter"] = "azure_activity"
    normalized["raw_payload"] = redact(curated)
    return normalized


def normalize_entra_signin(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    status = _dict_or_empty(raw.get("status"))
    device = _dict_or_empty(raw.get("deviceDetail"))
    user = first(raw.get("userPrincipalName"), raw.get("userDisplayName"), raw.get("userId"))
    error_code = status.get("errorCode")
    event_id = raw.get("id")
    curated = {
        key: raw.get(key)
        for key in (
            "createdDateTime",
            "userPrincipalName",
            "userDisplayName",
            "userId",
            "ipAddress",
            "appDisplayName",
            "resourceDisplayName",
            "correlationId",
            "conditionalAccessStatus",
            "riskLevelAggregated",
            "tenantId",
        )
        if raw.get(key) is not None
    }
    curated["status"] = {
        key: status.get(key)
        for key in ("errorCode", "failureReason")
        if status.get(key) is not None
    }
    curated["deviceDetail"] = {
        key: device.get(key)
        for key in ("deviceId", "displayName", "operatingSystem", "browser")
        if device.get(key) is not None
    }
    if error_code is None:
        raise RowError(row_number, "Entra sign-in record requires status.errorCode")
    outcome = "success" if str(error_code) == "0" else "failure"
    normalized = normalize_generic(
        {
            "event_time": raw.get("createdDateTime"),
            "event_type": "auth.success" if outcome == "success" else "auth.failure",
            "src_ip": parse_ip(raw.get("ipAddress")),
            "host_id": device.get("deviceId") or device.get("displayName"),
            "device_id": device.get("deviceId"),
            "username": user,
            "source_name": "microsoft.entra.signin",
            "actor": user,
            "action": raw.get("appDisplayName"),
            "app_name": raw.get("appDisplayName"),
            "cloud_resource": raw.get("resourceDisplayName"),
            "tenant_id": raw.get("tenantId"),
            "correlation_id": raw.get("correlationId"),
            "cloud_status": outcome,
            "error_code": error_code,
            "failure_reason": status.get("failureReason"),
            "risk_level": raw.get("riskLevelAggregated"),
            "user_agent": device.get("browser"),
            "dedup_key": f"entra-signin:{event_id}" if event_id else None,
        },
        row_number,
    )
    normalized["attributes"]["adapter"] = "entra_signin"
    normalized["raw_payload"] = redact(curated)
    return normalized


def normalize_suricata_eve(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    event_time = parse_dt(raw.get("timestamp"))
    if event_time is None:
        raise RowError(row_number, "Suricata EVE record missing timestamp")
    event_type = f"suricata.{raw.get('event_type', 'unknown')}"
    alert = _dict_or_empty(raw.get("alert"))
    severity = "informational"
    if alert.get("severity") == 1:
        severity = "high"
    elif alert.get("severity") == 2:
        severity = "medium"
    elif alert.get("severity") == 3:
        severity = "low"
    return {
        "event_time": event_time,
        "event_type": event_type[:128],
        "src_ip": parse_ip(raw.get("src_ip")),
        "dst_ip": parse_ip(raw.get("dest_ip")),
        "src_port": parse_port(raw.get("src_port")),
        "dst_port": parse_port(raw.get("dest_port")),
        # A top-level EVE `host` value may describe the log source/observer;
        # it is not reliable endpoint identity for cross-source correlation.
        "host_id": None,
        "severity": severity,
        "attributes": {
            "protocol": raw.get("proto"),
            "message": _clip(alert.get("signature")),
            "sid": alert.get("signature_id"),
            "source_host_context": _clip(raw.get("host")),
            "adapter": "suricata.eve",
        },
        "raw_payload": redact(raw),
        "schema_version": SCHEMA_VERSION,
        "dedup_key": None,
    }


ADAPTERS = {
    "generic_json": normalize_generic,
    "generic_csv": normalize_generic,
    "zeek_json": normalize_zeek_conn,
    "suricata_eve": normalize_suricata_eve,
    "aws_cloudtrail": normalize_aws_cloudtrail,
    "azure_activity": normalize_azure_activity,
    "entra_signin": normalize_entra_signin,
}


def load_records(
    content: bytes, filename: str, adapter: str, max_rows: int
) -> list[dict[str, Any]]:
    name = filename.lower()
    text = content.decode("utf-8", errors="replace")
    if adapter == "generic_csv" or name.endswith(".csv"):
        return _load_csv(text, max_rows)
    return _load_json_like(text, max_rows)


def _load_csv(text: str, max_rows: int) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(reader, start=1):
        if index > max_rows:
            raise ValueError(f"Row count exceeds limit of {max_rows}")
        rows.append({k: v for k, v in row.items() if k is not None})
    return rows


def _load_json_like(text: str, max_rows: int) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("[") or stripped.startswith("{"):
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            for wrapper in ("events", "Records", "records", "value", "items"):
                if isinstance(payload.get(wrapper), list):
                    payload = payload[wrapper]
                    break
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            raise ValueError("JSON must be an object, array, or {events: []}")
        if len(payload) > max_rows:
            raise ValueError(f"Row count exceeds limit of {max_rows}")
        return payload
    records: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        if not line.strip():
            continue
        if len(records) >= max_rows:
            raise ValueError(f"Row count exceeds limit of {max_rows}")
        records.append(json.loads(line))
    return records
