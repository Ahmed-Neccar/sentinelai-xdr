"""Bounded, read-only polling for supported cloud activity APIs."""

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import boto3
import httpx

PAGE_LIMIT = 10
HTTP_TIMEOUT = httpx.Timeout(20.0, connect=5.0)


class CloudPollError(RuntimeError):
    """A provider request failed; messages intentionally exclude response bodies."""


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _request(client: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    for attempt in range(3):
        try:
            response = client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            if attempt == 2:
                raise CloudPollError("Provider network request failed") from exc
            continue
        if response.status_code == 429 or 500 <= response.status_code <= 599:
            if attempt == 2:
                raise CloudPollError(
                    f"Provider temporarily unavailable (HTTP {response.status_code})"
                )
            retry_after = response.headers.get("Retry-After", "")
            delay = min(max(int(retry_after), 0), 5) if retry_after.isdigit() else 2**attempt
            import time

            time.sleep(delay)
            continue
        if not response.is_success:
            raise CloudPollError(f"Provider rejected the request (HTTP {response.status_code})")
        return response
    raise CloudPollError("Provider request retries exhausted")


def _oauth_token(
    client: httpx.Client, tenant_id: str, client_id: str, client_secret: str, scope: str
) -> str:
    if not tenant_id or not client_id or not client_secret:
        raise CloudPollError("Cloud connector credentials are incomplete")
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    response = _request(
        client,
        "POST",
        url,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": scope,
        },
        headers={"Accept": "application/json"},
    )
    token = response.json().get("access_token")
    if not isinstance(token, str) or not token:
        raise CloudPollError("Provider authentication returned no access token")
    return token


def _follow_pages(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    params: dict[str, str] | None,
    allowed_host: str,
) -> tuple[list[dict[str, Any]], bool]:
    events: list[dict[str, Any]] = []
    more = False
    for page in range(PAGE_LIMIT):
        parsed_url = urlparse(url)
        if (
            parsed_url.scheme != "https"
            or parsed_url.hostname != allowed_host
            or parsed_url.username is not None
            or parsed_url.port not in (None, 443)
        ):
            raise CloudPollError("Provider returned an unexpected pagination host")
        response = _request(client, "GET", url, headers=headers, params=params)
        params = None
        body = response.json()
        items = body.get("value", [])
        if not isinstance(items, list):
            raise CloudPollError("Provider returned an invalid event page")
        events.extend(item for item in items if isinstance(item, dict))
        next_url = body.get("@odata.nextLink") or body.get("nextLink")
        if not next_url:
            break
        url = str(next_url)
        if page == PAGE_LIMIT - 1:
            more = True
    return events, more


def poll_cloud_events(
    provider: str,
    config: dict[str, Any],
    credentials: dict[str, str],
    since: datetime,
    now: datetime,
) -> tuple[list[dict[str, Any]], datetime, bool]:
    """Return provider events, a safe timestamp checkpoint, and truncation state."""
    if provider == "aws_cloudtrail":
        from botocore.config import Config as BotoConfig

        if not credentials.get("access_key_id") or not credentials.get("secret_access_key"):
            raise CloudPollError("AWS connector credentials are incomplete")
        session = boto3.Session(
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            aws_session_token=credentials.get("session_token") or None,
            region_name=config.get("region", "us-east-1"),
        )
        client = session.client(
            "cloudtrail",
            config=BotoConfig(
                retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=20
            ),
        )
        events: list[dict[str, Any]] = []
        token = None
        truncated = False
        for page in range(PAGE_LIMIT):
            result = client.lookup_events(
                StartTime=since,
                EndTime=now,
                MaxResults=50,
                **({"NextToken": token} if token else {}),
            )
            for item in result.get("Events", []):
                try:
                    raw = item.get("CloudTrailEvent")
                    event = __import__("json").loads(raw) if isinstance(raw, str) else None
                except (ValueError, TypeError):
                    event = None
                if isinstance(event, dict):
                    events.append(event)
            token = result.get("NextToken")
            if not token:
                break
            if page == PAGE_LIMIT - 1:
                truncated = True
        return events, _safe_checkpoint(events, "eventTime", now, truncated), truncated

    if provider not in {"azure_activity", "entra_signin"}:
        raise CloudPollError("Unsupported cloud provider")
    tenant_id = str(config.get("tenant_id", ""))
    client_id = str(config.get("client_id", ""))
    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False) as client:
        if provider == "azure_activity":
            subscription_id = str(config.get("subscription_id", ""))
            token = _oauth_token(
                client,
                tenant_id,
                client_id,
                credentials.get("client_secret", ""),
                "https://management.azure.com/.default",
            )
            url = (
                "https://management.azure.com/subscriptions/"
                f"{subscription_id}/providers/Microsoft.Insights/eventtypes/management/values"
            )
            params = {
                "api-version": "2015-04-01",
                "$filter": f"eventTimestamp ge '{_iso(since)}' and eventTimestamp le '{_iso(now)}'",
            }
            events, truncated = _follow_pages(
                client, url, {"Authorization": f"Bearer {token}"}, params, "management.azure.com"
            )
            return events, _safe_checkpoint(events, "eventTimestamp", now, truncated), truncated

        token = _oauth_token(
            client,
            tenant_id,
            client_id,
            credentials.get("client_secret", ""),
            "https://graph.microsoft.com/.default",
        )
        url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        params = {"$top": "100", "$filter": f"createdDateTime ge {_iso(since)}"}
        events, truncated = _follow_pages(
            client, url, {"Authorization": f"Bearer {token}"}, params, "graph.microsoft.com"
        )
        return events, _safe_checkpoint(events, "createdDateTime", now, truncated), truncated


def _safe_checkpoint(
    events: list[dict[str, Any]], timestamp_key: str, now: datetime, truncated: bool
) -> datetime:
    if not truncated:
        return now
    timestamps: list[datetime] = []
    for event in events:
        value = event.get(timestamp_key)
        if isinstance(value, datetime):
            timestamps.append(value.astimezone(UTC))
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None:
                timestamps.append(parsed.astimezone(UTC))
    if not timestamps:
        return now - timedelta(minutes=1)
    return max(min(timestamps) - timedelta(minutes=1), datetime(1970, 1, 1, tzinfo=UTC))
