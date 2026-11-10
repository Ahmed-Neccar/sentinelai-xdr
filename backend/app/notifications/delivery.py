"""Send one alert message to an operator-configured destination.

Destinations are untrusted input. Requests are HTTPS only, never follow
redirects, and connect to an address that was resolved and checked to be
publicly routable, so a channel cannot be pointed at loopback, the Compose
network, or cloud metadata endpoints. Error messages never contain the
destination URL because webhook URLs and bot tokens are secrets.
"""

import hashlib
import hmac
import ipaddress
import json
import re
import socket
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

KINDS = ("webhook", "slack", "telegram")
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
HTTP_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
_TELEGRAM_TOKEN = re.compile(r"^\d{5,16}:[A-Za-z0-9_-]{30,64}$")
_TELEGRAM_CHAT = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

Resolver = Callable[[str, int], list[str]]


class DeliveryError(RuntimeError):
    """A send failed; the message is safe to store and show to administrators."""


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK.get((value or "").lower(), 0)


def parse_https_url(url: str) -> tuple[str, int, str]:
    """Return (host, port, path-with-query) for an acceptable destination URL."""
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) < 33 for char in url):
        raise ValueError("Destination URL is invalid")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("Destination URL must use https")
    if parts.username or parts.password or parts.fragment:
        raise ValueError("Destination URL must not contain credentials or a fragment")
    host = (parts.hostname or "").lower()
    if not _HOSTNAME.fullmatch(host):
        raise ValueError("Destination must be a public DNS host name, not an IP address")
    try:
        port = parts.port or 443
    except ValueError:
        raise ValueError("Destination URL port is invalid") from None
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return host, port, path


def validate_target(kind: str, target: dict[str, str]) -> dict[str, str]:
    """Validate the secret destination fields for a channel kind."""
    if kind == "telegram":
        if set(target) != {"bot_token", "chat_id"}:
            raise ValueError("Telegram channels need bot_token and chat_id")
        if not _TELEGRAM_TOKEN.fullmatch(target["bot_token"]):
            raise ValueError("Telegram bot token format is invalid")
        if not _TELEGRAM_CHAT.fullmatch(target["chat_id"]):
            raise ValueError("Telegram chat ID format is invalid")
        return dict(target)
    allowed = {"url", "signing_secret"} if kind == "webhook" else {"url"}
    if kind not in KINDS or "url" not in target or not set(target) <= allowed:
        raise ValueError("Destination fields do not match the channel type")
    parse_https_url(target["url"])
    secret = target.get("signing_secret")
    if secret is not None and not 16 <= len(secret) <= 256:
        raise ValueError("Signing secret must be 16 to 256 characters")
    return dict(target)


def resolve_public_addresses(host: str, port: int) -> list[str]:
    """Resolve a host and refuse it unless every address is publicly routable."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise DeliveryError("Destination host could not be resolved") from None
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise DeliveryError("Destination host could not be resolved")
    for address in addresses:
        if not ipaddress.ip_address(address.split("%", 1)[0]).is_global:
            raise DeliveryError("Destination resolves to a non-public address")
    return addresses


def build_message(
    *,
    event_type: str,
    title: str,
    severity: str,
    rule_id: str | None = None,
    detector_kind: str | None = None,
    detection_id: str | None = None,
    case_id: str | None = None,
    created_at: str | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "source": "sentinelai-xdr",
        "type": event_type,
        "severity": severity,
        "title": title[:400],
        "rule_id": rule_id,
        "detector_kind": detector_kind,
        "detection_id": detection_id,
        "case_id": case_id,
        "created_at": created_at,
        "note": "Review signal for an analyst; not confirmation of compromise.",
    }
    if summary:
        message["summary"] = summary[:1000]
    return message


def _text(message: dict[str, Any]) -> str:
    lines = [f"[{str(message['severity']).upper()}] {message['title']}"]
    if message.get("summary"):
        lines.append(str(message["summary"]))
    for label, key in (("Rule", "rule_id"), ("Detection", "detection_id"), ("Case", "case_id")):
        if message.get(key):
            lines.append(f"{label}: {message[key]}")
    lines.append(str(message["note"]))
    return "\n".join(lines)


def render_request(
    kind: str, target: dict[str, str], message: dict[str, Any]
) -> tuple[str, bytes, dict[str, str]]:
    """Return (url, body, extra headers) for a channel kind."""
    headers = {"Content-Type": "application/json", "User-Agent": "SentinelAI-XDR-Notifier"}
    if kind == "telegram":
        url = f"https://api.telegram.org/bot{target['bot_token']}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": target["chat_id"],
            "text": _text(message),
            "disable_web_page_preview": True,
        }
    elif kind == "slack":
        url = target["url"]
        payload = {"text": _text(message)}
    elif kind == "webhook":
        url = target["url"]
        payload = message
    else:
        raise DeliveryError("Unsupported channel type")
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    secret = target.get("signing_secret") if kind == "webhook" else None
    if secret:
        timestamp = str(int(time.time()))
        digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
        headers["X-Sentinel-Timestamp"] = timestamp
        headers["X-Sentinel-Signature"] = f"sha256={digest.hexdigest()}"
    return url, body, headers


def send(
    kind: str,
    target: dict[str, str],
    message: dict[str, Any],
    *,
    resolver: Resolver = resolve_public_addresses,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Deliver one message or raise DeliveryError with a secret-free reason."""
    url, body, headers = render_request(kind, target, message)
    try:
        host, port, path = parse_https_url(url)
    except ValueError as exc:
        raise DeliveryError(str(exc)) from None
    address = resolver(host, port)[0]
    literal = f"[{address}]" if ":" in address else address
    headers["Host"] = host if port == 443 else f"{host}:{port}"
    try:
        # Connect to the checked address; TLS still verifies the certificate for `host`.
        with httpx.Client(
            timeout=HTTP_TIMEOUT, follow_redirects=False, trust_env=False, transport=transport
        ) as client:
            with client.stream(
                "POST",
                f"https://{literal}:{port}{path}",
                content=body,
                headers=headers,
                extensions={"sni_hostname": host},
            ) as response:
                status = response.status_code
    except httpx.TimeoutException:
        raise DeliveryError("Destination timed out") from None
    except httpx.HTTPError as exc:
        raise DeliveryError(f"Destination request failed ({type(exc).__name__})") from None
    if not 200 <= status < 300:
        raise DeliveryError(f"Destination answered HTTP {status}")
