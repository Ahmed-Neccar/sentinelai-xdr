import hashlib
import hmac
import json

import httpx
import pytest
from app.api.v1.notifications import ChannelInput
from app.notifications import delivery
from app.notifications.delivery import (
    DeliveryError,
    build_message,
    parse_https_url,
    render_request,
    resolve_public_addresses,
    send,
    severity_rank,
    validate_target,
)
from pydantic import ValidationError

MESSAGE = build_message(
    event_type="detection",
    title="Repeated failed sign-ins",
    severity="high",
    rule_id="brute_force",
    detection_id="d-1",
    case_id="c-1",
)
HOOK_URL = "https://hooks.example.com/services/T000/B000/secret-token"


def public_resolver(_host: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",
        "https://user:pass@hooks.example.com/x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/x",
        "https://backend/x",
        "https://hooks.example.com/x#fragment",
        "https://hooks.example.com/has space",
        "ftp://hooks.example.com/x",
    ],
)
def test_destination_url_must_be_https_public_hostname(url: str) -> None:
    with pytest.raises(ValueError):
        parse_https_url(url)


def test_destination_url_parts_are_preserved() -> None:
    assert parse_https_url("https://Hooks.Example.com:8443/a/b?c=d") == (
        "hooks.example.com",
        8443,
        "/a/b?c=d",
    )


@pytest.mark.parametrize(
    "address", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "172.18.0.3", "::1"]
)
def test_resolver_rejects_hosts_that_resolve_to_internal_addresses(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    family = delivery.socket.AF_INET6 if ":" in address else delivery.socket.AF_INET
    monkeypatch.setattr(
        delivery.socket,
        "getaddrinfo",
        lambda *_a, **_k: [
            (delivery.socket.AF_INET, 1, 6, "", ("93.184.216.34", 443)),
            (family, 1, 6, "", (address, 443)),
        ],
    )
    with pytest.raises(DeliveryError, match="non-public"):
        resolve_public_addresses("rebind.example.com", 443)


def test_send_connects_to_checked_address_and_keeps_tls_name() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["host"] = request.headers["host"]
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200)

    send(
        "webhook",
        {"url": HOOK_URL},
        MESSAGE,
        resolver=public_resolver,
        transport=httpx.MockTransport(handler),
    )
    assert seen["url"] == "https://93.184.216.34/services/T000/B000/secret-token"
    assert seen["host"] == "hooks.example.com"
    assert seen["sni"] == "hooks.example.com"
    assert seen["body"]["title"] == "Repeated failed sign-ins"
    assert "summary" not in seen["body"]


def test_send_does_not_follow_redirects_or_leak_the_destination() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://169.254.169.254/"})

    with pytest.raises(DeliveryError) as raised:
        send(
            "slack",
            {"url": HOOK_URL},
            MESSAGE,
            resolver=public_resolver,
            transport=httpx.MockTransport(handler),
        )
    assert len(calls) == 1
    assert str(raised.value) == "Destination answered HTTP 302"
    assert "secret-token" not in str(raised.value)


def test_send_reports_transport_errors_without_the_url() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {HOOK_URL}")

    with pytest.raises(DeliveryError) as raised:
        send(
            "webhook",
            {"url": HOOK_URL},
            MESSAGE,
            resolver=public_resolver,
            transport=httpx.MockTransport(handler),
        )
    assert "secret-token" not in str(raised.value)
    assert "ConnectError" in str(raised.value)


def test_webhook_signature_covers_timestamp_and_body() -> None:
    secret = "a-shared-signing-value-for-tests"  # noqa: S105
    _url, body, headers = render_request(
        "webhook", {"url": HOOK_URL, "signing_secret": secret}, MESSAGE
    )
    expected = hmac.new(
        secret.encode(), f"{headers['X-Sentinel-Timestamp']}.".encode() + body, hashlib.sha256
    ).hexdigest()
    assert headers["X-Sentinel-Signature"] == f"sha256={expected}"


def test_slack_and_telegram_payloads() -> None:
    _url, body, headers = render_request("slack", {"url": HOOK_URL}, MESSAGE)
    text = json.loads(body)["text"]
    assert text.startswith("[HIGH] Repeated failed sign-ins")
    assert "Case: c-1" in text and "not confirmation of compromise" in text
    assert "X-Sentinel-Signature" not in headers

    token = "123456789:" + "A" * 35
    url, body, _headers = render_request(
        "telegram", {"bot_token": token, "chat_id": "-1001234567890"}, MESSAGE
    )
    assert url == f"https://api.telegram.org/bot{token}/sendMessage"
    assert json.loads(body)["chat_id"] == "-1001234567890"


def test_summary_is_only_included_when_requested() -> None:
    with_summary = build_message(
        event_type="detection", title="t", severity="low", summary="10.0.0.5 scanned 40 ports"
    )
    assert with_summary["summary"] == "10.0.0.5 scanned 40 ports"
    assert "summary" not in MESSAGE


def test_severity_ordering() -> None:
    assert severity_rank("critical") > severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low") > severity_rank("informational")
    assert severity_rank("unknown") == 0 and severity_rank(None) == 0


@pytest.mark.parametrize(
    ("kind", "target"),
    [
        ("slack", {"url": HOOK_URL, "signing_secret": "x" * 20}),
        ("webhook", {"url": "http://hooks.example.com/x"}),
        ("webhook", {"url": HOOK_URL, "signing_secret": "short"}),
        ("telegram", {"bot_token": "not-a-token", "chat_id": "1"}),
        ("telegram", {"bot_token": "123456789:" + "A" * 35, "chat_id": "bad chat"}),
        ("telegram", {"url": HOOK_URL}),
    ],
)
def test_invalid_targets_are_rejected(kind: str, target: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        validate_target(kind, target)


def test_channel_input_validates_destination_and_severity() -> None:
    ok = ChannelInput.model_validate(
        {"name": "On-call", "kind": "slack", "target": {"url": HOOK_URL}}
    )
    assert ok.min_severity == "high" and ok.include_summary is False
    with pytest.raises(ValidationError):
        ChannelInput.model_validate(
            {"name": "Bad", "kind": "slack", "target": {"url": "https://10.0.0.1/hook"}}
        )
    with pytest.raises(ValidationError):
        ChannelInput.model_validate(
            {
                "name": "Bad",
                "kind": "slack",
                "target": {"url": HOOK_URL},
                "min_severity": "informational",
            }
        )
