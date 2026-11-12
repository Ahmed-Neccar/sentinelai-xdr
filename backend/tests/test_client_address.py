import pytest
from app.core import client_address
from app.core.config import settings


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    monkeypatch.setattr(client_address, "_cache", None)
    yield
    monkeypatch.setattr(client_address, "_cache", None)


def test_header_is_ignored_when_no_proxy_is_trusted(monkeypatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxies", "")
    assert client_address.resolve_client_ip("172.19.0.1", "203.0.113.9") == "172.19.0.1"


def test_header_is_ignored_from_a_peer_that_is_not_a_trusted_proxy(monkeypatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxies", "172.19.0.5")
    assert client_address.resolve_client_ip("172.19.0.1", "203.0.113.9") == "172.19.0.1"


def test_rightmost_untrusted_address_wins_over_client_supplied_values(monkeypatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxies", "172.19.0.5, 172.19.0.6")
    # The client sent "1.2.3.4"; the first proxy appended the address it saw.
    chain = "1.2.3.4, 198.51.100.7, 172.19.0.6"
    assert client_address.resolve_client_ip("172.19.0.5", chain) == "198.51.100.7"


def test_all_trusted_or_malformed_chain_falls_back_to_the_peer(monkeypatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxies", "172.19.0.0/24")
    assert client_address.resolve_client_ip("172.19.0.5", "172.19.0.6") == "172.19.0.5"
    assert client_address.resolve_client_ip("172.19.0.5", "not-an-ip") == "172.19.0.5"
    assert client_address.resolve_client_ip("172.19.0.5", "198.51.100.7, junk") == "172.19.0.5"
    assert client_address.resolve_client_ip(None, "198.51.100.7") is None


def test_ipv6_and_cidr_entries(monkeypatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxies", "fd00::/8,10.0.0.0/8")
    assert client_address.resolve_client_ip("fd00::5", "2001:db8::1") == "2001:db8::1"
    assert client_address.resolve_client_ip("10.1.2.3", "2001:db8::1, 10.9.9.9") == "2001:db8::1"


def test_host_names_are_resolved_and_unknown_names_are_skipped(monkeypatch) -> None:
    def fake_getaddrinfo(name, *_args, **_kwargs):
        if name == "frontend":
            return [(None, None, None, "", ("172.19.0.5", 0))]
        raise OSError("unknown host")

    monkeypatch.setattr(client_address.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(settings, "trusted_proxies", "frontend,tls-proxy")
    assert client_address.resolve_client_ip("172.19.0.5", "198.51.100.7") == "198.51.100.7"
    assert client_address.resolve_client_ip("172.19.0.9", "198.51.100.7") == "172.19.0.9"
