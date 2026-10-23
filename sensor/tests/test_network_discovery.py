import threading
from types import SimpleNamespace

import pytest

from sensor import network_discovery


def test_scan_request_requires_explicit_authorization() -> None:
    with pytest.raises(ValueError, match="authorized"):
        network_discovery.validate_scan_request("192.168.1.0/24", [80], False)


@pytest.mark.parametrize("target", ["8.8.8.0/24", "127.0.0.1/32", "169.254.1.0/24", "192.168.0.0/16"])
def test_scan_request_rejects_unsafe_or_oversized_targets(target: str) -> None:
    with pytest.raises(ValueError):
        network_discovery.validate_scan_request(target, [80], True)


def test_scan_request_allows_small_private_target_and_approved_ports() -> None:
    network, ports = network_discovery.validate_scan_request("192.168.1.0/24", [80, 443], True)
    assert str(network) == "192.168.1.0/24"
    assert ports == [80, 443]


def test_scan_request_rejects_arbitrary_ports() -> None:
    with pytest.raises(ValueError, match="approved"):
        network_discovery.validate_scan_request("192.168.1.0/24", [4444], True)


@pytest.mark.parametrize("target", ["2001:4860:4860::/120", "fe80::/120"])
def test_scan_request_rejects_public_and_link_local_ipv6(target: str) -> None:
    with pytest.raises(ValueError):
        network_discovery.validate_scan_request(target, [443], True)


def test_scan_request_accepts_bounded_private_ipv6() -> None:
    network, _ = network_discovery.validate_scan_request("fd00::/120", [443], True)
    assert network.version == 6


def test_scan_host_reports_only_successful_tcp_connect(monkeypatch) -> None:
    class FakeSocket:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect_ex(self, address):
            self.port = address[1]
            return 0 if self.port == 22 else 10061

        def recv(self, _length):
            return b"SSH-2.0-OpenSSH_9.3\r\n"

    monkeypatch.setattr(network_discovery.socket, "socket", FakeSocket)
    result = network_discovery._scan_host("192.168.1.10", [22, 53], threading.Event())
    assert result == {
        "address": "192.168.1.10",
        "state": "up",
        "ports": [
            {"port": 22, "state": "open", "service": "SSH", "port_hint": "SSH", "identified": True, "product": "SSH-2.0-OpenSSH_9.3"},
            {"port": 53, "state": "closed", "service": "Unknown", "port_hint": "DNS", "identified": False, "product": None},
        ],
    }


def test_http_service_is_identified_from_protocol_response() -> None:
    class FakeHttpSocket:
        def settimeout(self, _timeout):
            pass

        def sendall(self, _request):
            pass

        def recv(self, _length):
            return b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n"

    assert network_discovery._probe_http(FakeHttpSocket(), "192.168.1.10", secure=False) == ("HTTP", "nginx/1.25")


def test_scan_reports_hosts_with_open_approved_services(monkeypatch) -> None:
    def fake_scan_host(address: str, ports: list[int], cancel: threading.Event):
        return {"address": address, "state": "up", "ports": [{"port": 80, "state": "open", "service": "HTTP", "port_hint": "Web (HTTP)", "identified": True, "product": "nginx"}]} if address.endswith(".1") else {}

    monkeypatch.setattr(network_discovery, "_scan_host", fake_scan_host)
    monkeypatch.setattr(network_discovery, "_discover_arp_hosts", lambda _network, _cancel: set())
    progress: list[tuple[int, list[dict]]] = []
    result = network_discovery.scan_network("192.168.1.0/30", [80], threading.Event(), lambda count, rows: progress.append((count, rows)))

    assert result == [{"address": "192.168.1.1", "state": "up", "ports": [{"port": 80, "state": "open", "service": "HTTP", "port_hint": "Web (HTTP)", "identified": True, "product": "nginx"}], "discovered_by": ["TCP"]}]
    assert progress


def test_scan_includes_arp_discovered_hosts_with_filtered_selected_ports(monkeypatch) -> None:
    def fake_scan_host(address: str, ports: list[int], cancel: threading.Event):
        return {
            "address": address,
            "state": "unknown",
            "ports": [{"port": 80, "state": "filtered", "service": "Unknown", "port_hint": "Web (HTTP)", "identified": False, "product": None}],
        }

    monkeypatch.setattr(network_discovery, "_scan_host", fake_scan_host)
    monkeypatch.setattr(network_discovery, "_discover_arp_hosts", lambda _network, _cancel: {"192.168.1.2"})

    result = network_discovery.scan_network("192.168.1.0/30", [80], threading.Event(), lambda _count, _rows: None)

    assert len(result) == 1
    assert result[0]["address"] == "192.168.1.2"
    assert result[0]["state"] == "up"
    assert result[0]["discovered_by"] == ["ARP"]
    assert result[0]["ports"][0]["state"] == "filtered"


def test_arp_discovery_parses_response_before_network_membership(monkeypatch) -> None:
    import scapy.all as scapy_all

    monkeypatch.setattr(
        scapy_all.conf.route,
        "route",
        lambda _address: ("test-interface", "192.168.1.10", "0.0.0.0"),
    )
    monkeypatch.setattr(
        scapy_all,
        "srp",
        lambda *_args, **_kwargs: (
            [
                (None, SimpleNamespace(psrc="192.168.1.2")),
                (None, SimpleNamespace(psrc="192.168.2.2")),
            ],
            [],
        ),
    )

    found = network_discovery._discover_arp_hosts(
        network_discovery.ipaddress.ip_network("192.168.1.0/24"),
        threading.Event(),
    )

    assert found == {"192.168.1.2"}
