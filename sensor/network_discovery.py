"""Bounded TCP discovery for explicitly authorized private networks."""

from __future__ import annotations

import ipaddress
import errno
import re
import socket
import ssl
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

MAX_HOSTS = 256
MAX_PORTS = 12
MAX_WORKERS = 48
CONNECT_TIMEOUT_SECONDS = 0.35
PROBE_TIMEOUT_SECONDS = 0.45
ALLOWED_PORTS = {
    22: "SSH", 53: "DNS", 80: "Web (HTTP)", 135: "Windows RPC",
    139: "Windows file sharing", 443: "Web (HTTPS)", 445: "Windows file sharing",
    3389: "Remote Desktop", 5432: "PostgreSQL", 8000: "Web application",
    8080: "Web application", 8443: "Secure web application",
}


def validate_scan_request(target: str, ports: list[int], authorized: bool) -> tuple[ipaddress._BaseNetwork, list[int]]:
    if authorized is not True:
        raise ValueError("Confirm that you are authorized to scan this network.")
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 network, such as 192.168.1.0/24.") from exc
    if not network.is_private or network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified:
        raise ValueError("Only private local networks can be scanned; public, loopback, and link-local targets are blocked.")
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(f"The selected network is too large. Limit the scan to {MAX_HOSTS} addresses or fewer.")
    if not ports or len(ports) > MAX_PORTS or len(set(ports)) != len(ports):
        raise ValueError(f"Select between 1 and {MAX_PORTS} distinct common service ports.")
    if any(type(port) is not int or port not in ALLOWED_PORTS for port in ports):
        raise ValueError("One or more selected ports are not in the approved common-service list.")
    return network, ports


def _clean_product(value: str) -> str:
    return re.sub(r"[^\x20-\x7e]", "", value).strip()[:100]


def _identify_service(client: socket.socket, address: str, port: int) -> tuple[str | None, str | None]:
    """Use harmless protocol greetings only; never sends credentials or changes state."""
    client.settimeout(PROBE_TIMEOUT_SECONDS)
    if port == 22:
        try:
            banner = _clean_product(client.recv(256).decode("ascii", errors="ignore").splitlines()[0])
            if banner.startswith("SSH-"):
                return "SSH", banner
        except (OSError, IndexError):
            pass
    elif port in {80, 8000, 8080}:
        return _probe_http(client, address, secure=False)
    elif port in {443, 8443}:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(client, server_hostname=address) as secure_client:
                protocol = secure_client.version() or "TLS"
                service, product = _probe_http(secure_client, address, secure=True)
                if service:
                    return service, f"{product}; {protocol}" if product else protocol
                return "TLS", protocol
        except (OSError, ssl.SSLError, ValueError):
            return None, None
    elif port == 53:
        try:
            query_id = 0x5341
            query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
            client.sendall(struct.pack("!H", len(query)) + query)
            response = client.recv(2)
            if len(response) == 2:
                length = struct.unpack("!H", response)[0]
                answer = b""
                while len(answer) < min(length, 512):
                    chunk = client.recv(min(512, length) - len(answer))
                    if not chunk:
                        break
                    answer += chunk
                if len(answer) >= 12 and struct.unpack("!H", answer[:2])[0] == query_id and answer[2] & 0x80:
                    return "DNS", "TCP DNS response"
        except OSError:
            pass
    elif port == 5432:
        try:
            client.sendall(struct.pack("!II", 8, 80877103))
            response = client.recv(1)
            if response in {b"S", b"N"}:
                return "PostgreSQL", "PostgreSQL protocol"
        except OSError:
            pass
    elif port == 3389:
        try:
            client.sendall(bytes.fromhex("030000130ee000000000000100080003000000"))
            response = client.recv(256)
            if len(response) >= 7 and response[:1] == b"\x03" and b"\xd0\x00" in response[:16]:
                return "Remote Desktop", "RDP negotiation response"
        except OSError:
            pass
    return None, None


def _probe_http(client: socket.socket, address: str, *, secure: bool) -> tuple[str | None, str | None]:
    try:
        client.sendall(f"HEAD / HTTP/1.0\r\nHost: {address}\r\nConnection: close\r\n\r\n".encode("ascii"))
        response = client.recv(1024).decode("iso-8859-1", errors="ignore")
        first_line = response.splitlines()[0] if response.splitlines() else ""
        if first_line.startswith("HTTP/"):
            server = next((line.split(":", 1)[1].strip() for line in response.splitlines()[1:] if line.lower().startswith("server:")), "")
            return ("HTTPS" if secure else "HTTP"), _clean_product(server) or _clean_product(first_line)
    except OSError:
        pass
    return None, None


def _classify_connect_error(error: int) -> str:
    if error in {errno.ECONNREFUSED, 10061}:
        return "closed"
    return "filtered"


def _discover_arp_hosts(network: ipaddress._BaseNetwork, cancel: threading.Event) -> set[str]:
    """Discover IPv4 peers on the directly connected link without relying on open ports."""
    if network.version != 4 or cancel.is_set():
        return set()
    try:
        from scapy.all import ARP, Ether, conf, srp

        probe_address = next(network.hosts(), network.network_address)
        interface, source_ip, gateway = conf.route.route(str(probe_address))
        if not interface or source_ip == "0.0.0.0" or gateway not in {"0.0.0.0", None}:
            return set()
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            iface=interface,
            timeout=1,
            retry=0,
            inter=0.005,
            verbose=0,
        )
    except Exception:
        # Keep the bounded TCP scan useful when Npcap/ARP is unavailable.
        return set()
    hosts: set[str] = set()
    for _, response in answered:
        try:
            parsed_address = ipaddress.ip_address(response.psrc)
        except ValueError:
            continue
        if parsed_address in network:
            hosts.add(str(parsed_address))
    return hosts


def _scan_host(address: str, ports: list[int], cancel: threading.Event) -> dict[str, Any]:
    port_results: list[dict[str, Any]] = []
    for port in ports:
        if cancel.is_set():
            break
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(CONNECT_TIMEOUT_SECONDS)
                result = client.connect_ex((address, port))
                if result == 0:
                    identified_service, product = _identify_service(client, address, port)
                    port_results.append({
                        "port": port,
                        "state": "open",
                        "service": identified_service or "Unknown",
                        "port_hint": ALLOWED_PORTS[port],
                        "identified": identified_service is not None,
                        "product": product,
                    })
                else:
                    port_results.append({"port": port, "state": _classify_connect_error(result), "service": "Unknown", "port_hint": ALLOWED_PORTS[port], "identified": False, "product": None})
        except OSError:
            port_results.append({"port": port, "state": "filtered", "service": "Unknown", "port_hint": ALLOWED_PORTS[port], "identified": False, "product": None})
    if not port_results:
        return {}
    responsive = any(item["state"] in {"open", "closed"} for item in port_results)
    return {"address": address, "state": "up" if responsive else "unknown", "ports": port_results}


def scan_network(target: str, ports: list[int], cancel: threading.Event, progress: Any) -> list[dict[str, Any]]:
    network, selected_ports = validate_scan_request(target, ports, authorized=True)
    addresses = [str(address) for address in network.hosts()]
    if network.version == 4 and network.prefixlen == 32:
        addresses = [str(network.network_address)]
    if network.version == 6 and network.prefixlen == 128:
        addresses = [str(network.network_address)]
    arp_hosts = _discover_arp_hosts(network, cancel)
    found: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="sentinel-discovery") as pool:
        futures = {pool.submit(_scan_host, address, selected_ports, cancel): address for address in addresses}
        for future in as_completed(futures):
            if cancel.is_set():
                break
            result = future.result()
            if result and (result["state"] == "up" or result["address"] in arp_hosts):
                methods = []
                if result["address"] in arp_hosts:
                    methods.append("ARP")
                if result["state"] == "up":
                    methods.append("TCP")
                result["state"] = "up"
                result["discovered_by"] = methods
                found.append(result)
            progress(len(addresses) - sum(1 for item in futures if not item.done()), found)
    return sorted(found, key=lambda item: ipaddress.ip_address(item["address"]))
