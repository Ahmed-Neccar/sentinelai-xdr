"""Client address resolution that does not trust spoofable headers.

`X-Forwarded-For` is only meaningful when the directly connected peer is a
reverse proxy this deployment controls. Any other client can send the header
with any content, which would let it forge audit records and dodge per-address
rate limits. The header is therefore ignored unless the peer is listed in
TRUSTED_PROXIES, and even then only the right-most address that is not itself
a trusted proxy is used; everything to its left is client-supplied.
"""

from __future__ import annotations

import ipaddress
import socket
import time

from fastapi import Request

from app.core.config import settings

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_CACHE_SECONDS = 60.0
_cache: tuple[str, float, tuple[_IPNetwork, ...]] | None = None


def _resolve(entry: str) -> list[_IPNetwork]:
    try:
        return [ipaddress.ip_network(entry, strict=False)]
    except ValueError:
        pass
    try:
        # A Compose service name such as "frontend"; its address can change
        # when the container is recreated, hence the short cache.
        infos = socket.getaddrinfo(entry, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    networks: list[_IPNetwork] = []
    for info in infos:
        try:
            networks.append(ipaddress.ip_network(str(info[4][0])))
        except ValueError:
            continue
    return networks


def trusted_networks() -> tuple[_IPNetwork, ...]:
    global _cache
    configured = settings.trusted_proxies
    now = time.monotonic()
    if _cache is not None and _cache[0] == configured and now - _cache[1] < _CACHE_SECONDS:
        return _cache[2]
    networks: list[_IPNetwork] = []
    for entry in configured.split(","):
        if entry.strip():
            networks.extend(_resolve(entry.strip()))
    _cache = (configured, now, tuple(networks))
    return _cache[2]


def _parse(value: str | None) -> _IPAddress | None:
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _is_trusted(address: _IPAddress, networks: tuple[_IPNetwork, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def resolve_client_ip(peer: str | None, forwarded_for: str | None) -> str | None:
    peer_address = _parse(peer)
    networks = trusted_networks()
    if peer_address is None or not forwarded_for or not _is_trusted(peer_address, networks):
        return peer
    for hop in reversed(forwarded_for.split(",")[-20:]):
        address = _parse(hop)
        if address is None:
            return peer  # malformed chain: fall back to what was observed
        if not _is_trusted(address, networks):
            return str(address)
    return peer


def client_ip(request: Request) -> str | None:
    peer = request.client.host if request.client else None
    return resolve_client_ip(peer, request.headers.get("x-forwarded-for"))
