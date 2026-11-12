"""Applies approved, time-limited IP blocks on this Windows host.

This is the only part of SentinelAI that changes a system. It is off unless
the sensor is started with --enforce-blocks, and it is deliberately narrow:

* it only ever adds or deletes Windows Firewall *block* rules that it named
  itself ("SentinelAI block <id>"); it cannot open anything;
* it refuses this host's own addresses, its default gateways, its DNS
  servers, the SentinelAI server and every reserved address, whatever the
  server asked for;
* every block has an end time that is kept on disk, so it is lifted when it
  expires even if the server is unreachable, and at the next start if the
  sensor was not running;
* the firewall command receives the address as a separate argument after it
  has been parsed as an IP address, never through a shell.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_MINUTES = 24 * 60
MAX_ACTIVE_BLOCKS = 100
RULE_PREFIX = "SentinelAI block "
_ACTION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

Runner = Callable[[list[str]], tuple[int, str]]


def server_allows_enforcement(server_url: str) -> bool:
    """Blocks are accepted only over TLS or from a server on this same machine.

    Over plain HTTP on a network, anyone able to alter the traffic could make
    this host block addresses.
    """
    parsed = urlsplit(server_url)
    if parsed.scheme == "https":
        return True
    host = (parsed.hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _run(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(  # noqa: S603 - fixed program, validated arguments, no shell
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return completed.returncode, (completed.stdout or completed.stderr or "").strip()


def _powershell_addresses(run: Runner) -> set[str]:
    script = (
        "$a=@(); "
        "$a+=(Get-NetIPAddress -ErrorAction SilentlyContinue).IPAddress; "
        "$a+=(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue).NextHop; "
        "$a+=(Get-DnsClientServerAddress -ErrorAction SilentlyContinue).ServerAddresses; "
        "$a | Where-Object { $_ } | Sort-Object -Unique | ConvertTo-Json -Compress"
    )
    code, output = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    if code != 0 or not output:
        raise RuntimeError("could not read this host's network configuration")
    values = json.loads(output)
    return {str(value) for value in (values if isinstance(values, list) else [values])}


def protected_addresses(server_url: str, run: Runner = _run) -> set[ipaddress._BaseAddress]:
    """Addresses this host must keep reaching. Raises if they cannot be determined."""
    raw = _powershell_addresses(run)
    host = urlsplit(server_url).hostname
    if host:
        try:
            raw.update(info[4][0] for info in socket.getaddrinfo(host, None))
        except OSError:
            pass
    protected: set[ipaddress._BaseAddress] = set()
    for value in raw:
        try:
            protected.add(ipaddress.ip_address(str(value).split("%")[0]))
        except ValueError:
            continue
    if not protected:
        raise RuntimeError("no protected addresses were found")
    return protected


def refusal_reason(
    value: Any, protected: set[ipaddress._BaseAddress]
) -> tuple[ipaddress._BaseAddress | None, str]:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, "not a valid IP address"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or (address.version == 4 and int(address) == 0xFFFFFFFF)
    ):
        return None, "reserved address"
    if address in protected:
        return None, "protected address (this host, its gateway, its DNS server or the server)"
    return address, ""


class BlockEnforcer:
    def __init__(
        self,
        state_path: Path,
        server_url: str,
        *,
        run: Runner = _run,
        clock: Callable[[], float] = time.time,
        protected: Callable[[], set[ipaddress._BaseAddress]] | None = None,
    ) -> None:
        self.state_path = state_path
        self.run = run
        self.clock = clock
        self._protected = protected or (lambda: protected_addresses(server_url, run))
        self.blocks: dict[str, dict[str, Any]] = self._load()

    # -- state -----------------------------------------------------------
    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            key: value
            for key, value in data.items()
            if _ACTION_ID.match(str(key)) and isinstance(value, dict)
        }

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.blocks, sort_keys=True), encoding="utf-8")
        temporary.replace(self.state_path)

    # -- firewall --------------------------------------------------------
    def _add_rules(self, action_id: str, address: ipaddress._BaseAddress) -> tuple[bool, str]:
        name = RULE_PREFIX + action_id
        for direction in ("in", "out"):
            code, output = self.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}", f"dir={direction}", "action=block",
                    f"remoteip={address}", "enable=yes", "profile=any",
                ]
            )
            if code != 0:
                self._delete_rules(action_id)  # never leave half a block behind
                return False, f"firewall rejected the rule ({code}): {output}"[:200]
        return True, ""

    def _delete_rules(self, action_id: str) -> tuple[bool, str]:
        code, output = self.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}{action_id}"]
        )
        # netsh reports "No rules match" with a non-zero code; that is already the goal.
        if code != 0 and "no rules match" not in output.lower():
            return False, f"firewall could not remove the rule ({code}): {output}"[:200]
        return True, ""

    # -- operations ------------------------------------------------------
    def block(self, action_id: str, ip: Any, minutes: Any) -> tuple[str, str]:
        if not _ACTION_ID.match(str(action_id)):
            return "refused", "malformed action id"
        if action_id in self.blocks:
            return "applied", "already in place"
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= MAX_MINUTES:
            return "refused", "duration outside the allowed range"
        if len(self.blocks) >= MAX_ACTIVE_BLOCKS:
            return "refused", "too many active blocks on this host"
        try:
            protected = self._protected()
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
            # Without the protected list a block could cut this host off.
            return "refused", f"cannot determine protected addresses: {exc}"[:200]
        address, reason = refusal_reason(ip, protected)
        if address is None:
            return "refused", reason
        # Record first: if the sensor dies after the rule is added, the next
        # start still knows it must be removed.
        self.blocks[action_id] = {"ip": str(address), "expires_at": self.clock() + minutes * 60}
        self._save()
        added, detail = self._add_rules(action_id, address)
        if not added:
            self.blocks.pop(action_id, None)
            self._save()
            return "failed", detail
        return "applied", f"blocked for {minutes} minutes"

    def unblock(self, action_id: str) -> tuple[str, str]:
        if not _ACTION_ID.match(str(action_id)):
            return "failed", "malformed action id"
        removed, detail = self._delete_rules(action_id)
        if not removed:
            return "failed", detail
        self.blocks.pop(action_id, None)
        self._save()
        return "removed", ""

    def expire(self) -> list[tuple[str, str, str]]:
        """Lift blocks whose time is up; safe to call often and without a server."""
        results: list[tuple[str, str, str]] = []
        now = self.clock()
        for action_id, block in list(self.blocks.items()):
            expires_at = block.get("expires_at")
            if not isinstance(expires_at, (int, float)) or expires_at <= now:
                state, detail = self.unblock(action_id)
                results.append((action_id, state, detail or "expired"))
        return results

    def handle(self, actions: Any) -> list[tuple[str, str, str]]:
        """Process the server's list and return (action id, result, detail) to report."""
        results = self.expire()
        reported = {action_id for action_id, _, _ in results}
        if not isinstance(actions, list):
            return results
        for item in actions[:50]:
            if not isinstance(item, dict):
                continue
            action_id = str(item.get("id", ""))
            if action_id in reported:
                continue
            if item.get("action") == "block":
                state, detail = self.block(action_id, item.get("ip"), item.get("minutes"))
            elif item.get("action") == "unblock":
                state, detail = self.unblock(action_id)
            else:
                continue
            results.append((action_id, state, detail))
        return results
