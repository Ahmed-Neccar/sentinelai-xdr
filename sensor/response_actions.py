"""Applies approved, time-limited response actions on this Windows host.

This is the only part of SentinelAI that changes a system. Every action is
off unless the sensor is started with its own flag, and each is narrow:

IP block (--enforce-blocks)
    Adds Windows Firewall *block* rules for one address. Refuses this host's
    own addresses, its gateways, its DNS servers, the SentinelAI server and
    every reserved address.

Host isolation (--allow-isolation)
    Adds Windows Firewall block rules for every address except the SentinelAI
    server, the gateway (for DHCP) and host-internal virtual networks. It then
    checks that the server is still reachable and removes the rules at once if
    it is not. Only one isolation can exist, and it is lifted when the sensor
    stops.

Local account disable (--allow-account-disable)
    Disables one local Windows account. Refuses built-in accounts, the account
    the sensor runs as, an account that is already disabled, and the last
    enabled administrator. Only accounts it disabled are ever re-enabled.

Common rules: it only deletes firewall rules it named itself and cannot open
anything; every action has an end time kept on disk, so it is lifted when it
expires even if the server is unreachable, and at the next start if the sensor
was not running; if it cannot read the facts a safeguard needs, it refuses;
commands receive validated values as separate arguments, never through a shell.
"""

from __future__ import annotations

import base64
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
MAX_ISOLATION_MINUTES = 4 * 60
MAX_ACTIVE_BLOCKS = 100
RULE_PREFIX = "SentinelAI block "
ISOLATION_PREFIX = "SentinelAI isolate "
BLOCK, ISOLATE, ACCOUNT = "block", "isolate", "account"
_ACTION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,19}$")
# Well-known relative IDs of accounts Windows itself owns.
_BUILT_IN_RIDS = {"500", "501", "503", "504"}
_MAX_RULE_ADDRESSES = 900
_MAX_COMMAND_CHARS = 7000

Runner = Callable[[list[str]], tuple[int, str]]
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def server_allows_enforcement(server_url: str) -> bool:
    """Actions are accepted only over TLS or from a server on this same machine.

    Over plain HTTP on a network, anyone able to alter the traffic could make
    this host block addresses, isolate itself or disable accounts.
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


NOTICE_ISOLATED = (
    "Bu bilgisayar SentinelAI XDR tarafindan agdan yalitildi ({minutes} dakika). "
    "Ag ve internet erisimi kesildi; sure dolunca otomatik acilir. Sorun icin BT yoneticinize basvurun. "
    "- "
    "This computer was isolated from the network by SentinelAI XDR for {minutes} minutes. "
    "It reconnects automatically when the time is up. Contact your IT administrator."
)
NOTICE_LIFTED = (
    "SentinelAI XDR yalitmayi kaldirdi; ag erisimi geri geliyor. - "
    "SentinelAI XDR lifted the isolation; network access is returning."
)


def show_notice(title: str, text: str) -> None:
    """Show a message box to whoever is at this computer. Never blocks, never raises.

    It only appears in an interactive session (the sensor runs as a logged-in user's task).
    The text is fixed in this module; the script travels as an encoded command so it
    cannot be altered by quoting.
    """
    safe_title = title.replace("'", "")[:80]
    safe_text = text.replace("'", "")[:600]
    script = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        f"$f = New-Object System.Windows.Forms.Form; $f.TopMost = $true; $f.ShowInTaskbar = $false; $f.Text = '{safe_title}'; "
        "$f.WindowState = 'Minimized'; $f.Show(); "
        f"[void][System.Windows.Forms.MessageBox]::Show($f, '{safe_text}', '{safe_title}', 'OK', 'Warning'); "
        "$f.Close()"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        subprocess.Popen(  # noqa: S603 - fixed program, fixed text, no shell
            ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, ValueError):
        pass


def _run(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(  # noqa: S603 - fixed program, validated arguments, no shell
        command,
        capture_output=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    # Bytes are decoded here, leniently: on a non-English Windows the console
    # code page differs from Python's default and adapter names are not ASCII.
    raw = completed.stdout or completed.stderr or b""
    return completed.returncode, raw.decode("utf-8", errors="replace").strip()


def _powershell_json(run: Runner, script: str, what: str) -> Any:
    script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script
    code, output = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    if code != 0 or not output:
        raise RuntimeError(f"could not read {what}")
    try:
        return json.loads(output)
    except ValueError as exc:
        raise RuntimeError(f"could not read {what}") from exc


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _server_addresses(server_url: str) -> set[str]:
    host = urlsplit(server_url).hostname
    if not host:
        return set()
    try:
        return {str(info[4][0]) for info in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def protected_addresses(server_url: str, run: Runner = _run) -> set[Address]:
    """Addresses this host must keep reaching. Raises if they cannot be determined."""
    script = (
        "$a=@(); "
        "$a+=(Get-NetIPAddress -ErrorAction SilentlyContinue).IPAddress; "
        "$a+=(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue).NextHop; "
        "$a+=(Get-DnsClientServerAddress -ErrorAction SilentlyContinue).ServerAddresses; "
        "$a | Where-Object { $_ } | Sort-Object -Unique | ConvertTo-Json -Compress"
    )
    raw = {str(value) for value in _as_list(_powershell_json(run, script, "this host's network configuration"))}
    raw.update(_server_addresses(server_url))
    protected: set[Address] = set()
    for value in raw:
        try:
            protected.add(ipaddress.ip_address(str(value).split("%")[0]))
        except ValueError:
            continue
    if not protected:
        raise RuntimeError("no protected addresses were found")
    return protected


def refusal_reason(value: Any, protected: set[Address]) -> tuple[Address | None, str]:
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


# -- isolation ------------------------------------------------------------
def isolation_exemptions(server_url: str, run: Runner = _run) -> list[ipaddress.IPv4Network]:
    """IPv4 networks that stay reachable while this host is isolated.

    The SentinelAI server (so the order to lift it can arrive), the default
    gateways (which are normally also the DHCP server), limited broadcast for
    DHCP, loopback, and host-internal virtual networks such as the ones Hyper-V
    and WSL create ("vEthernet ..."), which never leave this computer.
    Raises if the facts cannot be read or the server is only reachable by IPv6.
    """
    script = (
        "@{ips=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress,PrefixLength,InterfaceAlias); "
        "gateways=@((Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).NextHop)} "
        "| ConvertTo-Json -Depth 3 -Compress"
    )
    facts = _powershell_json(run, script, "this host's network configuration")
    if not isinstance(facts, dict):
        raise RuntimeError("could not read this host's network configuration")
    exempt: list[ipaddress.IPv4Network] = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("255.255.255.255/32"),
    ]
    server_v4 = []
    for value in _server_addresses(server_url):
        try:
            address = ipaddress.ip_address(value.split("%")[0])
        except ValueError:
            continue
        if address.version == 4:
            server_v4.append(address)
            exempt.append(ipaddress.ip_network(f"{address}/32"))
    if not server_v4:
        raise RuntimeError("the SentinelAI server has no IPv4 address to keep reachable")
    for value in _as_list(facts.get("gateways")):
        try:
            gateway = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if gateway.version == 4 and not gateway.is_unspecified:
            exempt.append(ipaddress.ip_network(f"{gateway}/32"))
    for item in _as_list(facts.get("ips")):
        if not isinstance(item, dict):
            continue
        if not str(item.get("InterfaceAlias", "")).lower().startswith("vethernet"):
            continue
        try:
            network = ipaddress.ip_network(
                f"{item.get('IPAddress')}/{int(item.get('PrefixLength'))}", strict=False
            )
        except (ValueError, TypeError):
            continue
        # Guard against an absurd prefix exempting most of the internet.
        if network.version == 4 and network.prefixlen >= 16:
            exempt.append(network)
    return exempt


def networks_to_block(exempt: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    """Every IPv4 address except the exempt networks, as a short list of CIDRs."""
    remaining: list[ipaddress.IPv4Network] = [ipaddress.ip_network("0.0.0.0/0")]
    for hole in exempt:
        next_remaining: list[ipaddress.IPv4Network] = []
        for network in remaining:
            if not network.overlaps(hole):
                next_remaining.append(network)
            elif hole.supernet_of(network):
                continue  # entirely exempt
            else:
                next_remaining.extend(network.address_exclude(hole))
        remaining = next_remaining
    return sorted(ipaddress.collapse_addresses(remaining))


class BlockEnforcer:
    def __init__(
        self,
        state_path: Path,
        server_url: str,
        *,
        allowed: frozenset[str] | set[str] = frozenset(),
        run: Runner = _run,
        clock: Callable[[], float] = time.time,
        protected: Callable[[], set[Address]] | None = None,
        exemptions: Callable[[], list[ipaddress.IPv4Network]] | None = None,
        server_reachable: Callable[[], bool] | None = None,
        notify: Callable[[str, str], None] | None = None,
    ) -> None:
        self.state_path = state_path
        # Called with (title, text) when this computer is isolated or released, so the person
        # at the keyboard can see what happened. Optional; failures never affect enforcement.
        self._notify = notify
        self.allowed = frozenset(allowed)
        self.run = run
        self.clock = clock
        self._protected = protected or (lambda: protected_addresses(server_url, run))
        self._exemptions = exemptions or (lambda: isolation_exemptions(server_url, run))
        # Without a way to check, isolation is refused rather than assumed safe.
        self._server_reachable = server_reachable
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

    def _kind(self, action_id: str) -> str:
        return str(self.blocks.get(action_id, {}).get("kind", BLOCK))

    def _precheck(self, action_id: Any, minutes: Any, kind: str, limit: int) -> tuple[str, str] | None:
        if kind not in self.allowed:
            return "refused", "this action is not allowed on this sensor"
        if not _ACTION_ID.match(str(action_id)):
            return "refused", "malformed action id"
        if action_id in self.blocks:
            return "applied", "already in place"
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= limit:
            return "refused", "duration outside the allowed range"
        if len(self.blocks) >= MAX_ACTIVE_BLOCKS:
            return "refused", "too many active actions on this host"
        return None

    def _record(self, action_id: str, kind: str, minutes: int, **extra: Any) -> None:
        # Recorded before the change is made: if the sensor dies in between,
        # the next start still knows something must be undone.
        self.blocks[action_id] = {"kind": kind, "expires_at": self.clock() + minutes * 60, **extra}
        self._save()

    def _forget(self, action_id: str) -> None:
        self.blocks.pop(action_id, None)
        self._save()

    # -- firewall --------------------------------------------------------
    def _add_rules(self, name: str, remote: str) -> tuple[bool, str]:
        for direction in ("in", "out"):
            code, output = self.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}", f"dir={direction}", "action=block",
                    f"remoteip={remote}", "enable=yes", "profile=any",
                ]
            )
            if code != 0:
                self._delete_rules(name)  # never leave half a rule set behind
                return False, f"firewall rejected the rule ({code}): {output}"[:200]
        return True, ""

    def _delete_rules(self, name: str) -> tuple[bool, str]:
        # Ask first whether the rule exists. netsh also answers "delete" with a
        # non-zero code when nothing matched, and its message is translated on
        # a non-English Windows, so the text cannot be relied on.
        exists, _ = self.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"])
        if exists != 0:
            return True, ""
        code, output = self.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        )
        if code != 0:
            return False, f"firewall could not remove the rule ({code}): {output}"[:200]
        return True, ""

    # -- IP block --------------------------------------------------------
    def block(self, action_id: str, ip: Any, minutes: Any) -> tuple[str, str]:
        early = self._precheck(action_id, minutes, BLOCK, MAX_MINUTES)
        if early:
            return early
        try:
            protected = self._protected()
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
            # Without the protected list a block could cut this host off.
            return "refused", f"cannot determine protected addresses: {exc}"[:200]
        address, reason = refusal_reason(ip, protected)
        if address is None:
            return "refused", reason
        self._record(action_id, BLOCK, minutes, ip=str(address))
        added, detail = self._add_rules(RULE_PREFIX + action_id, str(address))
        if not added:
            self._forget(action_id)
            return "failed", detail
        return "applied", f"blocked for {minutes} minutes"

    # -- host isolation --------------------------------------------------
    def isolate(self, action_id: str, minutes: Any) -> tuple[str, str]:
        early = self._precheck(action_id, minutes, ISOLATE, MAX_ISOLATION_MINUTES)
        if early:
            return early
        if any(block.get("kind") == ISOLATE for block in self.blocks.values()):
            return "refused", "this host is already isolated"
        if self._server_reachable is None:
            return "refused", "cannot verify that the server stays reachable"
        try:
            targets = networks_to_block(self._exemptions())
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
            return "refused", f"cannot determine what must stay reachable: {exc}"[:200]
        remote = ",".join(str(network) for network in targets)
        if not targets or len(targets) > _MAX_RULE_ADDRESSES or len(remote) > _MAX_COMMAND_CHARS:
            return "refused", "the isolation rule would be too large for this host"
        name = ISOLATION_PREFIX + action_id
        self._record(action_id, ISOLATE, minutes)
        added, detail = self._add_rules(name, remote)
        if added:
            # Global and unique-local IPv6; link-local stays for the local link.
            added, detail = self._add_rules(name, "2000::/3,fc00::/7")
        if not added:
            self._delete_rules(name)
            self._forget(action_id)
            return "failed", detail
        try:
            reachable = bool(self._server_reachable())
        except Exception:  # noqa: BLE001 - any failure here means "not reachable"
            reachable = False
        if not reachable:
            # An isolation nobody can lift remotely is worse than none.
            self._delete_rules(name)
            self._forget(action_id)
            return "failed", "the server was not reachable under isolation; rolled back"
        self._tell("SentinelAI XDR", NOTICE_ISOLATED.format(minutes=int(minutes)))
        return "applied", f"isolated for {minutes} minutes"

    def _tell(self, title: str, text: str) -> None:
        if self._notify is None:
            return
        try:
            self._notify(title, text)
        except Exception:  # noqa: BLE001 - a notice must never break enforcement
            pass

    def release_isolation(self, reason: str) -> list[tuple[str, str, str]]:
        """Lift any isolation now, for example because the sensor is stopping."""
        results = []
        for action_id, block in list(self.blocks.items()):
            if block.get("kind") == ISOLATE:
                state, detail = self.unblock(action_id)
                results.append((action_id, state, detail or reason))
        return results

    # -- local account ---------------------------------------------------
    def _accounts(self) -> dict[str, Any]:
        script = (
            "@{users=@(Get-LocalUser | Select-Object Name,@{n='SID';e={$_.SID.Value}},Enabled); "
            "admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | "
            "ForEach-Object { $_.SID.Value }); "
            "me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value} "
            "| ConvertTo-Json -Depth 3 -Compress"
        )
        facts = _powershell_json(self.run, script, "the local accounts")
        if not isinstance(facts, dict) or not facts.get("me"):
            raise RuntimeError("could not read the local accounts")
        return facts

    def disable_account(self, action_id: str, name: Any, minutes: Any) -> tuple[str, str]:
        early = self._precheck(action_id, minutes, ACCOUNT, MAX_MINUTES)
        if early:
            return early
        requested = str(name or "").strip()
        if not _ACCOUNT_NAME.match(requested) or requested.endswith((" ", ".")):
            return "refused", "not a valid local account name"
        try:
            facts = self._accounts()
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
            return "refused", f"cannot check the account safely: {exc}"[:200]
        users = [item for item in _as_list(facts.get("users")) if isinstance(item, dict)]
        target = next(
            (item for item in users if str(item.get("Name", "")).lower() == requested.lower()), None
        )
        if target is None:
            return "refused", "no local account with that name"
        sid = str(target.get("SID", ""))
        canonical = str(target.get("Name", ""))
        if not _ACCOUNT_NAME.match(canonical):
            return "refused", "the account name cannot be handled safely"
        if sid.rsplit("-", 1)[-1] in _BUILT_IN_RIDS:
            return "refused", "built-in Windows account"
        if sid == str(facts.get("me")):
            return "refused", "the account this sensor runs as"
        if target.get("Enabled") is not True:
            # It must not be re-enabled later by this sensor.
            return "refused", "the account is already disabled"
        admins = {str(value) for value in _as_list(facts.get("admins"))}
        if sid in admins:
            other_enabled_admins = [
                item for item in users
                if str(item.get("SID")) in admins
                and str(item.get("SID")) != sid
                and item.get("Enabled") is True
            ]
            if not other_enabled_admins:
                return "refused", "the last enabled administrator on this computer"
        self._record(action_id, ACCOUNT, minutes, account=canonical)
        code, output = self.run(["net", "user", canonical, "/active:no"])
        if code != 0:
            self._forget(action_id)
            return "failed", f"Windows refused to disable the account ({code}): {output}"[:200]
        return "applied", f"disabled for {minutes} minutes"

    # -- lifting ---------------------------------------------------------
    def unblock(self, action_id: str, kind_hint: str | None = None) -> tuple[str, str]:
        """Undo one action of any kind. Succeeds if there is nothing left to undo.

        `kind_hint` is what the server says the action was; it is only used
        when the local record is gone, so the right firewall rules are removed.
        """
        if not _ACTION_ID.match(str(action_id)):
            return "failed", "malformed action id"
        block = self.blocks.get(action_id)
        kind = self._kind(action_id) if block is not None else (kind_hint or BLOCK)
        if kind == ACCOUNT:
            account = str((block or {}).get("account", ""))
            if not _ACCOUNT_NAME.match(account):
                return "failed", "no recorded account to enable"
            code, output = self.run(["net", "user", account, "/active:yes"])
            if code != 0:
                return "failed", f"Windows refused to enable the account ({code}): {output}"[:200]
        else:
            prefix = ISOLATION_PREFIX if kind == ISOLATE else RULE_PREFIX
            removed, detail = self._delete_rules(prefix + action_id)
            if not removed:
                return "failed", detail
            if kind == ISOLATE:
                self._tell("SentinelAI XDR", NOTICE_LIFTED)
        self._forget(action_id)
        return "removed", ""

    def expire(self) -> list[tuple[str, str, str]]:
        """Lift actions whose time is up; safe to call often and without a server."""
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
            verb = item.get("action")
            if verb == "block":
                state, detail = self.block(action_id, item.get("ip"), item.get("minutes"))
            elif verb == "isolate":
                state, detail = self.isolate(action_id, item.get("minutes"))
            elif verb == "disable_account":
                state, detail = self.disable_account(
                    action_id, item.get("target"), item.get("minutes")
                )
            elif verb in {"unblock", "release", "enable_account"}:
                hint = {"unblock": BLOCK, "release": ISOLATE, "enable_account": ACCOUNT}[verb]
                state, detail = self.unblock(action_id, hint)
            else:
                continue
            results.append((action_id, state, detail))
        return results
