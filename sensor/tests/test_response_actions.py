import ipaddress
import json

from sensor.response_actions import (
    ACCOUNT,
    BLOCK,
    ISOLATE,
    ISOLATION_PREFIX,
    RULE_PREFIX,
    BlockEnforcer,
    isolation_exemptions,
    networks_to_block,
    protected_addresses,
    refusal_reason,
    server_allows_enforcement,
)

ACTION = "0603fe1c-dd2a-44df-a658-6bbc048f368f"
OTHER = "11111111-2222-3333-4444-555555555555"
PROTECTED = {ipaddress.ip_address(value) for value in ("192.168.1.172", "192.168.1.1", "8.8.8.8")}
EXEMPT = [
    ipaddress.ip_network(value)
    for value in ("127.0.0.0/8", "255.255.255.255/32", "192.168.1.1/32", "192.168.32.0/20")
]
ME = "S-1-5-21-1-2-3-1001"
USERS = [
    {"Name": "Administrator", "SID": "S-1-5-21-1-2-3-500", "Enabled": False},
    {"Name": "Guest", "SID": "S-1-5-21-1-2-3-501", "Enabled": False},
    {"Name": "Ahmed", "SID": ME, "Enabled": True},
    {"Name": "second-admin", "SID": "S-1-5-21-1-2-3-1002", "Enabled": True},
    {"Name": "sentinel-test", "SID": "S-1-5-21-1-2-3-1003", "Enabled": True},
    {"Name": "old-user", "SID": "S-1-5-21-1-2-3-1004", "Enabled": False},
]


class Windows:
    """Stands in for netsh, net and PowerShell: remembers changes, can be told to fail."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.rules: list[tuple[str, str, str]] = []
        self.fail_direction: str | None = None
        self.delete_fails = False
        self.users = [dict(user) for user in USERS]
        self.admins = [ME, "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-1002"]
        self.accounts_readable = True
        self.net_fails = False

    def __call__(self, command: list[str]) -> tuple[int, str]:
        self.commands.append(command)
        assert all(isinstance(part, str) for part in command)
        if command[0] == "powershell.exe":
            if not self.accounts_readable:
                return 1, ""
            return 0, json.dumps({"users": self.users, "admins": self.admins, "me": ME})
        if command[0] == "net":
            assert command[1] == "user" and command[3] in ("/active:no", "/active:yes")
            if self.net_fails:
                return 2, "System error 5 has occurred."
            for user in self.users:
                if user["Name"] == command[2]:
                    user["Enabled"] = command[3] == "/active:yes"
                    return 0, "The command completed successfully."
            return 2, "The user name could not be found."
        values = dict(part.split("=", 1) for part in command if "=" in part)
        if "add" in command:
            if values["dir"] == self.fail_direction:
                return 1, "Access is denied."
            assert values["action"] == "block"
            self.rules.append((values["name"], values["dir"], values["remoteip"]))
            return 0, "Ok."
        present = any(rule[0] == values["name"] for rule in self.rules)
        if "show" in command:
            # Like a Turkish Windows: the text is no use, only the exit code is.
            return (0, "Kural Adı: ...") if present else (1, "Belirtilen ölçütlerle eşleşen kural yok.")
        if self.delete_fails:
            return 1, "Erişim engellendi."
        self.rules = [rule for rule in self.rules if rule[0] != values["name"]]
        return (0, "Tamam.") if present else (1, "Belirtilen ölçütlerle eşleşen kural yok.")

    def changes(self) -> list[list[str]]:
        return [
            command
            for command in self.commands
            if command[0] != "powershell.exe" and "show" not in command
        ]

    def enabled(self, name: str) -> bool:
        return next(user["Enabled"] for user in self.users if user["Name"] == name)


def enforcer(tmp_path, windows, now=None, protected=None, allowed=(BLOCK, ISOLATE, ACCOUNT), reachable=True):
    clock = now or [1_000_000.0]
    return (
        BlockEnforcer(
            tmp_path / "blocks.json",
            "http://127.0.0.1:8001",
            allowed=frozenset(allowed),
            run=windows,
            clock=lambda: clock[0],
            protected=protected or (lambda: PROTECTED),
            exemptions=lambda: EXEMPT,
            server_reachable=(lambda: reachable) if reachable is not None else None,
        ),
        clock,
    )


# -- IP block ----------------------------------------------------------------
def test_block_adds_inbound_and_outbound_rules_and_survives_restart(tmp_path) -> None:
    windows = Windows()
    first, _ = enforcer(tmp_path, windows)
    assert first.block(ACTION, "203.0.113.9", 60)[0] == "applied"
    assert windows.rules == [
        (RULE_PREFIX + ACTION, "in", "203.0.113.9"),
        (RULE_PREFIX + ACTION, "out", "203.0.113.9"),
    ]
    saved = json.loads((tmp_path / "blocks.json").read_text())
    assert saved[ACTION]["ip"] == "203.0.113.9" and saved[ACTION]["kind"] == BLOCK
    assert first.block(ACTION, "203.0.113.9", 60) == ("applied", "already in place")
    assert len(windows.rules) == 2
    restarted, _ = enforcer(tmp_path, windows)
    assert ACTION in restarted.blocks


def test_expired_blocks_are_lifted_without_the_server(tmp_path) -> None:
    windows = Windows()
    first, clock = enforcer(tmp_path, windows)
    first.block(ACTION, "203.0.113.9", 5)
    assert first.expire() == []
    clock[0] += 5 * 60 + 1
    restarted, _ = enforcer(tmp_path, windows, now=clock, allowed=())
    assert restarted.handle(None) == [(ACTION, "removed", "expired")]
    assert windows.rules == [] and restarted.blocks == {}


def test_protected_and_reserved_addresses_are_refused(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    for target in (
        "192.168.1.172", "192.168.1.1", "8.8.8.8", "127.0.0.1", "::1", "0.0.0.0",  # noqa: S104
        "169.254.1.1", "224.0.0.1", "255.255.255.255", "::ffff:192.168.1.1",
        "203.0.113.0/24", "203.0.113.9 & calc", "", None,
    ):
        assert guard.block(ACTION, target, 60)[0] == "refused", target
    assert windows.commands == [] and guard.blocks == {}


def test_block_is_refused_when_protected_addresses_are_unknown(tmp_path) -> None:
    def unknown():
        raise RuntimeError("could not read this host's network configuration")

    windows = Windows()
    guard, _ = enforcer(tmp_path, windows, protected=unknown)
    state, detail = guard.block(ACTION, "203.0.113.9", 60)
    assert state == "refused" and "protected addresses" in detail
    assert windows.commands == []


def test_bad_duration_id_and_capacity_are_refused(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    for minutes in (0, -5, 24 * 60 + 1, "60", 60.0, True, None):
        assert guard.block(ACTION, "203.0.113.9", minutes)[0] == "refused"
    assert guard.block("../../evil", "203.0.113.9", 60)[0] == "refused"
    assert guard.block(ACTION + '" dir=in action=allow', "203.0.113.9", 60)[0] == "refused"
    assert windows.commands == []


def test_half_applied_block_is_rolled_back(tmp_path) -> None:
    windows = Windows()
    windows.fail_direction = "out"
    guard, _ = enforcer(tmp_path, windows)
    state, detail = guard.block(ACTION, "203.0.113.9", 60)
    assert state == "failed" and "Access is denied" in detail
    assert windows.rules == [] and guard.blocks == {}


def test_unblock_is_idempotent_and_handle_processes_server_actions(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    results = guard.handle(
        [
            {"id": ACTION, "action": "block", "ip": "203.0.113.9", "minutes": 30},
            {"id": OTHER, "action": "block", "ip": "192.168.1.1", "minutes": 30},
            {"id": OTHER, "action": "allow", "ip": "203.0.113.9"},
            "junk",
        ]
    )
    assert [(action_id, state) for action_id, state, _ in results] == [
        (ACTION, "applied"),
        (OTHER, "refused"),
    ]
    assert guard.handle([{"id": ACTION, "action": "unblock"}])[0][:2] == (ACTION, "removed")
    assert guard.unblock(ACTION) == ("removed", "")
    assert windows.rules == []


def test_each_action_needs_its_own_permission(tmp_path) -> None:
    windows = Windows()
    only_blocks, _ = enforcer(tmp_path, windows, allowed=(BLOCK,))
    assert only_blocks.isolate(ACTION, 30) == ("refused", "this action is not allowed on this sensor")
    assert only_blocks.disable_account(ACTION, "sentinel-test", 30)[0] == "refused"
    nothing, _ = enforcer(tmp_path, windows, allowed=())
    assert nothing.block(ACTION, "203.0.113.9", 30)[0] == "refused"
    assert windows.changes() == []


def test_enforcement_requires_tls_or_a_local_server() -> None:
    assert server_allows_enforcement("https://xdr.example.com")
    assert server_allows_enforcement("http://127.0.0.1:8001")
    assert server_allows_enforcement("http://localhost:8001")
    assert not server_allows_enforcement("http://192.168.56.1:8001")
    assert not server_allows_enforcement("http://xdr.example.com")


def test_protected_addresses_include_host_gateway_dns_and_server() -> None:
    def run(command):
        assert command[0] == "powershell.exe"
        return 0, json.dumps(["192.168.1.172", "fe80::1%12", "192.168.1.1", "1.1.1.1", "junk"])

    protected = protected_addresses("http://127.0.0.1:8001", run)
    for value in ("192.168.1.172", "192.168.1.1", "1.1.1.1", "127.0.0.1", "fe80::1"):
        assert ipaddress.ip_address(value) in protected
    assert refusal_reason("1.1.1.1", protected)[0] is None
    assert str(refusal_reason("203.0.113.9", protected)[0]) == "203.0.113.9"


# -- host isolation ----------------------------------------------------------
def _covered(networks, value: str) -> bool:
    return any(ipaddress.ip_address(value) in network for network in networks)


def test_isolation_blocks_everything_except_the_exemptions() -> None:
    blocked = networks_to_block(EXEMPT)
    for value in ("8.8.8.8", "1.1.1.1", "192.168.1.50", "192.168.1.172", "10.0.0.1", "203.0.113.9"):
        assert _covered(blocked, value), value
    for value in ("127.0.0.1", "192.168.1.1", "192.168.32.5", "192.168.47.254", "255.255.255.255"):
        assert not _covered(blocked, value), value
    # Every address is either blocked or exempt, never both and never neither.
    total = sum(network.num_addresses for network in blocked)
    exempt_total = sum(network.num_addresses for network in ipaddress.collapse_addresses(EXEMPT))
    assert total + exempt_total == 2**32
    assert len(blocked) < 200


def test_isolation_exemptions_keep_server_gateway_and_internal_switches() -> None:
    def run(_command):
        return 0, json.dumps(
            {
                "ips": [
                    {"IPAddress": "192.168.1.172", "PrefixLength": 24, "InterfaceAlias": "Wi-Fi"},
                    {"IPAddress": "192.168.32.1", "PrefixLength": 20, "InterfaceAlias": "vEthernet (WSL)"},
                    {"IPAddress": "10.0.0.1", "PrefixLength": 1, "InterfaceAlias": "vEthernet (bad)"},
                ],
                "gateways": ["192.168.1.1", "0.0.0.0"],  # noqa: S104 - a route value under test
            }
        )

    exempt = {str(network) for network in isolation_exemptions("http://127.0.0.1:8001", run)}
    assert {"127.0.0.0/8", "127.0.0.1/32", "192.168.1.1/32", "192.168.32.0/20"} <= exempt
    # The physical network is not exempt, and neither is an absurdly wide prefix.
    assert "192.168.1.0/24" not in exempt and "0.0.0.0/1" not in exempt and "0.0.0.0/32" not in exempt


def test_isolate_adds_rules_checks_the_server_and_lifts_on_expiry(tmp_path) -> None:
    windows = Windows()
    guard, clock = enforcer(tmp_path, windows)
    assert guard.isolate(ACTION, 30) == ("applied", "isolated for 30 minutes")
    names = {rule[0] for rule in windows.rules}
    assert names == {ISOLATION_PREFIX + ACTION} and len(windows.rules) == 4
    ipv4 = next(rule[2] for rule in windows.rules if "." in rule[2])
    assert "192.168.1.1/32" not in ipv4.split(",") and "127.0.0.0/8" not in ipv4.split(",")
    assert guard.isolate(OTHER, 30) == ("refused", "this host is already isolated")
    clock[0] += 30 * 60 + 1
    assert guard.handle([]) == [(ACTION, "removed", "expired")]
    assert windows.rules == []


def test_isolation_is_rolled_back_when_the_server_becomes_unreachable(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows, reachable=False)
    state, detail = guard.isolate(ACTION, 30)
    assert state == "failed" and "rolled back" in detail
    assert windows.rules == [] and guard.blocks == {}


def test_isolation_is_refused_without_a_reachability_check_or_over_the_limit(tmp_path) -> None:
    windows = Windows()
    blind, _ = enforcer(tmp_path, windows, reachable=None)
    assert blind.isolate(ACTION, 30)[0] == "refused"
    guard, _ = enforcer(tmp_path, windows)
    assert guard.isolate(ACTION, 4 * 60 + 1)[0] == "refused"
    assert windows.changes() == []


def test_isolation_is_released_when_the_sensor_stops_and_by_server_order(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    guard.isolate(ACTION, 30)
    guard.block(OTHER, "203.0.113.9", 30)
    assert guard.release_isolation("sensor stopping") == [(ACTION, "removed", "sensor stopping")]
    assert {rule[0] for rule in windows.rules} == {RULE_PREFIX + OTHER}  # the IP block stays
    # If the local record is lost, a release order still removes isolation rules.
    guard.isolate(ACTION, 30)
    (tmp_path / "blocks.json").unlink()
    amnesiac, _ = enforcer(tmp_path, windows)
    assert amnesiac.handle([{"id": ACTION, "action": "release"}]) == [(ACTION, "removed", "")]
    assert all(not rule[0].startswith(ISOLATION_PREFIX) for rule in windows.rules)


# -- local account -----------------------------------------------------------
def test_account_is_disabled_and_re_enabled_at_expiry(tmp_path) -> None:
    windows = Windows()
    guard, clock = enforcer(tmp_path, windows)
    assert guard.disable_account(ACTION, "SENTINEL-TEST", 10) == ("applied", "disabled for 10 minutes")
    assert windows.enabled("sentinel-test") is False
    assert ["net", "user", "sentinel-test", "/active:no"] in windows.commands
    clock[0] += 10 * 60 + 1
    assert guard.handle(None) == [(ACTION, "removed", "expired")]
    assert windows.enabled("sentinel-test") is True


def test_dangerous_or_unknown_accounts_are_refused(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    expected = {
        "Administrator": "built-in",
        "Guest": "built-in",
        "Ahmed": "this sensor runs as",
        "old-user": "already disabled",
        "nobody": "no local account",
        "/active:yes": "not a valid",
        "a&b": "not a valid",
        "": "not a valid",
    }
    for name, reason in expected.items():
        state, detail = guard.disable_account(ACTION, name, 10)
        assert state == "refused" and reason in detail, (name, detail)
    assert windows.changes() == [] and guard.blocks == {}


def test_last_enabled_administrator_is_refused_but_another_admin_is_not(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    # "Ahmed" and "second-admin" are enabled administrators: one may go.
    assert guard.disable_account(ACTION, "second-admin", 10)[0] == "applied"
    # If the sensor's own account were not an administrator, second-admin would be the last.
    windows2 = Windows()
    windows2.admins = ["S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-1002"]
    lone, _ = enforcer(tmp_path / "b", windows2)
    state, detail = lone.disable_account(OTHER, "second-admin", 10)
    assert state == "refused" and "last enabled administrator" in detail


def test_account_actions_fail_safely(tmp_path) -> None:
    windows = Windows()
    windows.accounts_readable = False
    guard, _ = enforcer(tmp_path, windows)
    state, detail = guard.disable_account(ACTION, "sentinel-test", 10)
    assert state == "refused" and "cannot check the account safely" in detail
    windows.accounts_readable, windows.net_fails = True, True
    state, detail = guard.disable_account(ACTION, "sentinel-test", 10)
    assert state == "failed" and guard.blocks == {}
    # Without a local record nothing is re-enabled on the server's word alone.
    windows.net_fails = False
    assert guard.handle([{"id": OTHER, "action": "enable_account", "target": "old-user"}]) == [
        (OTHER, "failed", "no recorded account to enable")
    ]
    assert windows.enabled("old-user") is False


def test_removal_does_not_depend_on_translated_firewall_messages(tmp_path) -> None:
    windows = Windows()
    guard, _ = enforcer(tmp_path, windows)
    # Nothing to remove: success, judged by the exit code of "show", not by text.
    assert guard.unblock(ACTION) == ("removed", "")
    guard.block(ACTION, "203.0.113.9", 30)
    windows.delete_fails = True
    state, detail = guard.unblock(ACTION)
    assert state == "failed" and ACTION in guard.blocks  # still recorded, so it is retried
    windows.delete_fails = False
    assert guard.unblock(ACTION) == ("removed", "") and windows.rules == []
