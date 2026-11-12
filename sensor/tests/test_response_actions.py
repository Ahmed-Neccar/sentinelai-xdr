import ipaddress
import json

from sensor.response_actions import (
    RULE_PREFIX,
    BlockEnforcer,
    protected_addresses,
    refusal_reason,
    server_allows_enforcement,
)

ACTION = "0603fe1c-dd2a-44df-a658-6bbc048f368f"
OTHER = "11111111-2222-3333-4444-555555555555"
PROTECTED = {ipaddress.ip_address(value) for value in ("192.168.1.172", "192.168.1.1", "8.8.8.8")}


class Firewall:
    """Stands in for netsh: remembers rules, can be told to fail."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.rules: list[tuple[str, str, str]] = []
        self.fail_direction: str | None = None

    def __call__(self, command: list[str]) -> tuple[int, str]:
        self.commands.append(command)
        assert all(isinstance(part, str) for part in command)
        values = dict(part.split("=", 1) for part in command if "=" in part)
        if "add" in command:
            if values["dir"] == self.fail_direction:
                return 1, "Access is denied."
            assert values["action"] == "block"
            self.rules.append((values["name"], values["dir"], values["remoteip"]))
            return 0, "Ok."
        before = len(self.rules)
        self.rules = [rule for rule in self.rules if rule[0] != values["name"]]
        return (0, "Deleted") if len(self.rules) < before else (1, "No rules match the specified criteria.")


def enforcer(tmp_path, firewall, now=None, protected=None):
    clock = now or [1_000_000.0]
    return (
        BlockEnforcer(
            tmp_path / "blocks.json",
            "http://127.0.0.1:8001",
            run=firewall,
            clock=lambda: clock[0],
            protected=protected or (lambda: PROTECTED),
        ),
        clock,
    )


def test_block_adds_inbound_and_outbound_rules_and_survives_restart(tmp_path) -> None:
    firewall = Firewall()
    first, _ = enforcer(tmp_path, firewall)
    assert first.block(ACTION, "203.0.113.9", 60)[0] == "applied"
    assert firewall.rules == [
        (RULE_PREFIX + ACTION, "in", "203.0.113.9"),
        (RULE_PREFIX + ACTION, "out", "203.0.113.9"),
    ]
    saved = json.loads((tmp_path / "blocks.json").read_text())
    assert saved[ACTION]["ip"] == "203.0.113.9"
    # A repeated instruction does not add a second pair of rules.
    assert first.block(ACTION, "203.0.113.9", 60) == ("applied", "already in place")
    assert len(firewall.rules) == 2
    restarted, _ = enforcer(tmp_path, firewall)
    assert ACTION in restarted.blocks


def test_expired_blocks_are_lifted_without_the_server(tmp_path) -> None:
    firewall = Firewall()
    first, clock = enforcer(tmp_path, firewall)
    first.block(ACTION, "203.0.113.9", 5)
    assert first.expire() == []
    clock[0] += 5 * 60 + 1
    # Even a freshly started sensor with no server contact removes it.
    restarted, _ = enforcer(tmp_path, firewall, now=clock)
    assert restarted.handle(None) == [(ACTION, "removed", "expired")]
    assert firewall.rules == [] and restarted.blocks == {}


def test_protected_and_reserved_addresses_are_refused(tmp_path) -> None:
    firewall = Firewall()
    guard, _ = enforcer(tmp_path, firewall)
    for target in (
        "192.168.1.172", "192.168.1.1", "8.8.8.8", "127.0.0.1", "::1", "0.0.0.0",  # noqa: S104
        "169.254.1.1", "224.0.0.1", "255.255.255.255", "::ffff:192.168.1.1",
        "203.0.113.0/24", "203.0.113.9 & calc", "", None,
    ):
        assert guard.block(ACTION, target, 60)[0] == "refused", target
    assert firewall.commands == [] and guard.blocks == {}


def test_block_is_refused_when_protected_addresses_are_unknown(tmp_path) -> None:
    def unknown():
        raise RuntimeError("could not read this host's network configuration")

    firewall = Firewall()
    guard, _ = enforcer(tmp_path, firewall, protected=unknown)
    state, detail = guard.block(ACTION, "203.0.113.9", 60)
    assert state == "refused" and "protected addresses" in detail
    assert firewall.commands == []


def test_bad_duration_id_and_capacity_are_refused(tmp_path) -> None:
    firewall = Firewall()
    guard, _ = enforcer(tmp_path, firewall)
    for minutes in (0, -5, 24 * 60 + 1, "60", 60.0, True, None):
        assert guard.block(ACTION, "203.0.113.9", minutes)[0] == "refused"
    assert guard.block("../../evil", "203.0.113.9", 60)[0] == "refused"
    assert guard.block(ACTION + '" dir=in action=allow', "203.0.113.9", 60)[0] == "refused"
    assert firewall.commands == []


def test_half_applied_block_is_rolled_back(tmp_path) -> None:
    firewall = Firewall()
    firewall.fail_direction = "out"
    guard, _ = enforcer(tmp_path, firewall)
    state, detail = guard.block(ACTION, "203.0.113.9", 60)
    assert state == "failed" and "Access is denied" in detail
    assert firewall.rules == [] and guard.blocks == {}


def test_unblock_is_idempotent_and_handle_processes_server_actions(tmp_path) -> None:
    firewall = Firewall()
    guard, _ = enforcer(tmp_path, firewall)
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
    assert guard.unblock(ACTION) == ("removed", "")  # nothing left: still success
    assert firewall.rules == []


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
