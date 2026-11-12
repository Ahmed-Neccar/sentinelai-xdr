from datetime import UTC, datetime

import pytest
from app.response import ip_block


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "::1",
        "0.0.0.0",  # noqa: S104 - an address under test, not a bind
        "255.255.255.255",
        "224.0.0.251",
        "169.254.10.20",
        "fe80::1",
        "::ffff:127.0.0.1",
        "240.0.0.1",
        "not-an-ip",
        "203.0.113.0/24",
        "",
    ],
)
def test_reserved_or_invalid_targets_are_never_blockable(value: str) -> None:
    with pytest.raises(ip_block.BlockPolicyError):
        ip_block.normalize_block_target(value)


def test_public_and_private_addresses_are_normalized() -> None:
    assert ip_block.normalize_block_target(" 203.0.113.9 ") == "203.0.113.9"
    assert ip_block.normalize_block_target("192.168.1.50") == "192.168.1.50"
    assert ip_block.normalize_block_target("::ffff:203.0.113.9") == "203.0.113.9"
    assert ip_block.normalize_block_target("2001:DB8::1") == "2001:db8::1"


def test_duration_is_bounded() -> None:
    assert ip_block.validate_minutes(None) == ip_block.DEFAULT_MINUTES
    assert ip_block.validate_minutes(5) == 5
    for bad in (0, 4, 24 * 60 + 1, -60):
        with pytest.raises(ip_block.BlockPolicyError):
            ip_block.validate_minutes(bad)
    applied = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
    assert ip_block.block_until(applied, 60) == datetime(2026, 11, 12, 13, 0, tzinfo=UTC)


def test_sensor_reports_only_move_the_state_forward() -> None:
    assert ip_block.next_status(ip_block.PENDING, "applied") == ip_block.APPLIED
    assert ip_block.next_status(ip_block.PENDING, "refused") == ip_block.REFUSED
    assert ip_block.next_status(ip_block.PENDING, "failed") == ip_block.FAILED
    assert ip_block.next_status(ip_block.APPLIED, "removed") == ip_block.REMOVED
    assert ip_block.next_status(ip_block.REMOVAL_PENDING, "removed") == ip_block.REMOVED
    # A sensor cannot apply something that was never approved, was cancelled,
    # or was already lifted, and cannot re-apply after removal.
    for current in (None, ip_block.CANCELLED, ip_block.REMOVED, ip_block.REFUSED):
        assert ip_block.next_status(current, "applied") is None
    assert ip_block.next_status(ip_block.PENDING, "removed") is None
    assert ip_block.next_status(ip_block.APPLIED, "applied") is None
    assert ip_block.next_status(ip_block.APPLIED, "bogus") is None


def test_each_executed_action_has_its_own_capability_verbs_and_limits() -> None:
    assert set(ip_block.EXECUTED) == {"block_source_ip", "isolate_host", "disable_local_account"}
    capabilities = {spec.capability for spec in ip_block.EXECUTED.values()}
    verbs = {verb for spec in ip_block.EXECUTED.values() for verb in (spec.apply, spec.lift)}
    assert len(capabilities) == 3 and len(verbs) == 6
    # Isolation cuts a whole computer off, so its ceiling is the lowest.
    assert ip_block.EXECUTED[ip_block.ISOLATE].max_minutes == 240
    assert ip_block.validate_minutes(None, ip_block.ISOLATE) == 30
    with pytest.raises(ip_block.BlockPolicyError):
        ip_block.validate_minutes(241, ip_block.ISOLATE)
    assert ip_block.validate_minutes(1440, ip_block.DISABLE_ACCOUNT) == 1440


def test_isolation_target_is_always_the_chosen_sensor() -> None:
    assert ip_block.normalize_target(ip_block.ISOLATE, "some-other-server", "LAB-PC") == "LAB-PC"
    assert ip_block.normalize_target(ip_block.ACTION, "203.0.113.9", "LAB-PC") == "203.0.113.9"
    with pytest.raises(ip_block.BlockPolicyError):
        ip_block.normalize_target("simulate_host_isolation", "x", "LAB-PC")


@pytest.mark.parametrize(
    "name",
    ["/active:yes", "-x", "a&b", "a|b", 'a"b', "a\\b", "a/b", "x" * 21, "", " ", "user.", "a;b"],
)
def test_account_names_that_could_be_read_as_options_or_commands_are_rejected(name: str) -> None:
    with pytest.raises(ip_block.BlockPolicyError):
        ip_block.normalize_account_name(name)


def test_ordinary_account_names_are_accepted() -> None:
    for name in ("sentinel-test", "Ahmed", "lab user", "svc_backup.01"):
        assert ip_block.normalize_account_name(f" {name} ") == name
