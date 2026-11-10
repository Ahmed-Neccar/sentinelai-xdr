import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "env_backup.py"
_SPEC = importlib.util.spec_from_file_location("env_backup", _PATH)
assert _SPEC and _SPEC.loader
env_backup = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(env_backup)

PHRASE = "correct horse battery staple"  # noqa: S105 - test value
CONTENT = b"SECRET_KEY=not-a-real-key\nMFA_ENCRYPTION_KEY=also-not-real\n"
WHEN = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def test_backup_round_trip_and_ciphertext_hides_content(tmp_path: Path) -> None:
    source = tmp_path / ".env"
    source.write_bytes(CONTENT)
    target = env_backup.backup(source, tmp_path / "backups", PHRASE, now=WHEN)
    blob = target.read_bytes()

    assert target.name == "env-20261110T120000Z.enc"
    assert blob.startswith(env_backup.MAGIC)
    assert b"SECRET_KEY" not in blob and b"not-a-real-key" not in blob
    restored = env_backup.restore(target, tmp_path / ".env.restored", PHRASE)
    assert restored.read_bytes() == CONTENT


def test_each_backup_uses_a_fresh_salt_and_nonce() -> None:
    assert env_backup.encrypt(CONTENT, PHRASE) != env_backup.encrypt(CONTENT, PHRASE)


def test_wrong_passphrase_and_tampering_are_rejected() -> None:
    blob = env_backup.encrypt(CONTENT, PHRASE)
    with pytest.raises(env_backup.EnvBackupError, match="Wrong passphrase"):
        env_backup.decrypt(blob, PHRASE + "x")
    damaged = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(env_backup.EnvBackupError, match="damaged"):
        env_backup.decrypt(damaged, PHRASE)
    with pytest.raises(env_backup.EnvBackupError, match="not a SentinelAI"):
        env_backup.decrypt(b"plain text file", PHRASE)


def test_short_passphrase_and_empty_file_are_refused(tmp_path: Path) -> None:
    with pytest.raises(env_backup.EnvBackupError, match="at least 12"):
        env_backup.encrypt(CONTENT, "too-short")
    empty = tmp_path / ".env"
    empty.write_bytes(b"")
    with pytest.raises(env_backup.EnvBackupError, match="empty"):
        env_backup.backup(empty, tmp_path / "backups", PHRASE)
    assert not (tmp_path / "backups").exists()


def test_existing_files_are_never_overwritten(tmp_path: Path) -> None:
    source = tmp_path / ".env"
    source.write_bytes(CONTENT)
    target = env_backup.backup(source, tmp_path / "backups", PHRASE, now=WHEN)
    with pytest.raises(FileExistsError):
        env_backup.backup(source, tmp_path / "backups", PHRASE, now=WHEN)
    live = tmp_path / "live.env"
    live.write_bytes(b"CURRENT=1\n")
    with pytest.raises(env_backup.EnvBackupError, match="already exists"):
        env_backup.restore(target, live, PHRASE)
    assert live.read_bytes() == b"CURRENT=1\n"


def test_latest_backup_picks_the_newest_timestamp(tmp_path: Path) -> None:
    assert env_backup.latest_backup(tmp_path) is None
    for name in ("env-20261101T000000Z.enc", "env-20261110T120000Z.enc", "db-x.dump"):
        (tmp_path / name).write_bytes(b"x")
    assert env_backup.latest_backup(tmp_path).name == "env-20261110T120000Z.enc"
