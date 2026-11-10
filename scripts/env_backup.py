"""Passphrase-encrypted backup of the deployment's .env file.

The .env file holds the keys that decrypt enrolled TOTP secrets and cloud
connector credentials, so a database backup cannot be fully restored without
it. This tool writes an encrypted copy next to the other backup artifacts.

The key is derived from a passphrase with scrypt and the file is sealed with
AES-256-GCM. The passphrase is read interactively and is never stored, logged,
or accepted on the command line. Without it the backup cannot be recovered;
keep it in a password manager, separate from the backup files.

File layout: magic (8) | salt (16) | nonce (12) | ciphertext and tag.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SENTENV1"
SALT_BYTES, NONCE_BYTES = 16, 12
MIN_PASSPHRASE = 12
MAX_PLAINTEXT = 1024 * 1024


class EnvBackupError(Exception):
    """A user-facing failure; the message never contains file contents."""


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    if len(passphrase) < MIN_PASSPHRASE:
        raise EnvBackupError(f"The passphrase must be at least {MIN_PASSPHRASE} characters.")
    if not plaintext or len(plaintext) > MAX_PLAINTEXT:
        raise EnvBackupError("The file to back up is empty or larger than 1 MiB.")
    salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
    sealed = AESGCM(_key(passphrase, salt)).encrypt(nonce, plaintext, MAGIC)
    return MAGIC + salt + nonce + sealed


def decrypt(blob: bytes, passphrase: str) -> bytes:
    header = len(MAGIC) + SALT_BYTES + NONCE_BYTES
    if len(blob) <= header or not blob.startswith(MAGIC):
        raise EnvBackupError("This is not a SentinelAI encrypted .env backup.")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_BYTES]
    nonce = blob[len(MAGIC) + SALT_BYTES : header]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, blob[header:], MAGIC)
    except InvalidTag:
        raise EnvBackupError("Wrong passphrase, or the backup file is damaged.") from None


def backup(source: Path, backup_dir: Path, passphrase: str, now: datetime | None = None) -> Path:
    if not source.is_file():
        raise EnvBackupError(f"File not found: {source}")
    plaintext = source.read_bytes()
    blob = encrypt(plaintext, passphrase)
    if decrypt(blob, passphrase) != plaintext:
        raise EnvBackupError("Verification failed; no backup was written.")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    target = backup_dir / f"env-{stamp}.enc"
    with target.open("xb") as stream:  # never replace an existing backup
        stream.write(blob)
    return target


def restore(encrypted: Path, output: Path, passphrase: str) -> Path:
    if not encrypted.is_file():
        raise EnvBackupError(f"File not found: {encrypted}")
    plaintext = decrypt(encrypted.read_bytes(), passphrase)
    try:
        with output.open("xb") as stream:  # never replace an existing file
            stream.write(plaintext)
    except FileExistsError:
        raise EnvBackupError(
            f"{output} already exists. Move it aside or choose another --output."
        ) from None
    return output


def latest_backup(backup_dir: Path) -> Path | None:
    candidates = sorted(backup_dir.glob("env-*.enc"))
    return candidates[-1] if candidates else None


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("backup", help="write an encrypted copy of .env")
    create.add_argument("--source", type=Path, default=root / ".env")
    create.add_argument("--backup-dir", type=Path, default=root / "backups")
    recover = commands.add_parser("restore", help="decrypt a backup into a new file")
    recover.add_argument("--file", type=Path, help="defaults to the newest env-*.enc")
    recover.add_argument("--backup-dir", type=Path, default=root / "backups")
    recover.add_argument("--output", type=Path, default=root / ".env.restored")
    args = parser.parse_args()

    try:
        if args.command == "backup":
            passphrase = getpass.getpass("Passphrase for the .env backup: ")
            if getpass.getpass("Repeat the passphrase: ") != passphrase:
                raise EnvBackupError("The passphrases do not match; no backup was written.")
            target = backup(args.source, args.backup_dir, passphrase)
            print(f"Encrypted .env backup written and verified: {target}")
            print("Store the passphrase in a password manager. It cannot be recovered.")
        else:
            source = args.file or latest_backup(args.backup_dir)
            if source is None:
                raise EnvBackupError(f"No env-*.enc backup found in {args.backup_dir}")
            passphrase = getpass.getpass(f"Passphrase for {source.name}: ")
            output = restore(source, args.output, passphrase)
            print(f"Decrypted to {output}. Review it, then rename it to .env.")
    except EnvBackupError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
