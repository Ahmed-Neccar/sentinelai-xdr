"""TOTP, encrypted secret storage, and one-time recovery codes."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

_AAD = b"sentinelai-xdr:totp:v1"


def _encryption_key() -> bytes:
    if settings.mfa_encryption_key:
        return base64.urlsafe_b64decode(settings.mfa_encryption_key)
    if not settings.is_development:
        raise RuntimeError("MFA_ENCRYPTION_KEY is required outside development")
    return hashlib.sha256((settings.secret_key + ":dev-mfa-encryption").encode()).digest()


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def encrypt_totp_secret(secret: str) -> str:
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(_encryption_key()).encrypt(nonce, secret.encode("ascii"), _AAD)
    return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def decrypt_totp_secret(value: str) -> str:
    payload = base64.urlsafe_b64decode(value)
    clear = AESGCM(_encryption_key()).decrypt(payload[:12], payload[12:], _AAD)
    return clear.decode("ascii")


def totp_counter(code: str, secret: str, timestamp: int | None = None) -> int | None:
    """Return the matching RFC 6238 counter, allowing one 30-second clock step."""
    if len(code) != 6 or not code.isdigit():
        return None
    now_counter = (int(time.time()) if timestamp is None else timestamp) // 30
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    for counter in (now_counter + 1, now_counter, now_counter - 1):
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        expected = f"{value:06d}"
        if hmac.compare_digest(expected, code):
            return counter
    return None


def otpauth_uri(secret: str, email: str, issuer: str = "SentinelAI XDR") -> str:
    label = quote(f"{issuer}:{email}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def generate_recovery_codes(count: int = 10) -> list[str]:
    codes = []
    for _ in range(count):
        raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii").rstrip("=")
        codes.append("-".join(raw[index : index + 4] for index in range(0, len(raw), 4)))
    return codes


def recovery_code_hash(code: str) -> str:
    normalized = "".join(
        char for char in code.upper() if char.isascii() and char.isalnum()
    )
    return hmac.new(_encryption_key(), normalized.encode("ascii"), hashlib.sha256).hexdigest()


def find_recovery_code(code: str, hashes: list[str]) -> int | None:
    candidate = recovery_code_hash(code)
    for index, stored in enumerate(hashes):
        if hmac.compare_digest(candidate, stored):
            return index
    return None


def valid_counter(code: str, secret_encrypted: str, last_counter: int | None) -> int | None:
    try:
        secret = decrypt_totp_secret(secret_encrypted)
    except (InvalidTag, ValueError, UnicodeDecodeError):
        return None
    counter = totp_counter(code, secret)
    if counter is None or (last_counter is not None and counter <= last_counter):
        return None
    return counter
