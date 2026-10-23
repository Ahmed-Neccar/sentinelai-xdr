"""Authenticated encryption for provider credentials stored by cloud connectors."""

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

_AAD = b"sentinelai-xdr:cloud-connector-credentials:v1"


def _key() -> bytes:
    if settings.cloud_connector_encryption_key:
        return base64.urlsafe_b64decode(settings.cloud_connector_encryption_key)
    if not settings.is_development:
        raise RuntimeError("CLOUD_CONNECTOR_ENCRYPTION_KEY is required outside development")
    return hashlib.sha256((settings.secret_key + ":cloud-connector-v1").encode()).digest()


def encrypt_credentials(credentials: dict[str, str]) -> str:
    nonce = secrets.token_bytes(12)
    clear = json.dumps(credentials, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(nonce + AESGCM(_key()).encrypt(nonce, clear, _AAD)).decode()


def decrypt_credentials(value: str) -> dict[str, str]:
    payload = base64.urlsafe_b64decode(value)
    clear = AESGCM(_key()).decrypt(payload[:12], payload[12:], _AAD)
    result = json.loads(clear)
    if not isinstance(result, dict) or any(
        not isinstance(key, str) or not isinstance(secret, str) for key, secret in result.items()
    ):
        raise ValueError("Stored connector credentials are invalid")
    return result
