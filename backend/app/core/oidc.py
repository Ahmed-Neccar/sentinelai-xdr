"""Small, strict OIDC authorization-code client for a single self-hosted IdP."""

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from jwt import PyJWKClient

from app.core.config import settings
from app.core.errors import AppError

TRANSACTION_COOKIE = "oidc_transaction"
TRANSACTION_TTL_SECONDS = 300


def enabled() -> bool:
    return all(
        (
            settings.oidc_issuer,
            settings.oidc_client_id,
            settings.oidc_client_secret,
            settings.oidc_redirect_uri,
        )
    )


def _issuer_url(path: str) -> str:
    issuer = settings.oidc_issuer or ""
    return f"{issuer.rstrip('/')}/{path.lstrip('/')}"


def _https_url(value: object) -> str:
    if not isinstance(value, str):
        raise AppError(503, "sso_unavailable", "Identity provider configuration is invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise AppError(503, "sso_unavailable", "Identity provider configuration is invalid")
    return value


def discover() -> dict:
    if not enabled():
        raise AppError(404, "sso_disabled", "Single sign-on is not configured")
    try:
        response = httpx.get(_issuer_url(".well-known/openid-configuration"), timeout=5)
        response.raise_for_status()
        metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise AppError(503, "sso_unavailable", "Identity provider discovery failed") from exc
    if not isinstance(metadata, dict) or metadata.get("issuer") != settings.oidc_issuer:
        raise AppError(503, "sso_unavailable", "Identity provider issuer did not match")
    metadata["authorization_endpoint"] = _https_url(metadata.get("authorization_endpoint"))
    metadata["token_endpoint"] = _https_url(metadata.get("token_endpoint"))
    metadata["jwks_uri"] = _https_url(metadata.get("jwks_uri"))
    return metadata


def create_transaction(organization_slug: str) -> tuple[str, str, str, str]:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    now = datetime.now(UTC)
    transaction = jwt.encode(
        {
            "type": "oidc_transaction",
            "organization_slug": organization_slug,
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=TRANSACTION_TTL_SECONDS)).timestamp()),
        },
        settings.secret_key,
        algorithm="HS256",
    )
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return transaction, state, nonce, challenge.rstrip(b"=").decode("ascii")


def read_transaction(transaction: str, state: str) -> dict:
    try:
        claims = jwt.decode(transaction, settings.secret_key, algorithms=["HS256"])
        if claims.get("type") != "oidc_transaction":
            raise ValueError("unexpected token type")
        expected = claims.get("state")
        if not isinstance(expected, str) or not hmac.compare_digest(expected, state):
            raise ValueError("state mismatch")
        if not all(
            isinstance(claims.get(key), str) and claims[key]
            for key in ("organization_slug", "nonce", "verifier")
        ):
            raise ValueError("incomplete transaction")
        return claims
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise AppError(
            401, "invalid_sso_transaction", "SSO transaction is invalid or expired"
        ) from exc


MICROSOFT_ENTRA_HOST = "login.microsoftonline.com"


def email_is_verified(claims: dict) -> bool:
    """Whether the identity provider vouches for the email claim.

    The standard signal is `email_verified: true`. Microsoft Entra ID never
    emits that claim; its equivalent is the optional claim `xms_edov` ("email
    domain owner verified"), which is honoured only for a tenant-specific
    Entra issuer. An Entra email claim without `xms_edov: true` can be set by
    any tenant administrator and must not be matched to a local account.
    """
    if claims.get("email_verified") is True:
        return True
    issuer = urlsplit(settings.oidc_issuer or "")
    return (
        issuer.scheme == "https"
        and issuer.hostname == MICROSOFT_ENTRA_HOST
        and claims.get("iss") == settings.oidc_issuer
        and claims.get("xms_edov") is True
    )


def exchange_and_validate(code: str, verifier: str, nonce: str) -> dict:
    metadata = discover()
    try:
        response = httpx.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "code_verifier": verifier,
            },
            auth=(settings.oidc_client_id or "", settings.oidc_client_secret or ""),
            timeout=8,
        )
        response.raise_for_status()
        token_response = response.json()
        id_token = token_response.get("id_token") if isinstance(token_response, dict) else None
        if not isinstance(id_token, str) or not id_token:
            raise ValueError("ID token missing")
        header = jwt.get_unverified_header(id_token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError("unsupported signing algorithm")
        signing_key = PyJWKClient(metadata["jwks_uri"], timeout=5).get_signing_key_from_jwt(
            id_token
        )
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.oidc_client_id,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud", "nonce"]},
            leeway=60,
        )
    except AppError:
        raise
    except (httpx.HTTPError, ValueError, TypeError, jwt.PyJWTError) as exc:
        raise AppError(
            401, "sso_authentication_failed", "Identity provider sign-in failed"
        ) from exc
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != settings.oidc_client_id:
        raise AppError(401, "sso_authentication_failed", "Identity provider sign-in failed")
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(
        claims["nonce"], nonce
    ):
        raise AppError(401, "sso_authentication_failed", "Identity provider sign-in failed")
    subject = claims.get("sub")
    email = claims.get("email")
    if (
        not isinstance(subject, str)
        or not 1 <= len(subject) <= 255
        or not isinstance(email, str)
        or len(email) > 320
        or not email_is_verified(claims)
    ):
        raise AppError(401, "sso_identity_unverified", "A verified email identity is required")
    return {"subject": subject, "email": email.lower(), "name": claims.get("name", "")}


def authorization_url(metadata: dict, state: str, nonce: str, challenge: str) -> str:
    query = urlencode(
        {
            "client_id": settings.oidc_client_id,
            "response_type": "code",
            "response_mode": "query",
            "scope": "openid profile email",
            "redirect_uri": settings.oidc_redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{metadata['authorization_endpoint']}?{query}"
