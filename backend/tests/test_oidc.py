from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from app.core import oidc
from app.core.config import Settings, settings
from app.core.errors import AppError
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError


def test_oidc_transaction_uses_state_nonce_and_pkce(monkeypatch) -> None:
    monkeypatch.setattr(settings, "secret_key", "test-oidc-state-signing-key")
    transaction, state, nonce, challenge = oidc.create_transaction("acme")

    claims = oidc.read_transaction(transaction, state)
    assert claims["organization_slug"] == "acme"
    assert claims["nonce"] == nonce
    assert len(challenge) == 43
    with pytest.raises(AppError, match="invalid or expired"):
        oidc.read_transaction(transaction, "wrong-state-value-that-is-long-enough")


def test_oidc_production_settings_require_complete_https_configuration() -> None:
    base = {
        "SENTINEL_ENV": "production",
        "SECRET_KEY": "s" * 48,
        "MFA_ENCRYPTION_KEY": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        "CLOUD_CONNECTOR_ENCRYPTION_KEY": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
        "DATABASE_URL": "postgresql+psycopg://sentinel_runtime:strong-app-password@db:5432/sentinel",
        "REDIS_URL": "redis://redis:6379/0",
        "SENTINEL_JOB_RUNNER": "celery",
        "CORS_ORIGINS": "https://xdr.example.com",
    }
    with pytest.raises(ValidationError, match="configured together"):
        Settings(_env_file=None, **(base | {"OIDC_ISSUER": "https://id.example.com"}))

    oidc_values = {
        "OIDC_ISSUER": "https://id.example.com/tenant",
        "OIDC_CLIENT_ID": "client-id",
        "OIDC_CLIENT_SECRET": "c" * 40,
        "OIDC_REDIRECT_URI": "http://xdr.example.com/api/v1/auth/oidc/callback",
    }
    with pytest.raises(ValidationError, match="OIDC_REDIRECT_URI"):
        Settings(_env_file=None, **(base | oidc_values))


@pytest.mark.parametrize("nonce_matches", [True, False])
def test_oidc_token_exchange_verifies_signature_audience_issuer_and_nonce(
    monkeypatch, nonce_matches: bool
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    issuer = "https://id.example.com/tenant"
    client_id = "sentinel-client"
    expected_nonce = "expected-nonce"
    monkeypatch.setattr(settings, "oidc_issuer", issuer)
    monkeypatch.setattr(settings, "oidc_client_id", client_id)
    monkeypatch.setattr(settings, "oidc_client_secret", "c" * 40)
    monkeypatch.setattr(settings, "oidc_redirect_uri", "https://xdr.example.com/callback")
    monkeypatch.setattr(
        oidc,
        "discover",
        lambda: {
            "issuer": issuer,
            "token_endpoint": "https://id.example.com/token",
            "jwks_uri": "https://id.example.com/jwks",
        },
    )
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": issuer,
            "sub": "user-123",
            "aud": client_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=2)).timestamp()),
            "nonce": expected_nonce if nonce_matches else "unexpected-nonce",
            "email": "analyst@example.com",
            "email_verified": True,
            "name": "Analyst",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"id_token": token}

    class SigningKey:
        key = public_key

    class Jwks:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get_signing_key_from_jwt(self, _token: str) -> SigningKey:
            return SigningKey()

    monkeypatch.setattr(oidc.httpx, "post", lambda *_args, **_kwargs: Response())
    monkeypatch.setattr(oidc, "PyJWKClient", Jwks)

    if nonce_matches:
        identity = oidc.exchange_and_validate("auth-code", "pkce-verifier", expected_nonce)
        assert identity == {
            "subject": "user-123",
            "email": "analyst@example.com",
            "name": "Analyst",
        }
    else:
        with pytest.raises(AppError, match="sign-in failed"):
            oidc.exchange_and_validate("auth-code", "pkce-verifier", expected_nonce)


def test_oidc_authorization_request_requests_code_flow_pkce_and_nonce(monkeypatch) -> None:
    monkeypatch.setattr(settings, "oidc_client_id", "sentinel-client")
    monkeypatch.setattr(settings, "oidc_redirect_uri", "https://xdr.example.com/callback")
    url = oidc.authorization_url(
        {"authorization_endpoint": "https://id.example.com/authorize"},
        "state-value",
        "nonce-value",
        "pkce-challenge",
    )
    query = parse_qs(urlsplit(url).query)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == ["pkce-challenge"]
    assert query["nonce"] == ["nonce-value"]


def test_entra_email_is_trusted_only_with_domain_owner_verification(monkeypatch) -> None:
    entra = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
    monkeypatch.setattr(settings, "oidc_issuer", entra)
    assert oidc.email_is_verified({"iss": entra, "xms_edov": True})
    assert not oidc.email_is_verified({"iss": entra})
    assert not oidc.email_is_verified({"iss": entra, "xms_edov": False})
    assert not oidc.email_is_verified({"iss": entra, "xms_edov": "true"})
    assert not oidc.email_is_verified({"iss": entra.replace("1111", "9999"), "xms_edov": True})


def test_other_providers_still_require_the_standard_email_verified_claim(monkeypatch) -> None:
    issuer = "https://id.example.com/tenant/v2.0"
    monkeypatch.setattr(settings, "oidc_issuer", issuer)
    assert oidc.email_is_verified({"iss": issuer, "email_verified": True})
    assert not oidc.email_is_verified({"iss": issuer, "xms_edov": True})
    assert not oidc.email_is_verified({"iss": issuer, "email_verified": "true"})
    lookalike = "https://login.microsoftonline.com.example.com/tenant/v2.0"
    monkeypatch.setattr(settings, "oidc_issuer", lookalike)
    assert not oidc.email_is_verified({"iss": lookalike, "xms_edov": True})


class _Account:
    def __init__(self, oidc_subject: str | None = None) -> None:
        self.oidc_subject = oidc_subject


def test_sso_account_selection_prefers_the_bound_identity_over_email() -> None:
    bound, other = _Account("subject-a"), _Account()
    assert oidc.select_account(bound, other) == (bound, False)
    assert oidc.select_account(bound, None) == (bound, False)


def test_sso_account_selection_binds_an_unbound_email_match_once() -> None:
    fresh = _Account()
    assert oidc.select_account(None, fresh) == (fresh, True)


def test_sso_account_selection_rejects_unprovisioned_and_rebound_accounts() -> None:
    with pytest.raises(AppError) as missing:
        oidc.select_account(None, None)
    assert missing.value.code == "sso_user_not_provisioned"
    # Same email, but the account already belongs to another provider subject:
    # an attacker who renamed their provider email must not get in.
    with pytest.raises(AppError) as mismatch:
        oidc.select_account(None, _Account("someone-else"))
    assert mismatch.value.code == "sso_identity_mismatch"
