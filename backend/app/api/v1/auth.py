import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

import jwt
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import DbDep, client_ip, get_current_user, require_roles
from app.audit.service import write_audit
from app.core import oidc
from app.core.auth_rate_limit import enforce_auth_rate_limit
from app.core.errors import AppError
from app.core.mfa import (
    encrypt_totp_secret,
    find_recovery_code,
    generate_recovery_codes,
    generate_totp_secret,
    otpauth_uri,
    recovery_code_hash,
    valid_counter,
)
from app.core.password_policy import check_new_password
from app.core.permissions import ADMIN
from app.core.security import (
    burn_password_check,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.session import set_organization_context
from app.models import Organization, RefreshToken, User, UserRole
from app.schemas.common import TokenUser

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


class LoginRequest(BaseModel):
    # Login identifiers may use reserved local-only domains such as .local.
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=1, max_length=256)
    organization_slug: str = Field(
        default="default",
        min_length=1,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth bearer scheme name, not a credential.
    expires_in: int
    user: TokenUser
    recovery_codes: list[str] | None = None


class MFAChallengeResponse(BaseModel):
    mfa_required: Literal[True] = True
    mfa_setup_required: bool
    challenge_token: str


class MFAChallengeIn(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=4096)
    code: str = Field(min_length=6, max_length=32, pattern=r"^[A-Za-z0-9 -]+$")


class MFASetupChallengeIn(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=4096)


class MFACodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32, pattern=r"^[A-Za-z0-9 -]+$")


class MFAEnrollIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)


class MFADisableIn(MFAEnrollIn):
    code: str = Field(min_length=6, max_length=32, pattern=r"^[A-Za-z0-9 -]+$")


class MFARequirementIn(BaseModel):
    required: bool


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _roles(user: User) -> list[str]:
    return [link.role.name for link in user.roles if link.role]


def _challenge_token(user: User, auth_methods: list[str] | None = None) -> str:
    from app.core.config import settings

    now = datetime.now(UTC)
    challenge_id = str(uuid4())
    user.mfa_challenge_id = challenge_id
    return jwt.encode(
        {
            "sub": str(user.id),
            "org": str(user.organization_id),
            "tv": user.token_version,
            "type": "mfa_challenge",
            "amr": auth_methods or ["pwd"],
            "jti": challenge_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        settings.secret_key,
        algorithm="HS256",
    )


def _issue_tokens(
    user: User,
    db: Session,
    response: Response,
    request: Request,
    *,
    auth_methods: list[str],
    recovery_codes: list[str] | None = None,
    action: str = "auth.login",
    session_started_at: datetime | None = None,
) -> TokenResponse:
    from app.core.config import settings

    roles = _roles(user)
    access = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        roles=roles,
        token_version=user.token_version,
        auth_methods=auth_methods,
    )
    refresh, expires_at = create_refresh_token(
        user_id=user.id,
        organization_id=user.organization_id,
        token_version=user.token_version,
        auth_methods=auth_methods,
        session_started_at=session_started_at,
    )
    db.add(
        RefreshToken(
            user_id=user.id,
            organization_id=user.organization_id,
            token_hash=_hash_token(refresh),
            expires_at=expires_at,
        )
    )
    write_audit(
        db,
        actor_id=user.id,
        action=action,
        target_type="user",
        target_id=str(user.id),
        ip_address=client_ip(request),
        details={"auth_methods": auth_methods},
    )
    db.commit()
    response.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        samesite="lax",
        secure=not settings.is_development,
        path="/api/v1/auth",
        max_age=settings.refresh_token_hours * 3600,
    )
    return TokenResponse(
        access_token=access,
        expires_in=settings.access_token_minutes * 60,
        user=TokenUser(
            id=user.id,
            organization_id=user.organization_id,
            email=user.email,
            full_name=user.full_name,
            roles=roles,
            is_active=user.is_active,
            auth_methods=auth_methods,
        ),
        recovery_codes=recovery_codes,
    )


def _load_challenge_user(token: str, db: Session) -> tuple[User, list[str]]:
    try:
        payload = decode_token(token)
        if payload.get("type") != "mfa_challenge":
            raise ValueError("wrong token type")
        organization_id = UUID(payload["org"])
        user_id = UUID(payload["sub"])
        token_version = int(payload["tv"])
        challenge_id = str(payload["jti"])
        raw_methods = payload.get("amr", ["pwd"])
        auth_methods = (
            [method for method in raw_methods if method in {"pwd", "otp", "oidc"}]
            if isinstance(raw_methods, list)
            else ["pwd"]
        )
        if not auth_methods:
            auth_methods = ["pwd"]
    except Exception as exc:  # noqa: BLE001 — fail closed for malformed or expired challenges.
        raise AppError(401, "invalid_mfa_challenge", "MFA challenge expired or invalid") from exc
    set_organization_context(db, organization_id)
    organization = db.scalar(
        select(Organization).where(
            Organization.id == organization_id,
            Organization.is_active.is_(True),
        )
    )
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.organization_id == organization_id,
            User.is_active.is_(True),
        ).with_for_update()
    )
    if (
        organization is None
        or user is None
        or user.token_version != token_version
        or user.mfa_challenge_id != challenge_id
    ):
        raise AppError(401, "invalid_mfa_challenge", "MFA challenge expired or invalid")
    return user, auth_methods


def _oidc_result_page(payload: dict) -> HTMLResponse:
    encoded = json.dumps(payload, separators=(",", ":"))
    for source, replacement in (
        ("&", "\\u0026"),
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        encoded = encoded.replace(source, replacement)
    return HTMLResponse(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in complete</title>"
        "</head><body><p>Returning to SentinelAI…</p>"
        f"<script id=\"oidc-result\" type=\"application/json\">{encoded}</script>"
        "<script src=\"/sso-callback.js\" defer></script></body></html>"
    )


def _verify_mfa_code(user: User, code: str) -> bool:
    if user.mfa_enabled_at is None or not user.mfa_secret_encrypted:
        return False
    counter = valid_counter(code, user.mfa_secret_encrypted, user.mfa_last_counter)
    if counter is not None:
        user.mfa_last_counter = counter
        return True
    hashes = list(user.mfa_recovery_code_hashes or [])
    match = find_recovery_code(code, hashes)
    if match is None:
        return False
    hashes.pop(match)
    user.mfa_recovery_code_hashes = hashes
    return True


@router.post("/login", response_model=TokenResponse | MFAChallengeResponse)
def login(
    payload: LoginRequest, request: Request, response: Response, db: DbDep
) -> TokenResponse | MFAChallengeResponse:
    enforce_auth_rate_limit(f"login:{client_ip(request) or 'unknown'}", limit=20)
    enforce_auth_rate_limit(
        f"login-account:{payload.organization_slug}:{payload.email.lower()}", limit=12
    )

    organization = db.scalar(
        select(Organization).where(
            Organization.slug == payload.organization_slug,
            Organization.is_active.is_(True),
        )
    )
    if organization is None:
        raise AppError(401, "invalid_credentials", "Invalid organization or credentials")
    set_organization_context(db, organization.id)
    user = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(
            User.email == payload.email.lower(),
            User.organization_id == organization.id,
        )
    )
    if user is None or not user.is_active:
        burn_password_check(payload.password)
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.hashed_password)
    ):
        write_audit(
            db,
            actor_id=None,
            action="auth.login_failed",
            target_type="user",
            target_id=payload.email.lower(),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_credentials", "Invalid email or password")
    if user.mfa_enabled_at is not None or organization.mfa_required:
        write_audit(
            db,
            actor_id=user.id,
            action="auth.mfa_challenge_issued",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )
        challenge_token = _challenge_token(user)
        db.commit()
        return MFAChallengeResponse(
            mfa_setup_required=user.mfa_enabled_at is None,
            challenge_token=challenge_token,
        )
    return _issue_tokens(
        user,
        db,
        response,
        request,
        auth_methods=["pwd"],
    )


@router.get("/oidc/status")
def oidc_status() -> dict:
    # The origin lets the sign-in page send people to the one address where
    # SSO can work: the transaction cookie and the result message are bound to
    # the origin of the registered redirect URI.
    return {"enabled": oidc.enabled(), "origin": oidc.redirect_origin()}


@router.get("/oidc/start")
def oidc_start(
    db: DbDep,
    request: Request,
    organization_slug: str = Query(
        default="default", min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"
    ),
) -> RedirectResponse:
    enforce_auth_rate_limit(
        f"oidc-start:{client_ip(request) or 'unknown'}:{organization_slug}", limit=20
    )
    metadata = oidc.discover()
    organization = db.scalar(
        select(Organization).where(
            Organization.slug == organization_slug,
            Organization.is_active.is_(True),
        )
    )
    if organization is None:
        raise AppError(401, "invalid_sso_organization", "Organization is unavailable")
    transaction, state, nonce, challenge = oidc.create_transaction(organization_slug)
    redirect = RedirectResponse(
        oidc.authorization_url(metadata, state, nonce, challenge), status_code=302
    )
    from app.core.config import settings

    redirect.set_cookie(
        oidc.TRANSACTION_COOKIE,
        transaction,
        httponly=True,
        secure=not settings.is_development,
        samesite="lax",
        max_age=oidc.TRANSACTION_TTL_SECONDS,
        path="/api/v1/auth/oidc",
    )
    return redirect


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    state: Annotated[str, Query(min_length=20, max_length=256)],
    db: DbDep,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    error: Annotated[str | None, Query(max_length=128)] = None,
) -> HTMLResponse:
    enforce_auth_rate_limit(f"oidc-callback:{client_ip(request) or 'unknown'}", limit=50)
    try:
        return _complete_oidc_callback(request, state, db, code, error)
    except AppError as exc:
        # Record why SSO failed. The browser only gets a generic message, so
        # without this an operator cannot tell a wrong account from a broken
        # provider configuration. The code is one of this app's own constants.
        logger.warning("SSO sign-in failed: %s", exc.code)
        try:
            db.rollback()
            # Audit rows are tenant-scoped; the organization is only known if
            # the signed transaction cookie is still readable.
            claims = oidc.read_transaction(request.cookies.get(oidc.TRANSACTION_COOKIE, ""), state)
            organization = db.scalar(
                select(Organization).where(Organization.slug == claims["organization_slug"])
            )
            if organization is not None:
                set_organization_context(db, organization.id)
                write_audit(
                    db,
                    actor_id=None,
                    action="auth.sso_failed",
                    target_type="sso",
                    target_id=exc.code[:64],
                    ip_address=client_ip(request),
                    details={"code": exc.code},
                )
                db.commit()
        except Exception:  # noqa: BLE001 - auditing must not mask the sign-in error page
            db.rollback()
        page = _oidc_result_page(
            {
                "type": "sentinelai-sso-error",
                "message": (
                    "SSO could not be completed. Check the account and identity-provider setup."
                ),
            }
        )
        page.delete_cookie(oidc.TRANSACTION_COOKIE, path="/api/v1/auth/oidc")
        page.headers["cache-control"] = "no-store"
        page.headers["referrer-policy"] = "no-referrer"
        return page


def _complete_oidc_callback(
    request: Request,
    state: str,
    db: Session,
    code: str | None,
    error: str | None,
) -> HTMLResponse:
    transaction = request.cookies.get(oidc.TRANSACTION_COOKIE)
    if not transaction:
        # The browser did not return the cookie set by /oidc/start.
        raise AppError(401, "sso_transaction_missing", "SSO transaction is missing or expired")
    if error or not code:
        # `error` is the provider's short OAuth error code, for example
        # access_denied; it is safe to record and is not shown to the browser.
        logger.warning("SSO provider returned error=%s", (error or "no_code")[:64])
        raise AppError(401, "sso_provider_error", "Identity provider sign-in failed")
    claims = oidc.read_transaction(transaction, state)
    identity = oidc.exchange_and_validate(code, claims["verifier"], claims["nonce"])
    organization = db.scalar(
        select(Organization).where(
            Organization.slug == claims["organization_slug"],
            Organization.is_active.is_(True),
        )
    )
    if organization is None:
        raise AppError(401, "sso_authentication_failed", "Organization is unavailable")
    set_organization_context(db, organization.id)
    from app.core.config import settings

    issuer = settings.oidc_issuer or ""
    account_query = select(User).options(selectinload(User.roles).selectinload(UserRole.role))
    bound_account = db.scalar(
        account_query.where(
            User.organization_id == organization.id,
            User.oidc_issuer == issuer,
            User.oidc_subject == identity["subject"],
        ).with_for_update()
    )
    email_account = None
    if bound_account is None:
        email_account = db.scalar(
            account_query.where(
                User.email == identity["email"], User.organization_id == organization.id
            ).with_for_update()
        )
    try:
        user, bind_identity = oidc.select_account(bound_account, email_account)
    except AppError as exc:
        if exc.code == "sso_identity_mismatch" and email_account is not None:
            write_audit(
                db,
                actor_id=None,
                action="auth.sso_identity_mismatch",
                target_type="user",
                target_id=str(email_account.id),
                ip_address=client_ip(request),
            )
            db.commit()
        raise
    if not user.is_active:
        raise AppError(
            403,
            "sso_user_not_provisioned",
            "Your organization administrator must provision your account before SSO sign-in",
        )
    if bind_identity:
        user.oidc_issuer = issuer
        user.oidc_subject = identity["subject"]
        write_audit(
            db,
            actor_id=user.id,
            action="auth.sso_identity_bound",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )

    page = _oidc_result_page({})
    page.delete_cookie(oidc.TRANSACTION_COOKIE, path="/api/v1/auth/oidc")
    if user.mfa_enabled_at is not None or organization.mfa_required:
        challenge_token = _challenge_token(user, auth_methods=["oidc"])
        write_audit(
            db,
            actor_id=user.id,
            action="auth.sso_mfa_challenge_issued",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )
        db.commit()
        result = {
            "type": "sentinelai-sso-result",
            "mfa_required": True,
            "mfa_setup_required": user.mfa_enabled_at is None,
            "challenge_token": challenge_token,
        }
    else:
        tokens = _issue_tokens(
            user,
            db,
            page,
            request,
            auth_methods=["oidc"],
            action="auth.sso_login",
        )
        result = {"type": "sentinelai-sso-result", **tokens.model_dump(mode="json")}
    page.body = _oidc_result_page(result).body
    page.headers["content-length"] = str(len(page.body))
    page.headers["cache-control"] = "no-store"
    page.headers["referrer-policy"] = "no-referrer"
    return page


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(request: Request, response: Response, db: DbDep) -> TokenResponse:
    token = request.cookies.get("refresh_token")
    if not token:
        raise AppError(401, "unauthenticated", "Refresh token missing")
    try:
        payload = decode_token(token)
    except Exception as exc:  # noqa: BLE001
        raise AppError(401, "invalid_token", "Invalid refresh token") from exc
    if payload.get("type") != "refresh":
        raise AppError(401, "invalid_token", "Invalid refresh token")
    try:
        organization_id = UUID(payload["org"])
    except (KeyError, ValueError, TypeError) as exc:
        raise AppError(401, "invalid_token", "Invalid refresh token") from exc
    set_organization_context(db, organization_id)
    stored = db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == _hash_token(token))
        .with_for_update()
    )
    if stored is None or stored.revoked:
        raise AppError(401, "invalid_token", "Refresh token revoked")
    # Rotation must not stretch a session without limit: the clock runs from the sign-in.
    try:
        started_at = int(payload.get("sat", payload["iat"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise AppError(401, "invalid_token", "Invalid refresh token") from exc
    session_started = datetime.fromtimestamp(started_at, UTC)
    from app.core.config import settings

    if datetime.now(UTC) >= session_started + timedelta(hours=settings.session_max_hours):
        stored.revoked = True
        db.commit()
        raise AppError(401, "session_expired", "Your session has ended. Sign in again")
    user = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(User.id == stored.user_id, User.organization_id == organization_id)
    )
    if user is None or not user.is_active:
        raise AppError(401, "unauthenticated", "User not found or inactive")
    if int(payload.get("tv", -1)) != user.token_version:
        stored.revoked = True
        db.commit()
        raise AppError(401, "token_revoked", "Refresh token has been revoked")
    claim_methods = payload.get("amr", ["pwd"])
    auth_methods = (
        [method for method in claim_methods if method in {"pwd", "otp", "oidc"}]
        if isinstance(claim_methods, list)
        else ["pwd"]
    )
    organization = db.get(Organization, organization_id)
    if (user.mfa_enabled_at is not None or (organization and organization.mfa_required)) and (
        "otp" not in auth_methods
    ):
        stored.revoked = True
        db.commit()
        raise AppError(401, "mfa_required", "Complete MFA verification to continue")
    stored.revoked = True
    db.flush()
    return _issue_tokens(
        user,
        db,
        response,
        request,
        auth_methods=auth_methods,
        action="auth.refresh",
        session_started_at=session_started,
    )


@router.get("/mfa/status")
def mfa_status(
    db: DbDep, user: Annotated[TokenUser, Depends(get_current_user)]
) -> dict:
    account = db.get(User, user.id)
    organization = db.get(Organization, user.organization_id)
    if account is None or organization is None:
        raise AppError(404, "not_found", "Account not found")
    return {
        "enabled": account.mfa_enabled_at is not None,
        "required_for_organization": organization.mfa_required,
        "recovery_codes_remaining": len(account.mfa_recovery_code_hashes or []),
    }


@router.post("/mfa/enroll")
def begin_mfa_enrollment(
    payload: MFAEnrollIn,
    db: DbDep,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> dict:
    enforce_auth_rate_limit(f"mfa-enroll:{user.organization_id}:{user.id}", limit=8)
    account = db.get(User, user.id)
    if account is None or not verify_password(payload.current_password, account.hashed_password):
        raise AppError(401, "invalid_credentials", "Current password is incorrect")
    if account.mfa_enabled_at is not None:
        raise AppError(409, "mfa_already_enabled", "MFA is already enabled")
    secret = generate_totp_secret()
    account.mfa_pending_secret_encrypted = encrypt_totp_secret(secret)
    write_audit(
        db,
        actor_id=user.id,
        action="auth.mfa_enrollment_started",
        target_type="user",
        target_id=str(user.id),
    )
    db.commit()
    return {"secret": secret, "otpauth_uri": otpauth_uri(secret, account.email)}


@router.post("/mfa/enable", response_model=TokenResponse)
def enable_mfa(
    payload: MFACodeIn,
    request: Request,
    response: Response,
    db: DbDep,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> TokenResponse:
    account = db.get(User, user.id)
    if account is None or not account.mfa_pending_secret_encrypted:
        raise AppError(409, "mfa_enrollment_missing", "Start MFA enrollment first")
    enforce_auth_rate_limit(f"mfa-enroll:{user.organization_id}:{user.id}", limit=8)
    counter = valid_counter(
        payload.code, account.mfa_pending_secret_encrypted, account.mfa_last_counter
    )
    if counter is None:
        write_audit(
            db,
            actor_id=user.id,
            action="auth.mfa_enrollment_failed",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_mfa_code", "The authenticator code is invalid")
    recovery_codes = generate_recovery_codes()
    account.mfa_secret_encrypted = account.mfa_pending_secret_encrypted
    account.mfa_pending_secret_encrypted = None
    account.mfa_enabled_at = datetime.now(UTC)
    account.mfa_last_counter = counter
    account.mfa_recovery_code_hashes = [recovery_code_hash(code) for code in recovery_codes]
    account.token_version += 1
    account.mfa_challenge_id = None
    return _issue_tokens(
        account,
        db,
        response,
        request,
        auth_methods=["pwd", "otp"],
        recovery_codes=recovery_codes,
        action="auth.mfa_enabled",
    )


@router.post("/mfa/setup")
def begin_required_mfa_setup(
    payload: MFASetupChallengeIn, request: Request, db: DbDep
) -> dict:
    account, challenge_methods = _load_challenge_user(payload.challenge_token, db)
    enforce_auth_rate_limit(f"mfa-setup:{account.organization_id}:{account.id}", limit=8)
    organization = db.get(Organization, account.organization_id)
    if organization is None or not organization.mfa_required or account.mfa_enabled_at:
        raise AppError(409, "mfa_setup_not_required", "MFA setup is not required")
    secret = generate_totp_secret()
    account.mfa_pending_secret_encrypted = encrypt_totp_secret(secret)
    write_audit(
        db,
        actor_id=account.id,
        action="auth.mfa_enrollment_started",
        target_type="user",
        target_id=str(account.id),
        ip_address=client_ip(request),
    )
    db.commit()
    return {"secret": secret, "otpauth_uri": otpauth_uri(secret, account.email)}


@router.post("/mfa/setup/confirm", response_model=TokenResponse)
def confirm_required_mfa_setup(
    payload: MFAChallengeIn, request: Request, response: Response, db: DbDep
) -> TokenResponse:
    account, challenge_methods = _load_challenge_user(payload.challenge_token, db)
    enforce_auth_rate_limit(f"mfa-setup:{account.organization_id}:{account.id}", limit=8)
    organization = db.get(Organization, account.organization_id)
    pending = account.mfa_pending_secret_encrypted
    if organization is None or not organization.mfa_required or not pending:
        raise AppError(409, "mfa_setup_not_required", "MFA setup is not required")
    counter = valid_counter(payload.code, pending, account.mfa_last_counter)
    if counter is None:
        write_audit(
            db,
            actor_id=account.id,
            action="auth.mfa_enrollment_failed",
            target_type="user",
            target_id=str(account.id),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_mfa_code", "The authenticator code is invalid")
    account.mfa_challenge_id = None
    recovery_codes = generate_recovery_codes()
    account.mfa_secret_encrypted = pending
    account.mfa_pending_secret_encrypted = None
    account.mfa_enabled_at = datetime.now(UTC)
    account.mfa_last_counter = counter
    account.mfa_recovery_code_hashes = [recovery_code_hash(code) for code in recovery_codes]
    account.token_version += 1
    return _issue_tokens(
        account,
        db,
        response,
        request,
        auth_methods=[*challenge_methods, "otp"],
        recovery_codes=recovery_codes,
        action="auth.mfa_enabled",
    )


@router.post("/mfa/verify", response_model=TokenResponse)
def verify_mfa_challenge(
    payload: MFAChallengeIn,
    request: Request,
    response: Response,
    db: DbDep,
) -> TokenResponse:
    account, challenge_methods = _load_challenge_user(payload.challenge_token, db)
    enforce_auth_rate_limit(f"mfa-verify-ip:{client_ip(request) or 'unknown'}", limit=50)
    enforce_auth_rate_limit(f"mfa-verify-account:{account.organization_id}:{account.id}", limit=10)
    if not _verify_mfa_code(account, payload.code):
        write_audit(
            db,
            actor_id=account.id,
            action="auth.mfa_failed",
            target_type="user",
            target_id=str(account.id),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_mfa_code", "The authenticator or recovery code is invalid")
    account.mfa_challenge_id = None
    return _issue_tokens(
        account,
        db,
        response,
        request,
        auth_methods=[*challenge_methods, "otp"],
        action="auth.mfa_login",
    )


@router.post("/mfa/disable")
def disable_mfa(
    payload: MFADisableIn,
    request: Request,
    response: Response,
    db: DbDep,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> dict:
    account = db.get(User, user.id)
    organization = db.get(Organization, user.organization_id)
    if organization is not None and organization.mfa_required:
        raise AppError(409, "mfa_required_by_organization", "Your organization requires MFA")
    enforce_auth_rate_limit(f"mfa-disable:{user.organization_id}:{user.id}", limit=8)
    if account is None or not verify_password(payload.current_password, account.hashed_password):
        raise AppError(401, "invalid_credentials", "Current password is incorrect")
    if not _verify_mfa_code(account, payload.code):
        write_audit(
            db,
            actor_id=user.id,
            action="auth.mfa_disable_failed",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_mfa_code", "The authenticator or recovery code is invalid")
    account.mfa_secret_encrypted = None
    account.mfa_pending_secret_encrypted = None
    account.mfa_enabled_at = None
    account.mfa_recovery_code_hashes = []
    account.mfa_last_counter = None
    account.mfa_challenge_id = None
    account.token_version += 1
    for refresh in db.scalars(select(RefreshToken).where(RefreshToken.user_id == account.id)):
        refresh.revoked = True
    write_audit(
        db,
        actor_id=user.id,
        action="auth.mfa_disabled",
        target_type="user",
        target_id=str(user.id),
        ip_address=client_ip(request),
    )
    db.commit()
    response.delete_cookie("refresh_token", path="/api/v1/auth")
    return {"ok": True, "relogin_required": True}


@router.patch("/mfa/requirement")
def set_organization_mfa_requirement(
    payload: MFARequirementIn,
    db: DbDep,
    actor: Annotated[TokenUser, Depends(require_roles(ADMIN))],
    request: Request,
) -> dict:
    organization = db.get(Organization, actor.organization_id)
    account = db.get(User, actor.id)
    if organization is None or account is None:
        raise AppError(404, "not_found", "Organization not found")
    if payload.required and "otp" not in actor.auth_methods:
        raise AppError(
            403,
            "mfa_proof_required",
            "Enroll in MFA and sign in with an authenticator before requiring it "
            "for the organization",
        )
    if payload.required != organization.mfa_required:
        organization.mfa_required = payload.required
        if payload.required:
            accounts = db.scalars(
                select(User).where(User.organization_id == organization.id)
            ).all()
            for member in accounts:
                member.token_version += 1
            for refresh in db.scalars(select(RefreshToken)):
                refresh.revoked = True
        write_audit(
            db,
            actor_id=actor.id,
            action="organization.mfa_requirement_changed",
            target_type="organization",
            target_id=str(organization.id),
            ip_address=client_ip(request),
            details={"required": payload.required},
        )
        db.commit()
    return {"required": organization.mfa_required, "reauthentication_required": payload.required}


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


@router.post("/verify-password")
def verify_own_password(
    payload: MFAEnrollIn,
    request: Request,
    db: DbDep,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> dict:
    """Check the signed-in person's own password without changing anything.

    The password dialogs call this first, so a wrong password is caught before the person
    chooses a new one. It shares nothing with sign-in except the password check, and it is
    throttled per account like the other password-confirmation steps.
    """
    enforce_auth_rate_limit(f"password-verify:{user.organization_id}:{user.id}", limit=8)
    account = db.get(User, user.id)
    if account is None or not verify_password(payload.current_password, account.hashed_password):
        write_audit(
            db,
            actor_id=user.id,
            action="auth.password_verify_failed",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_credentials", "Current password is incorrect")
    return {"ok": True}


@router.post("/password", response_model=TokenResponse)
def change_own_password(
    payload: PasswordChangeIn,
    request: Request,
    response: Response,
    db: DbDep,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> TokenResponse:
    """Change the signed-in person's own password.

    The current password is required, so a stolen access token alone cannot take the account
    over. Every other session ends; this one continues with fresh tokens.
    """
    enforce_auth_rate_limit(f"password-change:{user.organization_id}:{user.id}", limit=8)
    account = db.get(User, user.id)
    if account is None or not verify_password(payload.current_password, account.hashed_password):
        write_audit(
            db,
            actor_id=user.id,
            action="auth.password_change_failed",
            target_type="user",
            target_id=str(user.id),
            ip_address=client_ip(request),
        )
        db.commit()
        raise AppError(401, "invalid_credentials", "Current password is incorrect")
    check_new_password(payload.new_password, email=account.email, current=payload.current_password)
    account.hashed_password = hash_password(payload.new_password)
    account.token_version += 1
    account.mfa_challenge_id = None
    for refresh in db.scalars(select(RefreshToken).where(RefreshToken.user_id == account.id)):
        refresh.revoked = True
    return _issue_tokens(
        account,
        db,
        response,
        request,
        auth_methods=list(user.auth_methods) or ["pwd"],
        action="auth.password_changed",
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: DbDep,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> dict:
    token = request.cookies.get("refresh_token")
    if token:
        stored = db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == _hash_token(token))
        )
        if stored:
            stored.revoked = True
    write_audit(
        db,
        actor_id=user.id,
        action="auth.logout",
        target_type="user",
        target_id=str(user.id),
        ip_address=client_ip(request),
    )
    db.commit()
    response.delete_cookie("refresh_token", path="/api/v1/auth")
    return {"ok": True}


@router.get("/me", response_model=TokenUser)
def me(user: Annotated[TokenUser, Depends(get_current_user)]) -> TokenUser:
    return user
