"""Create a dedicated ingestion_service account for one additional sensor.

Every sensor needs its own account: an account is bound to the first sensor
that enrolls with it, and revoking a sensor disables its account. The panel
has no user-management screen, so this tool calls the audited API instead.

All secrets are read interactively and are never stored, logged, or accepted
on the command line.
"""

from __future__ import annotations

import argparse
import getpass
import sys

import httpx

MIN_PASSWORD = 12


class AccountError(Exception):
    """A user-facing failure; the message never contains a secret."""


def _detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    for key in ("message", "detail", "error"):
        value = body.get(key) if isinstance(body, dict) else None
        if isinstance(value, dict):
            value = value.get("message")
        if isinstance(value, str):
            return f"HTTP {response.status_code}: {value[:200]}"
    return f"HTTP {response.status_code}"


def administrator_token(
    client: httpx.Client, email: str, password: str, organization: str, read_code
) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password, "organization_slug": organization},
    )
    if response.is_error:
        raise AccountError(f"Administrator sign-in failed ({_detail(response)}).")
    body = response.json()
    if body.get("mfa_required"):
        if body.get("mfa_setup_required"):
            raise AccountError("This administrator must finish MFA setup in the panel first.")
        response = client.post(
            "/api/v1/auth/mfa/verify",
            json={"challenge_token": body["challenge_token"], "code": read_code()},
        )
        if response.is_error:
            raise AccountError(f"MFA verification failed ({_detail(response)}).")
        body = response.json()
    if "administrator" not in body.get("user", {}).get("roles", []):
        raise AccountError("Only an administrator can create sensor accounts.")
    return str(body["access_token"])


def create_sensor_account(
    client: httpx.Client,
    token: str,
    email: str,
    password: str,
    full_name: str,
    role: str = "ingestion_service",
) -> dict:
    if len(password) < MIN_PASSWORD:
        raise AccountError(f"The sensor password must be at least {MIN_PASSWORD} characters.")
    response = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "email": email,
            "password": password,
            "full_name": full_name,
            "roles": [role],
        },
    )
    if response.status_code == 409:
        raise AccountError(f"An account named {email} already exists; choose another email.")
    if response.is_error:
        raise AccountError(f"The account was not created ({_detail(response)}).")
    created = response.json()
    if created.get("roles") != [role]:
        raise AccountError("The server returned unexpected roles; check the audit log.")
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", default="http://127.0.0.1:8001")
    parser.add_argument("--organization", default="default")
    parser.add_argument("--admin-email", default="admin@localhost.local")
    parser.add_argument("--sensor-email", default="sensor-vm@localhost.local")
    parser.add_argument("--full-name", default="")
    parser.add_argument(
        "--role",
        default="ingestion_service",
        choices=("ingestion_service", "analyst", "auditor"),
        help="analyst or auditor provisions a person, for example for SSO sign-in",
    )
    args = parser.parse_args()

    try:
        print(f"Creating sensor account {args.sensor_email} on {args.server}")
        admin_password = getpass.getpass(f"Password for {args.admin_email}: ")
        sensor_password = getpass.getpass(
            f"New password for {args.sensor_email} (12+ characters): "
        )
        if len(sensor_password) < MIN_PASSWORD:
            raise AccountError(f"The sensor password must be at least {MIN_PASSWORD} characters.")
        if getpass.getpass("Repeat the new sensor password: ") != sensor_password:
            raise AccountError("The sensor passwords do not match; nothing was created.")
        with httpx.Client(base_url=args.server.rstrip("/"), timeout=15.0) as client:
            token = administrator_token(
                client,
                args.admin_email,
                admin_password,
                args.organization,
                lambda: input("Authenticator code: ").strip(),
            )
            created = create_sensor_account(
                client, token, args.sensor_email.lower(), sensor_password, args.full_name, args.role
            )
            client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        print(f"Created {created['email']} with role {args.role} (id {created['id']}).")
    except AccountError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except httpx.HTTPError as error:
        print(f"Error: cannot reach {args.server} ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
