# SentinelAI XDR — Threat Model

Last reviewed against the code on 2026-11-14. This is the author's own analysis, not an independent review. "Mitigation" means a control that exists in the code or configuration and, where noted, has an automated test; it does not mean the risk is gone.

## System statement

SentinelAI XDR is a self-hosted monitoring and response tool for a lab or small environment. It processes untrusted telemetry, holds credentials for cloud accounts and notification services, and can make three real changes on a sensor computer (an IP block, a network isolation of that computer, and disabling one local account). It must not become an attack pivot, a credential dump, or an unsupervised automation engine.

## Assets

- Analyst credentials, MFA factors, session and refresh tokens, SSO identity bindings
- Role assignments and the organization boundary (row-level security)
- Imported and live telemetry (internal IPs, host names, user names)
- Detection evidence, case notes, response proposals and approvals
- Audit log integrity
- `.env`: signing key, MFA and connector encryption keys, database passwords, OIDC client secret
- Cloud connector credentials and notification destinations (encrypted in the database)
- Sensor identity: each sensor's Ed25519 private key and request counter, and its account password (`sensor-credentials.json` on remote computers)
- The enforcement capability itself: whoever can get a sensor to apply an action can cut a computer off the network
- Backups (database dump, application data, encrypted `.env` copy, S3 objects)
- Model artifacts (the anomaly model is not deployed)

## Actors

- Administrator, analyst, auditor, ingestion service (machine account)
- A second administrator, as a control: approval of real response actions
- Unauthenticated peer on the same network (the HTTPS front can be bound to the LAN)
- Compromised or malicious sensor, or a crafted telemetry file
- Curious insider with a lower-privilege role
- Another organization in the same installation (tenant)
- Someone with access to a sensor computer or to the server computer

## Assumptions

- The Docker host and the person with administrator rights on it are trusted. Anyone who can read the project folder can read `.env`, the local backups and the sensor key.
- The database and Redis are reachable only on the Compose network (plain, unauthenticated Redis; database on loopback for the host).
- Published ports are loopback by default. The HTTPS front can be bound to the LAN, and then only computers allowed through the Windows Firewall rules created by `scripts/remote_sensors.ps1` can reach it.
- Operators change the placeholder administrator password before switching to production mode (the switch script refuses otherwise).

## STRIDE summary

| Threat | Example | Mitigations (tested unless marked) |
|---|---|---|
| Spoofing | Stolen or forged token, password guessing, account discovery | Short-lived access tokens; refresh rotation with revocation; token version bumped on password reset or change; absolute session limit (`SESSION_MAX_HOURS`, default 12) enforced across refresh rotation; the interface signs out after 30 idle minutes; own password change needs the current password and ends other sessions; an administrator resetting someone else's password must confirm with their own; password policy (12+ characters, no common words, not the account name); token type and organization checked; Argon2; throttling per address (20/5 min) and per account (12/5 min), Redis-backed outside development; unknown and inactive accounts cost the same time as real ones; optional enforced TOTP MFA; OIDC with PKCE, nonce and verified-email checks and binding to issuer and subject; SSO account creation off by default and only with a role mapped from the person's groups; SCIM tokens are per organization, stored as hashes, revocable, and cannot grant the administrator role; an identity provider that disables someone ends their sessions at once; the last active administrator cannot be removed by SCIM or by group sync; a replaced refresh token that is presented again more than 15 seconds later ends the whole session (theft signal; two tabs racing within seconds are only refused); the audit log can be copied to an outside collector as it grows (HTTPS, public host name only, no redirects, optional HMAC), so removing the newest rows becomes visible; each person can see and end their own sessions, and an ended session stops working at once (the access token carries a session id that is checked on every request) |
| Spoofing (sensor) | A process pretending to be a sensor, replayed requests | Dedicated `ingestion_service` account per sensor; each live request signed with the sensor's Ed25519 key (first use pinned); monotonic request counter rejects replays; revocation disables the account; over a network the sensor must use HTTPS and trusts only the pinned certificate. Not hardware-backed: whoever copies `sensor\runtime` or the credentials file can impersonate the sensor |
| Tampering | Edited findings, changed rules, altered audit rows | Rule versioning; audit records for administrative actions; application role has no DDL rights; migrations through Alembic. The audit table is not cryptographically chained, and a database administrator can edit it |
| Repudiation | "I did not approve that block" | Audit events with actor, action, target and address; proposals, approvals, applications and lifts are separate records |
| Information disclosure | Cross-tenant reads, secrets in responses or logs, stack traces | PostgreSQL row-level security (forced) with a non-superuser runtime role; API-level isolation test across two organizations; connector and channel secrets encrypted and never returned; generic error bodies; CSV formula escaping; sensors send only selected fields |
| Denial of service | Large uploads, floods, slow queries | Size and row limits, pagination caps, throttling. Not covered: no network-level rate limiting or WAF; text search and the host inventory scan the organization's events; one API process by default |
| Elevation of privilege | Role self-assignment, last administrator removal | Server-side role checks on every route (tested per role); the last active administrator cannot be removed or disabled; the requester of a real response action cannot approve it |
| Server-side request forgery | A notification channel pointed at an internal address | Destinations are HTTPS only, no redirects, refused when the host is an IP literal or resolves to a non-public address |
| Supply chain | Vulnerable or tampered dependencies | Hash-pinned lock installed with `--require-hashes`; weekly audit in CI and Dependabot (not yet run on GitHub); base images referenced by tag, not digest |

## Untrusted input

Treat as hostile: imported JSON, CSV, Zeek and Suricata files; event fields (`message`, `query`, command lines if present); case comments; sensor-reported diagnostics; file names; and everything a cloud provider returns. Parsers do not evaluate content or follow attacker-controlled paths; uploads are written under a generated name inside the upload directory; quarantined rows keep only a bounded sample.

## Response safety

Real actions exist, so the control is the workflow, not an absence of capability:

1. Only three action types are executable: `block_source_ip`, `isolate_host`, `disable_local_account`. Everything else is an audit-only simulation.
2. A proposal needs a case, a target, a chosen sensor and a duration; a **different administrator** must approve within 24 hours; the requester cannot approve their own.
3. The server never connects to a computer. The sensor receives an approved action in the response to its signed heartbeat and applies it to itself.
4. A sensor must have been started with the matching opt-in (`--enforce-blocks`, `--allow-isolation`, `--allow-account-disable`), and refuses network enforcement over plain HTTP to another computer.
5. Safeguards in the sensor, applied whatever the server sends: it only touches rules named `SentinelAI block/isolate <id>`; it refuses reserved addresses, its own and its gateways', its DNS servers and the SentinelAI server; isolation verifies the server stays reachable and rolls back otherwise, allows one isolation at a time and caps it at 4 hours; account disable refuses built-in accounts, its own account, already-disabled accounts and the last enabled administrator.
6. Every action is time-limited and lifted by the sensor on expiry, when the sensor stops, or when it starts again; any administrator can lift it early. Everything is audited and notified.

Residual risks: a compromised administrator account plus a second compromised administrator can cut off any opted-in computer; a sensor killed instead of stopped leaves an isolation until it restarts (`scripts/remove_sentinel_blocks.ps1` removes it locally); a block can break unrelated services that share an address; a VPN client can extend an isolation (observed once). Only one computer, a lab, has run these actions.

## Network exposure

Loopback by default. For remote sensors, `scripts/remote_sensors.ps1` binds the HTTPS front to the LAN address and first adds Windows Firewall block rules for every other computer, because Docker Desktop's own rule would otherwise let the whole network in (confirmed from a phone). An allowed computer can reach the panel's sign-in page as well as the sensor API. The certificate is self-signed, valid 90 days and tied to one address; it expires silently for sensors unless `scripts\check_cert_expiry.ps1` is watched.

## Containers

API, worker, scheduler, frontend and HTTPS front run as unprivileged users with all capabilities dropped, `no-new-privileges` and a read-only root filesystem. Not done: CPU and memory limits, image digests, seccomp profiles, a Redis password, TLS between containers.

## Explicit non-goals and residual risk

- Not a full EDR: no process, file or memory telemetry beyond selected Windows Security events; an ordinary Wi-Fi adapter does not see the LAN.
- No independent penetration test or code review.
- Detection rules and ATT&CK mappings are hypotheses; none has been evaluated on real telemetry. The anomaly score is not a probability and is not deployed.
- Single host: no high availability, and the host's disk holds the database, the keys and the local backups.
- Local backups are not encrypted (only the `.env` copy is); S3 objects use provider-managed encryption.
- `.env` and `sensor-credentials.json` hold secrets in clear text, protected by file permissions only. `.data\env-before-production-*` copies, if kept, hold the old secrets.
- The sensor may run as SYSTEM through the boot task (untested); a compromise of that account is a compromise of the host.
- First-use pinning of a sensor's key trusts the first enrollment.

## Secrets handling

- `.env` is git-ignored; `.env.example` holds placeholders. The production switch generates a 96-character signing key, an MFA key and three database passwords without displaying them, keeps the existing connector key, and refuses to run while a placeholder administrator password still works.
- Production mode refuses to start with weak or missing keys, non-HTTPS origins or placeholder passwords.
- TOTP secrets, connector credentials and notification destinations are encrypted with separate keys from `.env`; recovery codes are keyed hashes; losing the keys makes the stored secrets unreadable, so an encrypted `.env` backup (`scripts\backup_env.ps1`) is part of recovery.
- The bootstrap administrator is created only while the user table is empty, and its password line is cleared from `.env` by the production switch.
