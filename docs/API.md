# SentinelAI XDR — API Contract (`/api/v1`)

Base URL (Compose): `http://127.0.0.1:8001/api/v1` (the UI is at `http://127.0.0.1:8080`). For a host-side backend, the default port is `8000`.

Interactive docs in Compose: `http://127.0.0.1:8001/docs` (OpenAPI). For a host-side backend, use `http://127.0.0.1:8000/docs`. Disable or restrict in any non-lab deployment.

## Conventions

- JSON request/response; UTC ISO-8601 timestamps
- Errors: `{ "error": { "code": "string", "message": "string", "details": {} } }`
- Pagination: `page` (1-based), `page_size` (max 100), response `{ items, page, page_size, total }`
- Auth: `Authorization: Bearer <access_token>` and/or refresh cookie
- No stack traces in bodies
- Rate limits: login and ingest are stricter than read endpoints

## Status codes

| Code | When |
|------|------|
| 200 | Success |
| 201 | Created |
| 202 | Job accepted |
| 204 | No content |
| 400 | Validation / malformed |
| 401 | Unauthenticated |
| 403 | Authenticated but forbidden |
| 404 | Missing |
| 409 | Conflict (duplicate idempotency / dedup) |
| 413 | Payload too large |
| 422 | Schema validation |
| 429 | Rate limited |
| 503 | Dependency not ready |

## Endpoints

### Health

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/health` | none | Liveness |
| GET | `/ready` | none | DB (and Redis if configured) |
| GET | `/metrics` | `Authorization: Bearer $METRICS_TOKEN` | Optional process-local Prometheus metrics; disabled when no token is configured |

### Auth

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/auth/login` | none | organization slug + email/password; returns access token or a five-minute MFA challenge |
| POST | `/auth/refresh` | refresh cookie or body | rotates the refresh token and issues an access token; refused with `session_expired` once the sign-in is older than `SESSION_MAX_HOURS` |
| POST | `/auth/verify-password` | user | check the caller's own password (`current_password`) without changing anything; 401 `invalid_credentials` if wrong |
| POST | `/auth/password` | user | change the caller's own password; needs `current_password`, applies the password policy, ends every other session and returns fresh tokens for this one |
| POST | `/auth/logout` | user | invalidates refresh family |
| GET | `/auth/me` | user | current user + roles |
| GET | `/auth/oidc/status` | none | whether single sign-on is configured, and the origin it uses |
| GET | `/auth/oidc/start` | none | begin the OIDC authorization-code flow with PKCE |
| GET | `/auth/oidc/callback` | provider redirect | finish sign-in; only accounts an administrator already created can sign in |
| GET | `/auth/mfa/status` | user | enrollment and organization policy status |
| POST | `/auth/mfa/enroll` | user | verify current password and begin TOTP setup |
| POST | `/auth/mfa/enable` | user | verify TOTP, enable MFA, and return one-time recovery codes |
| POST | `/auth/mfa/setup` | MFA challenge | begin required organization TOTP setup |
| POST | `/auth/mfa/setup/confirm` | MFA challenge + TOTP | finish required setup and return one-time recovery codes |
| POST | `/auth/mfa/verify` | MFA challenge + TOTP/recovery code | complete second-factor sign-in |
| POST | `/auth/mfa/disable` | user + password + TOTP/recovery code | disable personal MFA unless organization policy requires it |
| PATCH | `/auth/mfa/requirement` | administrator + MFA-authenticated session | require or stop requiring MFA for the organization; enabling revokes sessions |

MFA uses TOTP authenticator apps. TOTP secrets are encrypted with `MFA_ENCRYPTION_KEY` in production; recovery codes are stored as keyed hashes and are shown only once. Configure and back up the separate encryption key before deployment. This is not SSO or identity-provider federation.

### Users (admin)

| Method | Path | Auth |
|--------|------|------|
| GET | `/users` | administrator |
| POST | `/users` | administrator |
| PATCH | `/users/{id}` | administrator | Change name, roles, active flag or someone else's password (`password` plus `confirm_password`, the administrator's own password; an administrator cannot set their own password here, use `POST /auth/password`); `unlink_sso` forgets the bound SSO identity. The last active administrator cannot be disabled or demoted |
| GET | `/identity/settings` | administrator | SSO provisioning switches, group-to-role mappings, SCIM tokens (never the token itself) |
| PUT | `/identity/settings` | administrator | `auto_provision`, `sync_roles`, `default_role` (never administrator) |
| POST | `/identity/mappings` | administrator | map a groups/roles claim value to a role |
| DELETE | `/identity/mappings/{id}` | administrator | remove a mapping |
| POST | `/identity/scim-tokens` | administrator | create a SCIM token; shown once, only its hash is stored |
| DELETE | `/identity/scim-tokens/{id}` | administrator | revoke a SCIM token |
| POST | `/users/{id}/sign-out` | administrator | end every session of one account at once |
| GET, POST, PUT, PATCH, DELETE | `/scim/v2/Users[/{id}]` | SCIM bearer token | SCIM 2.0 provisioning: list with `userName eq` / `externalId eq` filters, create, replace, patch (`active`, `displayName`, `name.*`, `externalId`, `roles`), delete = disable. A SCIM token never grants the administrator role |
| GET | `/scim/v2/ServiceProviderConfig`, `/scim/v2/Groups` | SCIM bearer token (Groups) | capabilities; Groups is always empty |

### Data sources

| Method | Path | Auth |
|--------|------|------|
| GET | `/data-sources` | analyst+ |
| POST | `/data-sources` | administrator |
| GET | `/data-sources/{id}` | analyst+ |
| PATCH | `/data-sources/{id}` | administrator |

### Ingestion

| Method | Path | Auth |
|--------|------|------|
| POST | `/ingest/upload` | admin, analyst |
| POST | `/ingest/live/start` | admin, analyst, ingestion_service | Start a live sensor session. Sensor-only credentials must provide an ID; first registration binds the ID and data source to that account. A credential cannot claim a different ID/source or start a second recent session. |
| POST | `/ingest/live/{id}/heartbeat` | admin, analyst, ingestion_service | Refresh a running session heartbeat; ingestion-only users may update only sessions they created |
| POST | `/ingest/live/{id}/events` | admin, analyst, ingestion_service | Accept a batch of at most 100 normalized live records; ingestion-only users may write only to sessions they created |
| POST | `/ingest/live/{id}/finish` | admin, analyst, ingestion_service | Finish a live sensor session; ingestion-only users may finish only sessions they created |
| GET | `/ingest/live/sessions` | admin, analyst, ingestion_service | List recent sessions; ingestion-only users see only sessions they created |
| POST | `/ingest/live/{id}/actions/{action_id}/result` | ingestion_service | A sensor reports that it applied, refused, failed or lifted an action (signed request) |
| POST | `/ingest/live/sensors/enrollment` | administrator | Create a dedicated sensor account with a generated password, returned once |
| GET | /ingest/live/sensors | administrator | List up to 500 registered sensor identities and health fields |
| POST | /ingest/live/sensors/{sensor_id}/revoke | administrator | Revoke credential, invalidate tokens, and close server sessions; the host process exits after its next denied heartbeat |
| POST | /ingest/live/sensors/{sensor_id}/rotate-credential | administrator | Set a new credential password; update host .env and restart its controller |
| GET | `/ingest/jobs` | analyst+ |
| GET | `/ingest/jobs/{id}` | analyst+ |
| GET | `/ingest/jobs/{id}/quarantine` | analyst+ |

Upload adapters: `generic_json`, `generic_csv`, `zeek_json`, `suricata_eve`, `aws_cloudtrail`, `azure_activity`, and `entra_signin`. The AWS/Azure/Entra adapters import provider export files only; they do not poll live cloud APIs. See `docs/CLOUD_INGESTION.md` for input shapes and privacy boundaries. Upload constraints (defaults, overridable in settings): 10 MiB, 20_000 rows, extensions `.json`, `.csv`, `.log`.

Idempotency: optional header `Idempotency-Key`. Duplicate keys return the original job.

Live capture is supplied by the optional Windows sensor, not by the Docker containers. It records only passive IP/port/protocol/time metadata exposed by the selected host adapter; it does not capture payloads or provide whole-LAN visibility by itself. See `sensor/README.md`.

### Events

| Method | Path | Auth |
|--------|------|------|
| GET | `/events` | analyst+ / auditor |
| GET | `/events/{id}` | analyst+ / auditor |

Filters: `event_type`, `src_ip`, `dst_ip` (an invalid address returns 400 `invalid_ip`), `host_id`, `severity`, `from`, `to` (ISO-8601; URL-encode the `+` of an offset), `q` (substring of event type or host id; slow on large tables).

### Hosts (telemetry-derived)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/hosts` | analyst+ / auditor | Host labels aggregated from received events; not a managed-agent inventory |
| GET | `/hosts/{host_id}` | analyst+ / auditor | Event counts/types, 25 recent events, related detections |

The UI's “recent data” indicator is computed from the last event timestamp; it is not a sensor heartbeat.

### Detections

| Method | Path | Auth |
|--------|------|------|
| GET | `/detections` | analyst+ / auditor |
| GET | `/detections/{id}` | analyst+ / auditor |

### Rules

| Method | Path | Auth |
|--------|------|------|
| GET | `/rules` | analyst+ / auditor |
| GET | `/rules/{id}` | analyst+ / auditor |
| PATCH | `/rules/{id}` | administrator (enable/disable) |
| GET | `/rules/{id}/versions` | analyst+ / auditor |

### Cases

| Method | Path | Auth |
|--------|------|------|
| GET | `/cases` | analyst+ / auditor |
| GET | `/cases/assignees` | analyst+ / auditor; returns active analyst/administrator identity fields for assignment controls |
| POST | `/cases` | analyst, administrator |
| GET | `/cases/{id}` | analyst+ / auditor |
| PATCH | `/cases/{id}` | analyst, administrator |
| POST | `/cases/{id}/comments` | analyst, administrator |
| GET | `/cases/pending-approvals` | analyst+ / auditor | Response proposals waiting for approval |
| POST | `/cases/{id}/responses` | analyst, administrator | Propose a response. `simulate_*` types are audit records only. `block_source_ip`, `isolate_host` and `disable_local_account` are executed by the chosen sensor after approval |
| POST | `/cases/{id}/responses/{response_id}/approve` | administrator | Approve (simulations within 7 days, executed actions within 24 hours); the requester cannot approve their own |
| POST | `/cases/{id}/responses/{response_id}/reject?note=...` | administrator | Reject a proposal with an optional note; requester cannot self-review |
| POST | `/cases/{id}/responses/{response_id}/simulate` | administrator | Record a simulation after approval; no endpoint is contacted |
| POST | `/cases/{id}/responses/{response_id}/unblock` | administrator | Lift an executed action early (any administrator, including the requester) |
| GET | `/cases/{id}/history` | analyst+ / auditor |

Case updates accept `status`, `severity`, `priority` (`p1`–`p4`), and `assigned_to`. Assignment may be set to an active analyst/administrator UUID or cleared with `null`; invalid priorities, severities, and inactive/non-analyst assignees are rejected. Case mutations are audited.

Auditor is read-only. Simulations are audit records only. The three executed actions are applied by an enrolled sensor to its own computer, for a limited time, after a different administrator approves; the server never contacts a host (see `docs/OPERATIONS.md` and `docs/THREAT_MODEL.md`).

### Notification channels

| Method | Path | Auth |
|--------|------|------|
| GET | `/notification-channels` | administrator, analyst |
| POST | `/notification-channels` | administrator |
| PATCH | `/notification-channels/{id}` | administrator |
| DELETE | `/notification-channels/{id}` | administrator |
| POST | `/notification-channels/{id}/test` | administrator |

Kinds: `webhook`, `slack`, `telegram`. The destination is HTTPS only, stored encrypted and never returned. Messages cover new findings above the channel's minimum severity, response workflow events, silent sensors and failing cloud connectors. Delivery is asynchronous (about 30 seconds) with retries.

### Cloud connectors

| Method | Path | Auth |
|--------|------|------|
| GET | `/cloud-connectors` | administrator, analyst |
| POST | `/cloud-connectors` | administrator |
| PUT | `/cloud-connectors/{id}` | administrator (replace configuration and credentials; refused while a poll is running) |
| PATCH | `/cloud-connectors/{id}` | administrator (enable or pause) |
| DELETE | `/cloud-connectors/{id}` | administrator (revoke: erases the stored credentials) |
| POST | `/cloud-connectors/{id}/poll` | administrator (queue a poll now) |

Providers: `aws_cloudtrail`, `azure_activity`, `entra_signin`. Credentials are encrypted and never returned; responses only say whether they are configured. Polling is read-only.

### Models (evaluation artifacts)

| Method | Path | Auth |
|--------|------|------|
| GET | `/models` | analyst+ / auditor |
| GET | `/models/{id}` | analyst+ / auditor |
| GET | `/models/{id}/evaluation` | analyst+ / auditor |

Training is **CLI only** (`python -m app.detection.ml.train`). Not exposed as a POST in v1.

### Dashboard, reports, audit, settings

| Method | Path | Auth |
|--------|------|------|
| GET | `/dashboard/summary` | analyst+ / auditor |
| GET | `/reports/summary` | analyst+ / auditor |
| GET | `/system/health` | analyst+ / auditor | Sensors online and silent, cloud connector health, notification queue and failures (the Overview page's health card) |
| GET | `/audit-logs` | administrator, auditor |
| GET | `/audit-logs/sign-in-security` | administrator, auditor | Failed password and SSO sign-ins in the last `hours` (default 24): counts by kind and the accounts and addresses with most attempts |
| GET | `/settings` | authenticated (safe subset) |
| PATCH | `/settings` | administrator |

Settings are tenant-scoped. Administrators may update event and imported source-file retention (1–3650 days). Original files from completed/failed imports default to 30 days and are removed by the daily retention task; queued/running jobs are excluded.

The protected `/metrics` endpoint reports per-process HTTP request totals and latency histograms by method, route template, and status. It does not expose tenant/user labels. Configure a private token of at least 32 characters in production and scrape it only from a trusted monitoring network. The application does not provide the metrics collector, alert delivery, or on-call service.

## Role matrix (server-enforced)

| Role | Ingest | Investigate cases | Enable rules | Users | Audit |
|------|--------|-------------------|--------------|-------|-------|
| administrator | yes | yes | yes | yes | yes |
| analyst | yes | yes | no | no | no |
| auditor | no | read | read | no | yes |
| ingestion_service | yes | no | no | no | no |

## Token lifecycle

- Access JWT: 15 minutes, `sub` = user id, `roles` claim
- Refresh: 8 hours per token, httpOnly, `SameSite=Lax`, path `/api/v1/auth`. Rotation keeps the original sign-in time (`sat` claim), so a session ends at most `SESSION_MAX_HOURS` (default 12) after the sign-in however often it is refreshed
- Logout increments token version / deletes refresh row
- Documented: do not store access tokens in localStorage
