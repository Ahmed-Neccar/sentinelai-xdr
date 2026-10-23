# SentinelAI XDR — Operations

These procedures are for a self-hosted deployment. They do not replace a production backup platform, an external security review, or a tested incident-response plan.

The API and worker images run as an unprivileged UID with Linux capabilities dropped and privilege escalation disabled. The UI container also runs as its unprivileged NGINX user and listens on port 8080 inside the container. Compose still publishes the local UI at `127.0.0.1:8080`.

## OpenID Connect single sign-on

For a self-hosted installation with one identity provider, set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_REDIRECT_URI` in the private `.env` file. Register the exact callback URI `https://<your-xdr-host>/api/v1/auth/oidc/callback` at the provider, then restart the API. The app uses Authorization Code with PKCE, validates issuer, audience, signature, nonce and a verified email claim, and only matches accounts that an administrator has already provisioned in that organization. It does not create users or grant roles from provider claims. Local TOTP MFA still runs after SSO when the user or organization requires it.

The environment configuration applies to the whole self-hosted instance and currently supports one provider. The provider must return an RS256 ID token with `email` and `email_verified: true`. Test login, account disablement and the organization's MFA policy against the actual provider before enabling SSO for users. Protect `.env` and rotate the client secret through the identity provider.

## Backups

`scripts/backup.ps1` creates a PostgreSQL custom-format dump and an archive of the shared application-data volume (uploads and model artifacts). The Compose backup job validates both archives and writes a manifest with SHA-256 hashes. The PowerShell wrapper rechecks the manifest and both hashes on the host. Backup artifacts are written to the ignored `backups/` directory and contain customer telemetry and source files; restrict access and encrypt them before sending them off the host. Protect `MFA_ENCRYPTION_KEY` separately because a database backup alone cannot decrypt enrolled TOTP secrets.

Run a backup manually:

```powershell
./scripts/backup.ps1
```

To schedule a daily 03:00 local-time backup for the current Windows user, run `./scripts/install_backup_task.ps1`. Docker Desktop must be running in that user's interactive session. Check Task Scheduler history and the latest manifest after each scheduled run. Remove the task with `./scripts/remove_backup_task.ps1`.

## Restore

Restore requires the manifest for the matching database and app-data pair. It verifies both hashes and archive readability, creates a fresh pre-restore backup, asks the operator to type `RESTORE`, stops the API/worker/frontend processes, replaces the database and app-data volume, and then starts the services again. The current PostgreSQL and Redis services remain in place. Use this procedure first on an isolated copy of production data and record the achieved recovery time and data-loss window.

```powershell
./scripts/restore.ps1 -ManifestPath .\backups\manifest-YYYYMMDDTHHMMSSZ.json
```

After restore, verify `http://127.0.0.1:8001/api/v1/ready`, sign in, and inspect a representative event, case, sensor registration, and audit record. Do not treat archive/hash validation as proof that an application-level recovery drill succeeded.

## Telemetry retention

- Security events use the tenant's `retention_days` setting (default 90 days).
- Uploaded original files for completed or failed imports use the tenant's `upload_retention_days` setting (default 30 days). Administrators can choose 1–3650 days in **Settings → Imported source-file retention**.
- Daily cleanup runs at 02:15 UTC. It audits bounded deletion batches. It only unlinks a source file whose resolved parent is inside `UPLOAD_DIR`; queued/running jobs and paths outside that directory are not removed. Ingestion job metadata, detection snapshots, cases, and audit history remain available.

## Metrics scrape

Set a private `METRICS_TOKEN` (at least 32 characters in production) in `.env` and restart the API. Scrape `http://backend:8000/api/v1/metrics` from a monitoring service on the Compose network with `Authorization: Bearer <token>`. Without the token, the endpoint is disabled. The current endpoint exposes process-local HTTP request totals and duration histograms with route templates, method, and status only; it does not label metrics with tenant, user, IP, or event data.

An optional pinned Prometheus service and starter alert rules are included. Set `METRICS_TOKEN` in `.env` to a private value, then start the collector with `docker compose --profile monitoring up -d prometheus`; its UI is bound to `127.0.0.1:9090`. The scrape credential is written only to a container memory filesystem. The included alerts cover API scrape failure, server-error rate, and request latency. They do not notify anyone by themselves.

This is still not a complete monitoring service. Production operation needs alert delivery routing, durable/off-host metrics storage, and a tested on-call procedure for database/Redis health, worker backlog, ingestion lag, sensor heartbeat gaps, disk capacity, and backup failures.

## Current production boundary

TOTP MFA is implemented; identity-provider SSO is not. AWS CloudTrail, Azure Activity Log, and Entra sign-ins are file-import adapters; live polling is not implemented. The Windows sensor collects selected passive network and Windows Security signals, not full EDR coverage or whole-LAN traffic from an ordinary Wi-Fi adapter. Verify these constraints with customers and do not describe the product as full-coverage XDR or automated response.
