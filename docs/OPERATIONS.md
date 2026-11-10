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

### Encrypted off-site copy (AWS S3)

The optional `scripts/offsite_backup.ps1` creates and verifies a fresh local backup, verifies each artifact against the manifest SHA-256, uploads the database dump and app-data archive to a timestamped S3 prefix, then uploads the manifest as the completion marker. Upload requests explicitly use TLS and S3-managed SSE-S3 (`AES256`); the uploader checks remote object size, encryption, and the manifest SHA-256 metadata. The local files remain available if S3 is unreachable. S3 SSE-S3 is AWS-managed encryption at rest and does not require a separate customer key; AWS account recovery/MFA remains essential. Do not mistake this for client-side encryption: AWS services with authorized access can decrypt stored objects.

The lab bucket `sentinelai-xdr-offsite-20261024-a84f39` is provisioned in `us-east-1` with Block Public Access, Bucket owner enforced object ownership, versioning, default SSE-S3, TLS-only access, and an SSE-S3 upload requirement under `sentinelai-xdr/`. The writer policy at `infra/aws/sentinelai-backup-writer-policy.template.json` is already scoped to this exact bucket and prefix. The enabled rule `sentinelai-xdr-30-day-retention` expires current versions and permanently deletes noncurrent versions after 30 days under `sentinelai-xdr/`. Because this bucket has versioning enabled, expiring a current version creates a delete marker; that data then remains as a noncurrent version for its own 30-day retention period, so a version that stays current until day 30 can remain physically stored for about 60 days from upload. Never reuse the CloudTrail reader identity, and do not send access keys through chat or commit them.

The dedicated IAM user `sentinelai-backup-writer` has no console password and has only the customer-managed `SentinelAIBackupWriterPolicy` attached. Create its programmatic access key in AWS yourself; the secret appears only once. Configure the profile locally with `./scripts/configure_aws_backup_profile.ps1`; it prompts for the key without printing it and stores it in a separate Windows credential file with an ACL limited to the current Windows account. Never paste the key into chat or commit it. Store the one-time secret in an approved password manager for recovery/rotation, and rotate/revoke the key if exposed. The local host's S3 credential is a persistent secret; use short-lived credentials instead when a suitable unattended workload identity is available. The uploader uses the project `.venv` (which has `boto3` through backend requirements):

```powershell
./scripts/offsite_backup.ps1 -BucketName sentinelai-xdr-offsite-20261024-a84f39 -Region us-east-1 -ProfileName sentinelai-backup
./scripts/install_offsite_backup_task.ps1 -BucketName sentinelai-xdr-offsite-20261024-a84f39 -Region us-east-1 -ProfileName sentinelai-backup
```

The scheduled task runs at 03:00 local time for the current signed-in Windows user and requires Docker Desktop. Review Task Scheduler history and confirm the timestamped S3 prefix contains the database dump, app-data archive, and manifest. Restore access must be tested separately using a trusted administrator/read identity; the writer profile deliberately cannot delete objects. S3 usage is billed by storage, requests, and data transfer; SSE-S3 has no additional encryption charge. Check the AWS account's region-specific S3 pricing and billing alerts before retaining customer data there.

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

## Windows sensor identity

The Windows sensor persists its stable ID, Ed25519 private key, and monotonic request counter under the ignored `sensor/runtime/` directory. Restrict the project directory to the Windows account that runs the sensor and include this directory in the host's protected backup plan only if the private key is treated as a secret. The API pins the public key on the sensor's first authenticated start and verifies signed live requests; credential rotation clears the pin so the next start can enroll the current local key again. Losing the private key or counter state requires administrator credential rotation before that sensor can resume.

When updating an existing installation, rebuild/restart the API so migration 009 runs, then update the sensor environment with `sensor/.venv/Scripts/python.exe -m pip install -r sensor/requirements.txt` and restart the elevated local controller. Existing registrations are upgraded by the next sensor start; older sensor binaries cannot send signed requests. The request counter rejects replayed requests. First-use pinning is not hardware attestation, and administrator-controlled host access remains trusted.

## Metrics scrape

Set a private `METRICS_TOKEN` (at least 32 characters in production) in `.env` and restart the API. Scrape `http://backend:8000/api/v1/metrics` from a monitoring service on the Compose network with `Authorization: Bearer <token>`. Without the token, the endpoint is disabled. The current endpoint exposes process-local HTTP request totals and duration histograms with route templates, method, and status only; it does not label metrics with tenant, user, IP, or event data.

An optional pinned Prometheus service and starter alert rules are included. Set `METRICS_TOKEN` in `.env` to a private value, then start the collector with `docker compose --profile monitoring up -d prometheus`; its UI is bound to `127.0.0.1:9090`. The scrape credential is written only to a container memory filesystem. The included alerts cover API scrape failure, server-error rate, and request latency. They do not notify anyone by themselves.

This is still not a complete monitoring service. Production operation needs alert delivery routing, durable/off-host metrics storage, and a tested on-call procedure for database/Redis health, worker backlog, ingestion lag, sensor heartbeat gaps, disk capacity, and backup failures.

## Alert notifications

Administrators add channels under **Notifications** (API: `/api/v1/notification-channels`). Three kinds are supported: a generic JSON webhook (optionally signed), a Slack-compatible incoming webhook (`{"text": ...}`), and a Telegram bot (`bot_token` plus `chat_id`). E-mail is not implemented. Each channel has a minimum severity (default `high`); a new detection at or above it queues one message per channel. Analysts can read channel status; only administrators can create, change, test, or delete channels, and every change is audited.

A message contains the finding title, severity, rule ID, detector kind, detection and case IDs, and a note that it is a review signal. The finding summary can contain IP addresses, host names, and account names and is omitted unless **Include the finding summary** is enabled for that channel. Raw events are never sent. Treat any enabled channel as a transfer of that data to the receiving service.

Delivery uses a database outbox: the queue row is written in the same transaction as the detection and Celery Beat triggers delivery every 30 seconds, so expect up to about 30 seconds of delay. A failed send is retried with backoff (1, 2, 4, 8 minutes) and marked failed after five attempts, with an audit record. Messages still unsent after 24 hours are dropped. At most 20 messages per organization are sent per run; a burst of findings is delivered over several runs, not discarded. Delivery history is kept for 30 days. Delivery is at-least-once: a receiver can see a duplicate if a send succeeded but its result could not be recorded.

Destinations are stored encrypted with `CLOUD_CONNECTOR_ENCRYPTION_KEY` and never returned by the API. Requests are HTTPS only, do not follow redirects, and are refused when the host is an IP literal or resolves to a non-public address, so a channel cannot target loopback, the Compose network, or cloud metadata endpoints. The worker container therefore needs outbound HTTPS and DNS. For the generic webhook with a signing secret, verify `X-Sentinel-Signature: sha256=<hex>` as HMAC-SHA256 over `<X-Sentinel-Timestamp>.<raw body>` and reject old timestamps.

Use **Send test** after creating a channel and confirm the message arrives. This covers detection alerts only: it does not report sensor heartbeat gaps, connector failures, failed backups, or service health, and it is not an on-call rota or escalation system.

## Current production boundary

TOTP MFA and single-provider OIDC SSO are implemented. OIDC still requires validation against the operator's real identity provider, including account disablement and MFA policy. Read-only polling foundations exist for AWS CloudTrail, Azure Activity Log, and Microsoft Entra sign-ins. AWS CloudTrail polling and event visibility have been exercised in the local lab; Azure and Entra live polling still require separate test tenants and end-to-end validation. Provider access is read-only, but operators must verify the exact permissions, licensing, retention, and credential rotation for their accounts.

The Windows sensor collects selected passive network metadata and opt-in Windows Security events. It is not full EDR, and an ordinary Wi-Fi adapter does not expose all traffic on a LAN. The XDR response workflow records human-approved simulations; it does not isolate hosts, block addresses, or disable accounts. ML scores and rule findings are investigation signals, not proof of compromise. A lab deployment and successful connector check do not establish commercial production readiness. Before production use, complete an isolated backup/restore rehearsal, off-host encrypted backup and recovery-key procedures, alert delivery/on-call coverage, workload and tenant-isolation validation, representative detection evaluation, and an independent security review.
