# SentinelAI XDR — Operations

These procedures are for a self-hosted deployment. They do not replace a production backup platform, an external security review, or a tested incident-response plan.

The API and worker images run as an unprivileged UID with Linux capabilities dropped and privilege escalation disabled. The UI container also runs as its unprivileged NGINX user and listens on port 8080 inside the container. Compose still publishes the local UI at `127.0.0.1:8080`.

## OpenID Connect single sign-on

For a self-hosted installation with one identity provider, set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_REDIRECT_URI` in the private `.env` file. Register the exact callback URI `https://<your-xdr-host>/api/v1/auth/oidc/callback` at the provider, then restart the API. The app uses Authorization Code with PKCE, validates issuer, audience, signature, nonce and a verified email claim, and only matches accounts that an administrator has already provisioned in that organization. It does not create users or grant roles from provider claims. Local TOTP MFA still runs after SSO when the user or organization requires it.

The environment configuration applies to the whole self-hosted instance and currently supports one provider. The provider must return an RS256 ID token with `email` and `email_verified: true`. Test login, account disablement and the organization's MFA policy against the actual provider before enabling SSO for users. Protect `.env` and rotate the client secret through the identity provider.

### Microsoft Entra ID

Entra never emits `email_verified`. For a tenant-specific Entra issuer (`https://login.microsoftonline.com/<tenant-id>/v2.0`) the app accepts Entra's optional claim `xms_edov: true` instead. In the app registration, open Token configuration and add the optional ID-token claims `email` and `xms_edov`; without `xms_edov` every sign-in is rejected as unverified. Multi-tenant issuers (`common`, `organizations`) are not supported.

### Account binding

The first SSO sign-in binds the local account to the provider's issuer and immutable subject (`sub`). Later sign-ins are matched by that pair, whatever the email claim says, and an email match is accepted only for an account that has never been bound. If a person's provider account is rebuilt and gets a new subject, sign-in fails with `sso_identity_mismatch` (audited); an administrator can then use "Unlink SSO" on the Users page so the next sign-in binds again. The very first sign-in still trusts the verified email, so provision SSO accounts only for addresses whose owner you know.

### Lab HTTPS front

The callback must be HTTPS. For a lab on one computer, `scripts/make_lab_tls_cert.py` writes a self-signed certificate to `.data/tls-lab/` and `docker compose --profile tls-lab up -d tls-proxy` serves the panel at `https://localhost:8443`. The browser warns about the certificate; this is expected and is not acceptable for real users. Use `OIDC_REDIRECT_URI=https://localhost:8443/api/v1/auth/oidc/callback` and open the panel at that address when signing in with SSO. The sensor controller only accepts the `http://127.0.0.1:8080` origin, so use that address for the Sensors page.

## Backups

`scripts/backup.ps1` creates a PostgreSQL custom-format dump and an archive of the shared application-data volume (uploads and model artifacts). The Compose backup job validates both archives and writes a manifest with SHA-256 hashes. The PowerShell wrapper rechecks the manifest and both hashes on the host. Backup artifacts are written to the ignored `backups/` directory and contain customer telemetry and source files; restrict access and encrypt them before sending them off the host. Protect `MFA_ENCRYPTION_KEY` separately because a database backup alone cannot decrypt enrolled TOTP secrets.

Run a backup manually:

```powershell
./scripts/backup.ps1
```

To schedule a daily 03:00 local-time backup for the current Windows user, run `./scripts/install_backup_task.ps1`. Docker Desktop must be running in that user's interactive session. Check Task Scheduler history and the latest manifest after each scheduled run. Remove the task with `./scripts/remove_backup_task.ps1`.

### Encrypted `.env` backup

The database backup does not contain `.env`. Without its keys a restored database cannot decrypt TOTP secrets, cloud connector credentials, or notification destinations. Run `./scripts/backup_env.ps1` in your own terminal after creating or changing `.env`. It asks for a passphrase of at least 12 characters twice, verifies that the result decrypts, and writes `backups/env-<timestamp>.enc` (AES-256-GCM, key derived with scrypt). The passphrase is not stored anywhere and cannot be recovered; keep it in a password manager, away from the backup files.

`./scripts/backup.ps1` warns when no encrypted copy exists or when `.env` is newer than the latest one. The encrypted file is not part of the manifest and is not uploaded by the off-site job, so it protects against losing `.env` but not against losing this disk until you copy it to other media yourself. Restore with `./scripts/restore_env.ps1`; it writes `.env.restored` and never overwrites an existing file.

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

## Adding a second sensor (lab)

Each sensor needs its own `ingestion_service` account: an account is bound to the first sensor ID and signing key that enrolls with it, and revoking a sensor disables its account. Create the account on the panel's Users page with the role "Sensor account", or with `.\scripts\create_sensor_account.ps1` in your own terminal; the script asks for the administrator password and a new sensor password and stores neither.

`.\scripts\package_sensor.ps1` writes `dist\sentinel-sensor.zip` without `sensor\runtime`, so the other machine generates its own identity. Never copy `sensor\runtime` to another machine: it holds this installation's sensor ID and private signing key.

For a VirtualBox guest, `.\scripts\sensor_lab_network.ps1 -Action Enable` (elevated) forwards the host-only address `192.168.56.1:8001` to the loopback-only API and allows only the host-only subnet through the firewall. The connection is plain HTTP and is acceptable only on a host-only network that never leaves the computer; run `-Action Disable` when finished. A sensor on a real network requires the TLS reverse proxy described in `DEPLOYMENT.md`.

## Enforced IP blocks

`block_source_ip` is the only response action that changes a system. It blocks one IP address, inbound and outbound, in the Windows Firewall of one sensor computer for a limited time.

How it runs:

1. The sensor must be started with blocking allowed: the "Allow this computer to apply approved IP blocks" box on the Sensors page, or `--enforce-blocks` on the command line. It then announces the capability `response.block_ip`. A sensor refuses this option when its server address is plain HTTP to another computer.
2. In a case, an analyst or administrator proposes "Real IP block", choosing the address, the sensor and a duration (5 minutes to 24 hours, default 60).
3. A different administrator approves within 24 hours. The requester cannot approve their own proposal, so a deployment needs at least two administrators to use this.
4. The sensor receives the block in the response to its next signed heartbeat (about ten seconds), applies it, and reports back. The server never connects to a host.
5. The block ends by itself. Any administrator, including the requester, can lift it earlier with "Lift block now". Every step is audited (`response.block.*`).

Safeguards on the sensor, applied whatever the server sends: it only adds or deletes block rules named `SentinelAI block <id>`; it refuses reserved addresses, its own addresses, its default gateways, its DNS servers and the SentinelAI server; if it cannot read that protected list it refuses; end times are kept in `sensor\runtime\response-blocks.json` and expired blocks are lifted without the server.

Limits to know before relying on it:

- A block is lifted by the sensor process. If the sensor is not running when a block expires, the firewall rule stays until the sensor next starts. To clear everything by hand, run `.\scripts\remove_sentinel_blocks.ps1` in an elevated PowerShell.
- It protects only the sensor computer, not the network; other machines can still reach the blocked address.
- A block cuts existing and new connections to that address for every program on the computer. Blocking a shared service address (a CDN, a public DNS resolver you rely on but have not configured, a VPN endpoint) can break unrelated things; the protected list only knows what the computer has configured.
- Private addresses can be blocked on purpose. Check the address is not a device you need, such as a printer or a second router.

## Enforced host isolation and local account disable

These follow the same rules as an enforced IP block (proposal, approval by a different administrator within 24 hours, delivery in the sensor's signed heartbeat response, automatic end, early lift by any administrator, audit as `response.isolation.*` and `response.account.*`). Each has its own opt-in box on the Sensors page (`--allow-isolation`, `--allow-account-disable`).

**Host isolation** (`isolate_host`, 5 minutes to 4 hours, default 30) blocks every IPv4 address and all global and unique-local IPv6 in the sensor computer's Windows Firewall, except: the SentinelAI server, the default gateway (needed for DHCP), limited broadcast, loopback, and host-internal virtual networks whose adapter name starts with `vEthernet` (Hyper-V, WSL, Docker Desktop). Right after adding the rules the sensor checks that the server still answers and removes the rules again if it does not. Only one isolation can exist. It is lifted when the sensor stops, and a newly started sensor lifts any isolation left behind.

- Everyone using that computer loses the network and the internet for the whole duration, including remote-support and cloud tools.
- The gateway itself stays reachable, so the router's own pages are not cut off.
- A sensor that is killed rather than stopped leaves the isolation in place until it starts again. `.\scripts\remove_sentinel_blocks.ps1` (elevated) removes it without a network connection; keep that in mind before isolating a machine nobody can physically reach.
- The server must have an IPv4 address; otherwise the sensor refuses.

**Local account disable** (`disable_local_account`, 5 minutes to 24 hours, default 60) runs `net user <name> /active:no` on the sensor computer and enables the account again at the end. The sensor refuses built-in accounts (Administrator, Guest and similar), the account it runs as, an account that is already disabled (so it never re-enables something an administrator turned off), the last enabled member of the local Administrators group, and any name it cannot read back from Windows. If it cannot list the accounts it refuses.

- It applies to local accounts on that one computer only, not to domain, Microsoft or Entra accounts.
- Disabling an account does not sign out a session that is already open.
- Names with non-ASCII letters are refused.

While a host is isolated, the sensor shows a message box to whoever is at the computer (Turkish and English) and another when the isolation is lifted. It appears only in an interactive Windows session; whether it appears on a given machine has not been checked. Both the sensor and the removal script judge firewall commands by their exit code, not their text, because `netsh` messages are translated on a non-English Windows.

## Sensors on other computers (lab, private certificate)

A sensor on another computer needs the server over HTTPS; without it the sensor refuses every response action. `scripts\remote_sensors.ps1` (elevated PowerShell) sets this up for one local network and controls which computers may connect.

Once, on the server computer:

```text
.\scripts\remote_sensors.ps1 -Action Setup
```

It creates a certificate valid for this computer's network address, adds firewall rules that block the HTTPS port for every other computer, binds the HTTPS front to the network (`TLS_BIND_ADDRESS=0.0.0.0` in `.env`), and builds `dist\sentinel-sensor.zip` with the public certificate inside. The firewall rules come first because Docker Desktop's own rule would otherwise let every computer on the network reach the port. After Setup nobody else can connect yet.

For each computer to add:

1. `.\scripts\remote_sensors.ps1 -Action AddComputer -Address <its address>` on the server.
2. In the panel, Sensors, "Add a sensor computer": enter a name and download `sensor-credentials.json`. The server generates the account and a random password, returns the password once and stores only its hash.
3. On that computer: install Python 3.12 and Npcap, extract the package, put `sensor-credentials.json` in the folder, run `install.ps1`, then `start.ps1 -Interface "<adapter>"` with `-AllowIpBlocks`, `-AllowIsolation` or `-AllowAccountDisable` as wanted. The sensor trusts exactly the packaged certificate (`--ca-file`) and signs in from the file (`--credentials-file`).

`-Action Status` shows the state, `RemoveComputer` withdraws a computer (revoke its sensor in the panel too), and `Disable` puts everything back on this computer only.

Limits of this arrangement: the certificate is self-signed and tied to an address that DHCP can change (run Setup again and redistribute the package if it does); an allowed computer can open the panel's sign-in page as well as the sensor API; `sensor-credentials.json` holds the sensor's password in clear text on that computer, like `.env` does here; and, outside the lab, the stack should run in production mode (see `DEPLOYMENT.md`). A real deployment needs a stable name, a certificate from a trusted authority and a separate server.

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

The Windows sensor collects selected passive network metadata and opt-in Windows Security events. It is not full EDR, and an ordinary Wi-Fi adapter does not expose all traffic on a LAN. The XDR response workflow records human-approved simulations, and three actions are executed by a sensor: an IP block, host isolation and a local account disable (see "Enforced IP blocks" and "Enforced host isolation and local account disable"). All three have been exercised only in the local lab, on one computer. ML scores and rule findings are investigation signals, not proof of compromise. A lab deployment and successful connector check do not establish commercial production readiness. Before production use, complete an isolated backup/restore rehearsal, off-host encrypted backup and recovery-key procedures, alert delivery/on-call coverage, workload and tenant-isolation validation, representative detection evaluation, and an independent security review.

## Local backup retention, backup failure alerts and certificate expiry

- `scriptsackup.ps1` keeps the newest 14 local backup sets (`-KeepLast` changes it) and deletes older `db-*`, `app-data-*` and `manifest-*` files after a verified backup. Encrypted `.env` copies are never deleted. `scripts\prune_backups.ps1 -WhatIf` shows what would go. The off-site copies in S3 follow their own 30-day rule.
- When `backup.ps1` or `offsite_backup.ps1` fails, `backups\LAST_BACKUP_FAILURE.txt` is written (the next success removes it). If `.env` contains `BACKUP_ALERT_WEBHOOK_URL=https://...` (a Slack-compatible incoming webhook; add it yourself), the same message is posted there. The message holds the script name, time and error text. A machine that is off or a Task Scheduler task that never ran cannot report anything.
- The lab HTTPS certificate is valid for 90 days. `scripts\check_cert_expiry.ps1` reports the days left and `backup.ps1` runs it. When it expires, sensors on other computers stop connecting: run `scriptsemote_sensors.ps1 -Action Setup` and redistribute the sensor package.

## Failed sign-ins

The Audit page shows failed password and single sign-on attempts of the last 24 hours (counts by kind, and the accounts and addresses with most attempts) to administrators and auditors. It reads the existing audit records (`auth.login_failed`, `auth.sso_failed`, `auth.sso_identity_mismatch`); behind the bundled HTTPS front the address is the client's only if the proxy forwards it.

## Starting the sensor at boot (untested)

`install_sensor_autostart.ps1` starts the sensor controller when you sign in; the sensor itself still has to be started from the Sensors page. `install_sensor_boot_task.ps1 -Interface "<adapter>"` (elevated) instead registers a scheduled task that runs the sensor at boot as SYSTEM and restarts it; it takes the same switches as the Sensors page (`-AllowIpBlocks`, `-AllowIsolation`, ...). It is a scheduled task, not a Windows service. It has not been run on a real computer yet; check `sensoruntimeoot-sensor.log` after a restart. Do not run it together with a sensor started from the Sensors page. Remove it with `remove_sensor_boot_task.ps1`.
