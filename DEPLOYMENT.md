# SentinelAI XDR — Deployment Guide

This guide covers installing SentinelAI XDR from nothing, configuring it, the hardening that is built in, what you must add yourself, upgrades, and recovery.

**Read this first.** The project is a lab prototype. The Compose file is a single-host deployment that binds to loopback. Production mode enforces strong configuration, but TLS termination, alerting for system health, high availability, and an independent security review are not provided. Section 10 lists what is missing. Do not put customer data in a deployment until those gaps are closed for your environment.

## 1. Requirements

| Item | Requirement |
|---|---|
| Host | 64-bit Linux or Windows with Docker Engine/Desktop and Compose v2 |
| Memory | 4 GB free as a minimum. The worker used 1.9 GB with 160,000 events in the two-hour detection window (see the load-test record) |
| Disk | Database and uploads grow with telemetry; local backups add about one database dump plus one data archive per run |
| Outbound network | Only if used: cloud provider APIs (cloud connectors), notification destinations, the OIDC issuer, Amazon S3 (off-site backup) |
| Sensor host | Windows 10/11, Npcap, Python 3.12 (see `sensor/README.md`) |
| Tools on the host | PowerShell for the scripts in `scripts/`; a Python 3.12 virtual environment at `.venv` with `backend/requirements.txt` for the off-site uploader and the `.env` backup tool |

## 2. Services

`docker compose up` starts the following. Only three ports are published, all on 127.0.0.1.

| Service | Purpose | Published port | Notes |
|---|---|---|---|
| `postgres` | PostgreSQL 16 | 127.0.0.1:5432 | Data in volume `postgres_data` |
| `redis` | Celery broker and results | none | Volume `redis_data`; no password, reachable only inside the Compose network |
| `db-provision` | One-shot: creates the runtime and migrator roles | — | Uses the bootstrap superuser |
| `db-migrate` | One-shot: `alembic upgrade head` | — | Uses the non-superuser `sentinel_migrator` role |
| `app-data-init` | One-shot: fixes ownership of the data volume | — | Runs as root with three capabilities, then exits |
| `backend` | FastAPI API | 127.0.0.1:8001 | Runs as UID 10001, all capabilities dropped |
| `worker` | Celery worker: ingestion, cloud polling, notifications, retention | none | Same image as the API |
| `celery-beat` | Scheduler | none | Retention 02:15 UTC, cloud polling every 5 min, notifications every 30 s |
| `frontend` | NGINX serving the console and proxying `/api` | 127.0.0.1:8080 | Unprivileged NGINX |
| `backup`, `restore` | Operations profile, run on demand by the scripts | — | |
| `prometheus` | Optional, `--profile monitoring` | 127.0.0.1:9090 | Needs `METRICS_TOKEN` |

The API and worker connect as `sentinel_runtime`, which is not a superuser and cannot bypass row-level security. They never receive the migrator or bootstrap passwords.

## 3. Configuration

All configuration is in `.env` in the repository root. It is ignored by Git. Copy `.env.example` and set the values below.

### Generating secrets

Use a cryptographic generator. With Docker available:

```text
docker run --rm python:3.12-slim python -c "import secrets; print(secrets.token_urlsafe(48))"
docker run --rm python:3.12-slim python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

The first form is for passwords and `SECRET_KEY`. The second produces the 32-byte URL-safe base64 keys required for `MFA_ENCRYPTION_KEY` and `CLOUD_CONNECTOR_ENCRYPTION_KEY`; keep the trailing `=`. Generate each value separately. The two encryption keys must differ.

### Variables

| Variable | Required | Purpose |
|---|---|---|
| `SENTINEL_ENV` | yes | `development` or `production`. Production turns on the checks in section 4 |
| `SECRET_KEY` | yes | Signs access and refresh tokens. At least 32 characters in production |
| `MFA_ENCRYPTION_KEY` | production | Encrypts enrolled TOTP secrets. In development it is derived from `SECRET_KEY` if unset |
| `CLOUD_CONNECTOR_ENCRYPTION_KEY` | production | Encrypts cloud connector credentials and notification destinations |
| `POSTGRES_PASSWORD` | yes | Bootstrap superuser, used only by provisioning and backup jobs |
| `POSTGRES_APP_PASSWORD` | yes | `sentinel_runtime` role used by the API and worker |
| `POSTGRES_MIGRATOR_PASSWORD` | yes | `sentinel_migrator` role used by migrations |
| `SENTINEL_BOOTSTRAP_ADMIN_EMAIL`, `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD` | first start | First administrator; used only while the database has no users |
| `SENTINEL_SENSOR_EMAIL`, `SENTINEL_SENSOR_PASSWORD` | if a sensor runs | Credentials of the dedicated `ingestion_service` account, read by the Windows sensor controller |
| `CORS_ORIGINS` | yes | Comma-separated browser origins. HTTPS only in production |
| `METRICS_TOKEN` | optional | Enables `/api/v1/metrics`; at least 32 characters in production |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` | optional | Single-provider SSO; all four or none |
| `MAX_UPLOAD_BYTES`, `MAX_UPLOAD_ROWS` | optional | Import limits (10 MiB, 20,000 rows) |
| `RETENTION_DAYS` | optional | Default event retention (90). Each organization can change it in Settings |
| `ACCESS_TOKEN_MINUTES`, `REFRESH_TOKEN_HOURS` | optional | Session lifetimes (15 minutes, 8 hours) |
| `API_BIND_ADDRESS`, `POSTGRES_BIND_ADDRESS` | optional | Host address and port for the two published services |

The database passwords are embedded in connection URLs by Compose; use URL-safe characters (the generator above does). `DATABASE_URL`, `MIGRATION_DATABASE_URL`, `REDIS_URL`, and `SENTINEL_JOB_RUNNER` in `.env.example` apply only when running the backend outside Compose.

Losing `.env` matters: without `MFA_ENCRYPTION_KEY` and `CLOUD_CONNECTOR_ENCRYPTION_KEY` (or, in development, the `SECRET_KEY` they are derived from), a restored database cannot decrypt TOTP secrets, cloud credentials, or notification destinations. Back it up as described in section 8.

## 4. Production mode

Setting `SENTINEL_ENV=production` makes the services refuse to start unless:

- `SECRET_KEY` is at least 32 characters and not a known placeholder.
- `MFA_ENCRYPTION_KEY` and `CLOUD_CONNECTOR_ENCRYPTION_KEY` are valid, different 32-byte keys.
- The three PostgreSQL passwords are at least 32 characters and the service connections do not use a development password or a bootstrap role.
- The bootstrap administrator password, if set, is at least 12 characters and not a placeholder.
- Redis is configured and jobs run through Celery.
- Every entry in `CORS_ORIGINS` is an HTTPS origin.
- OIDC settings, if any are present, are complete, use HTTPS, and the client secret is at least 32 characters.
- `METRICS_TOKEN`, if set, is at least 32 characters.

Production mode also disables the interactive API documentation page. It does not add TLS, change which ports are published, or enable alerting.

### Switching an existing installation to production mode

An installation that was started in development mode (weak `SECRET_KEY`, the Compose default database passwords) can be switched in place:

```text
powershell -ExecutionPolicy Bypass -File .\scripts\switch_to_production.ps1
```

It takes a database backup, keeps a copy of the current `.env` under `.data\`, generates a new signing key, MFA key and three database passwords (written to `.env`, never displayed), changes the database superuser password, sets `SENTINEL_ENV=production` and HTTPS-only `CORS_ORIGINS`, rebuilds and restarts every service, and puts the previous configuration back if the stack does not become healthy. An existing `CLOUD_CONNECTOR_ENCRYPTION_KEY` is kept, because a new one would make stored connector credentials unreadable; the script stops if none is set.

Afterwards everyone must sign in again, sensors must be restarted, the API schema and documentation are no longer served, and the session cookie is marked Secure. Refresh the encrypted `.env` backup, and delete the kept copy of the old `.env` once satisfied: it holds the old secrets.

Rehearse first. `scripts\rehearse_production.ps1 -FromDevelopment` builds a separate, throwaway stack shaped like an unhardened installation, adds data, runs the switch against it and checks that the data survived; without the switch it checks production mode on a fresh stack. Neither touches the live stack or `.env`.

## 5. Network exposure and TLS

**The stack serves plain HTTP on loopback. The only TLS termination included is the lab HTTPS front (`--profile tls-lab`, self-signed certificate, see `docs/OPERATIONS.md`).** For real users you must add a reverse proxy with a trusted certificate on the host, and that is your responsibility to configure and test:

1. Terminate TLS in a proxy you maintain (for example NGINX, Caddy, or Traefik) with a certificate for your host name, and forward to `http://127.0.0.1:8080`. The frontend container already proxies `/api` to the backend, so one upstream is enough.
2. Set `CORS_ORIGINS` to the public HTTPS origin. If SSO is used, set `OIDC_REDIRECT_URI` to `https://<host>/api/v1/auth/oidc/callback` and register exactly that URI with the provider.
3. Add your proxy to `TRUSTED_PROXIES` (addresses, CIDR ranges or host names; the default is the bundled `frontend,tls-proxy`). The API believes `X-Forwarded-For` only when the connecting peer is a trusted proxy, and then uses the right-most address that is not itself trusted; a header sent by any other client, including direct access to port 8001, is ignored. If your proxy is not listed, audit records and per-address rate limits see the proxy's address instead of the client's. With Docker Desktop, connections through a published port arrive from the Docker gateway address, so the real client address is only available when your own proxy forwards it.
4. Keep ports 8001 and 5432 on loopback. Nothing outside the host needs them. Restrict the proxy with a firewall or VPN where you can.

The frontend sends a restrictive Content Security Policy and standard security headers. That policy also allows the loopback Windows sensor controller (`127.0.0.1`), which is only meaningful on the sensor host.

The remote Windows sensor posts to the API over the URL you give it. Once a proxy is in place, point sensors at the HTTPS address; sensor requests are also signed with a per-installation Ed25519 key.

## 6. Dependencies and the lock file

- `backend/requirements.txt` lists the direct dependencies with exact versions.
- `backend/requirements.lock` pins every direct and transitive package with SHA-256 hashes. The container image and CI install from it with `--require-hashes`, so a rebuild cannot silently pull a newer transitive release. It is resolved for Linux and Python 3.12; on a Windows development machine keep installing `requirements.txt`.
- `sensor/requirements.lock` records the exact versions of the Windows sensor environment.
- `frontend/package-lock.json` pins the console; the image build uses `npm ci`.
- `backend/requirements-ml.txt` (optional anomaly model) is not locked and not installed in the image.

To change or update a backend dependency, edit `requirements.txt`, then regenerate the lock from the repository root:

```text
docker run --rm -v "${PWD}/backend:/work" -w /work python:3.12-slim sh -c "pip install --quiet pip-tools==7.6.2 && pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras --output-file requirements.lock requirements.txt"
```

This resolves every transitive package to its newest compatible release, so expect more changes than the one you made. The current lock was generated with the versions of the previously running image as constraints, which is why its entries are annotated `-c constraints.txt`. Review the diff, rebuild, run the test suite, and confirm the worker starts before deploying. An unpinned transitive dependency (`kombu`) once broke the worker on a routine rebuild; the lock exists to prevent a repeat.

Base images (`python:3.12-slim`, `postgres:16-alpine`, `redis:7-alpine`, `node:22-alpine`, `nginx:1.27-alpine`) are referenced by tag, not digest, and will move with upstream patch releases.

## 7. Installing and upgrading

### First installation

1. Install Docker and clone the repository onto the host.
2. Create `.env` (section 3). For anything beyond a local lab, set `SENTINEL_ENV=production`.
3. Start: `docker compose up --build -d`. Provisioning and migrations run automatically before the API starts.
4. Check: `docker compose ps` shows `backend` healthy and `worker`, `celery-beat`, and `frontend` up; `http://127.0.0.1:8001/api/v1/ready` reports the database and Redis as available.
5. Sign in as the bootstrap administrator with organization `default`. Enroll MFA for that account, create named accounts for people, and consider requiring MFA for the organization under Settings.
6. Remove `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD` from `.env` once other administrators exist; it is not needed again.
7. Run `scripts\backup_env.ps1`, then `scripts\backup.ps1`, and store the passphrase safely.
8. Set up the reverse proxy (section 5), sensors, cloud connectors, and notification channels as needed.

### Upgrading

1. Take a backup: `scripts\backup.ps1`. Confirm the manifest was written.
2. Update the code.
3. `docker compose up --build -d`. Migrations apply before the new API starts. Always build every service this way: the migration, API, worker and scheduler are separate images built from the same source, and rebuilding only `backend` once started a new API against an unmigrated database, which crash-looped until the migration image was rebuilt.
4. Verify: `docker compose ps`, the readiness URL, `docker compose logs --tail 50 worker` shows the worker `ready`, sign in, and open an event and a case.
5. If the sensor changed, update its environment (`sensor\.venv\Scripts\python.exe -m pip install -r sensor\requirements.lock`) and restart the controller.

Rolling back code after a migration has run is not tested. The supported way back is restoring the pre-upgrade backup with `scripts\restore.ps1`, which loses anything ingested since.

## 8. Backup and disaster recovery

A complete recovery needs four things. Each has a different home.

| What | How it is backed up | Where it lives |
|---|---|---|
| Database | `scripts\backup.ps1` (custom-format dump with SHA-256 manifest) | `backups\`, and S3 with `scripts\offsite_backup.ps1` |
| Uploaded files and model directory | Same run, as a tar archive | Same |
| `.env` (encryption keys and passwords) | `scripts\backup_env.ps1`, passphrase-encrypted | `backups\env-<timestamp>.enc`, **local only** |
| Source code and lock files | Git | The private GitHub remote |

### The `.env` backup

`scripts\backup_env.ps1` asks for a passphrase twice and writes `backups\env-<timestamp>.enc`, encrypted with AES-256-GCM under a key derived from the passphrase with scrypt. The passphrase is never stored. Run it after creating or changing `.env`; `backup.ps1` prints a warning when `.env` is newer than its last encrypted copy or when none exists.

- The passphrase cannot be recovered. Keep it in a password manager, not next to the backups.
- The encrypted file is not uploaded by the off-site job. It stays on this machine unless you copy it elsewhere yourself. A copy on separate media or in a password manager attachment is what makes it useful after a disk failure.
- Restore with `scripts\restore_env.ps1`. It writes `.env.restored` and refuses to overwrite an existing file; review it and rename it to `.env`.

### Recovering on a replacement host

1. Install Docker and get the source code.
2. Recover `.env`: copy the `env-*.enc` file into `backups\`, create the `.venv`, and run `scripts\restore_env.ps1`.
3. Obtain the database dump, data archive, and manifest for the same timestamp (from `backups\` or the S3 prefix) and place them in `backups\`.
4. Start the stack once so the roles and volumes exist: `docker compose up --build -d`.
5. Restore: `scripts\restore.ps1 -ManifestPath .\backups\manifest-<timestamp>.json`.
6. Verify readiness, sign in with MFA, open an event, a case, and an audit record, and confirm a cloud connector can poll (which proves the encryption key matches).
7. Re-enroll sensors: the sensor's signing key lives on the sensor host, so an unchanged sensor resumes; a rebuilt sensor needs its credential rotated.

Measured so far: downloading from S3, verifying, and restoring the database and archive took about 14 seconds at the current size. Steps 1, 2, 4, 6, and 7 have not been timed, and the whole procedure has not been rehearsed end to end on a second machine. Data written after the last successful backup is lost; with the daily scheduled task that is up to 24 hours.

Scheduling, the S3 bucket settings, retention, and the writer identity are described in `docs/OPERATIONS.md`.

## 9. Built-in hardening

Present:

- API, worker, and frontend run as unprivileged users with all Linux capabilities dropped and `no-new-privileges` set.
- Separate database roles for bootstrap, migration, and runtime; forced row-level security on every organization-owned table.
- Secrets at rest: TOTP secrets, cloud credentials, and notification destinations are encrypted with keys from `.env`; passwords are hashed with Argon2.
- TOTP MFA with replay protection, optional organization-wide enforcement, optional OIDC SSO with PKCE.
- Sensor requests signed per installation, with credential rotation and revocation.
- Outbound notification requests restricted to public HTTPS destinations, without redirects.
- Upload size and row limits, quarantine of malformed rows, redaction of secret-looking fields in raw payloads.
- Audit records for administrative and security-relevant actions.
- Dependencies installed from a hash-pinned lock file.

Not present:

- A trusted TLS certificate, a web application firewall, or network-level rate limiting in front of the API (the lab HTTPS front uses a self-signed certificate).
- Read-only container filesystems, CPU/memory limits, or image digests.
- A password on Redis or TLS between containers (they share one private Compose network).
- Encryption of the database volume or of local backup files; rely on disk encryption.
- Secret management beyond a file; `.env` is readable by anyone who can read the project directory.
- Hardware-backed sensor identity. The sensor key is trust-on-first-use and stored on the sensor host.

## 10. Before using this beyond a lab

These are not done. Treat each as a blocker for real data.

1. Independent security review, including the tenant isolation boundary.
2. TLS termination and an access-restricted network path, tested.
3. Source code is on a private GitHub repository with CI; keep the repository private (it holds infrastructure details) and confirm that after any change of ownership.
4. A full recovery rehearsal on a second machine with measured recovery time, and an off-machine copy of the encrypted `.env`.
5. Alerting for system health: failed backups, a stopped worker, sensor heartbeat gaps, connector failures, disk space. Notifications currently cover detections only.
6. Capacity work: the detection window's memory use, a single API process, text search, and the host inventory (see `docs/PERFORMANCE_AND_ML_EVALUATION.md`).
7. Validation of Azure, Entra, and OIDC SSO against real tenants, and of two independent sensors.
8. Detection quality measured on representative real telemetry.
9. A patching routine for base images and dependencies.

## 11. Related documents

- `docs/OPERATIONS.md` — SSO, backups, restore, retention, notifications, metrics.
- `docs/THREAT_MODEL.md` — assets, trust boundaries, known risks.
- `docs/ARCHITECTURE.md` — components and data flow.
- `sensor/README.md` — Windows sensor installation.
- `docs/CLOUD_CONNECTORS.md` — provider permissions.
- `docs/STATUS.md` — what has actually been verified, with dates.
