# SentinelAI XDR

SentinelAI XDR is a defensive, self-hosted security monitoring platform for a lab or small environment. It collects authorized endpoint, network, and cloud audit telemetry, normalizes it, runs transparent detection rules, groups related findings into cases, and gives analysts a console to investigate them.

**Status: lab prototype.** It runs and has been exercised on one machine, but it has not had an independent security review and is not approved for commercial production. Findings are review signals for an analyst, not proof of compromise. Response actions are recorded simulations unless a real one is explicitly requested. Three can be executed, each time-limited and applied by a sensor computer to itself: a firewall block of one IP address, a network isolation of that computer, and the disabling of one local Windows account. Each needs a proposal, approval by a different administrator, and an explicit opt-in on that sensor (see `docs/OPERATIONS.md`). The server never changes a cloud tenant, a directory or another machine.

## What it does

| Area | Included |
|---|---|
| Collection | JSON/CSV, Zeek, and Suricata EVE file import; a Windows host sensor for passive TCP/UDP header metadata and opt-in Windows Security events; read-only polling of AWS CloudTrail, Azure Activity Log, and Microsoft Entra sign-ins |
| Detection | Versioned built-in rules with evidence-linked findings; correlation into cases by shared source, host, account, or resource inside a time window |
| Investigation | Cases with assignment, priority, notes, status history, and CSV export of events and detections |
| Notification | Webhook, Slack-compatible, and Telegram channels for new findings above a chosen severity, response approvals and outcomes, silent sensors and failing cloud connectors |
| Access control | Roles (administrator, analyst, auditor, ingestion service), TOTP MFA, single-provider OIDC SSO, audit log |
| Isolation | Organization-scoped data with PostgreSQL row-level security and a non-superuser runtime role |
| Operations | Backup and restore scripts with pruning and failure alerts, encrypted off-site copy to S3, encrypted `.env` backup, retention cleanup, a production-mode switch with rehearsal scripts, optional Prometheus metrics |

What it is not: a full EDR, a whole-network monitor (an ordinary Wi-Fi adapter sees only its own host's traffic), or an automated response system. The optional Isolation Forest anomaly score is not deployed and is not recommended in its current form; see the [evaluation](docs/PERFORMANCE_AND_ML_EVALUATION.md).

## Quick start (local lab)

Requirements: Docker Desktop with Compose v2, about 4 GB of free memory, Windows 10/11 for the host sensor (the server stack itself runs anywhere Docker does).

1. Copy `.env.example` to `.env`.
2. Replace every placeholder secret in `.env`: `SECRET_KEY`, the three `POSTGRES_*PASSWORD` values, `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD`, and `SENTINEL_SENSOR_PASSWORD`. Set `MFA_ENCRYPTION_KEY` and `CLOUD_CONNECTOR_ENCRYPTION_KEY` to two different URL-safe base64 keys of 32 random bytes. [DEPLOYMENT.md](DEPLOYMENT.md#3-configuration) shows how to generate them.
3. Start the stack:

   ```text
   docker compose up --build -d
   ```

4. Open <http://127.0.0.1:8080> and sign in with organization `default` and the bootstrap administrator email and password from `.env`. The API is at <http://127.0.0.1:8001>; in development mode its OpenAPI page is at `/docs`.
5. For a first walkthrough, import `data/samples/auth_and_network_synthetic.json` under **Ingestion**. It is labelled synthetic data that produces example findings.
6. Back up your configuration once the stack works: run `scripts\backup_env.ps1` and store the passphrase in a password manager.

Published ports bind to loopback only. Do not expose this stack to a network without the steps in [DEPLOYMENT.md](DEPLOYMENT.md).

The bootstrap administrator is created only when the database has no users. If the credentials were missing on first start, set them and run `docker compose exec backend python -m app.core.bootstrap`.

### Useful commands

```text
docker compose ps
docker compose logs -f backend worker
docker compose down
```

`docker compose down -v` deletes the database and all uploaded data.

## Live telemetry from this Windows host

Follow [sensor/README.md](sensor/README.md). In short: install Npcap, create a dedicated account with only the `ingestion_service` role, put its credentials in `.env`, and run `start_sensor_controller.ps1` in an elevated PowerShell. Then start and stop capture from **Sensors** in the console. The sensor reads packet headers and selected Windows event fields only; it does not capture payloads, passwords, or command lines, and it does not send traffic.

## Cloud sources and notifications

- Cloud connectors are added under **Cloud connectors** with read-only provider credentials; see [docs/CLOUD_CONNECTORS.md](docs/CLOUD_CONNECTORS.md). Only AWS CloudTrail has been exercised against a real account.
- Notification channels are added under **Notifications**; see [docs/OPERATIONS.md](docs/OPERATIONS.md#alert-notifications) for what a message contains and how delivery behaves.

## Additional organizations

```text
docker compose exec -it backend python -m app.core.tenants acme "Acme Ltd" admin@example.com
```

The command prompts for the first administrator's password and seeds that organization's rules. Users sign in with the new slug.

## Backups

```text
scripts\backup.ps1            # database dump + application data, with SHA-256 manifest
scripts\backup_env.ps1        # passphrase-encrypted copy of .env
scripts\offsite_backup.ps1    # fresh backup uploaded to a private S3 bucket
scripts\restore.ps1           # restore from a manifest (asks for confirmation)
```

Backups contain telemetry and must be protected. Details, scheduling, and the recovery procedure are in [docs/OPERATIONS.md](docs/OPERATIONS.md) and [DEPLOYMENT.md](DEPLOYMENT.md#8-backup-and-disaster-recovery).

## Development

- **Backend:** Python 3.12. Create a virtual environment, install `backend/requirements.txt`, set `DATABASE_URL`, `SECRET_KEY`, and `SENTINEL_JOB_RUNNER=inline`, apply migrations with `alembic upgrade head`, and run `uvicorn app.main:app --reload` from `backend`.
- **Frontend:** Node 22. `npm ci` and `npm run dev` from `frontend`; the dev server proxies `/api` to `127.0.0.1:8000`.
- **Checks** (the same ones CI runs, from `backend`):

  ```text
  python -m pytest
  python -m ruff check app tests
  python -m mypy app
  ```

  Most tests need a migrated PostgreSQL database and are skipped without one. On Windows with Docker, `scripts\run_integration_tests.ps1` runs the whole suite as CI does against a throwaway database container and touches nothing else. CI also audits the locked dependencies (`.github/workflows/security.yml`).

- **Dependencies:** container images and CI install from the hash-pinned `backend/requirements.lock`. After changing `backend/requirements.txt`, regenerate it as described in [DEPLOYMENT.md](DEPLOYMENT.md#6-dependencies-and-the-lock-file).
- **Load test and ML evaluation:** `scripts/loadtest/run_load_test.ps1` starts a separate Compose project so synthetic data never reaches your normal database; `scripts/ml/evaluate_ml.py` evaluates the anomaly model offline.

## Repository layout

| Path | Contents |
|---|---|
| `backend/` | FastAPI application, Celery tasks, Alembic migrations, tests |
| `frontend/` | React/TypeScript console served by NGINX |
| `sensor/` | Windows host sensor and its local controller |
| `scripts/` | Backup, restore, off-site upload, load test, and evaluation tooling |
| `infra/aws/` | Least-privilege IAM and bucket policy templates for off-site backups |
| `monitoring/` | Optional Prometheus configuration and starter alert rules |
| `data/samples/` | Labelled synthetic sample datasets |
| `docs/` | Architecture, operations, API, threat model, and status |

## Documentation

| Document | Use it for |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Installing, configuring, hardening, upgrading, and recovering a deployment |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Day-to-day procedures: SSO, backups, retention, notifications, metrics |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components and data flow |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, and known risks |
| [docs/API.md](docs/API.md) | HTTP API contract |
| [docs/EVENT_SCHEMA.md](docs/EVENT_SCHEMA.md) | Normalized event fields |
| [docs/CLOUD_CONNECTORS.md](docs/CLOUD_CONNECTORS.md) | Provider permissions and polling limits |
| [docs/PERFORMANCE_AND_ML_EVALUATION.md](docs/PERFORMANCE_AND_ML_EVALUATION.md) | Measured load-test results and the anomaly-model evaluation |
| [docs/XDR_CAPABILITY_READINESS.md](docs/XDR_CAPABILITY_READINESS.md) | Scope and acceptance criteria per capability |
| [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md) | A guided demonstration |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common problems |
| [docs/STATUS.md](docs/STATUS.md) | Dated record of what was built and what was actually verified |

## Known limitations

- No independent security review; tenant isolation is enforced by the application and PostgreSQL row-level security. It is covered by automated tests, including two organizations side by side through the API, but has not been externally tested.
- TLS is the lab HTTPS front with a self-signed certificate, valid for 90 days and tied to one network address; there is no trusted certificate or real host name. See [DEPLOYMENT.md](DEPLOYMENT.md#5-network-exposure-and-tls).
- The whole stack runs on one personal computer: no high availability, no separate database host, no support or release process.
- Azure Activity, OIDC single sign-on (Microsoft Entra) and two independent sensors were exercised once each on the author's lab. Entra sign-in logs (they need a paid licence), a second real Windows computer as a remote sensor, and recovery on a second machine have not been tested.
- Performance was measured on one laptop with synthetic data. The API runs one process by default (`API_WORKERS` is available but unused), the text search scans the organization's events, and detection re-reads the recent-event window for every job.
- The sensor is not a full EDR and runs as a scheduled task or from a console, not as a signed, self-updating Windows service. Only Windows is supported.
- Alerting covers detections, response workflow events, silent sensors and failing cloud connectors, plus a webhook for failed backups. It is not an on-call system: a stopped worker or scheduler cannot report itself.
- Detection content is a small set of rules; none has been evaluated on real telemetry.
