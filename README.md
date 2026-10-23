# SentinelAI XDR

SentinelAI XDR is a defensive, locally deployable security monitoring prototype. It imports authorized JSON/CSV telemetry and can receive passive TCP/UDP header telemetry plus optional Windows Security logon, process-start, and selected endpoint/security events from its host sensor. It normalizes and stores events, runs transparent rules, correlates selected credential and network-discovery findings into cases, and provides an analyst dashboard. Rule hits are investigation signals, not proof of compromise. Automated response is disabled.

## Start the local lab

Requirements: Docker Desktop with Compose v2 or newer.

1. Copy `.env.example` to `.env`.
2. Replace `SECRET_KEY`, `MFA_ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD`, `POSTGRES_MIGRATOR_PASSWORD`, `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD`, and `SENTINEL_SENSOR_PASSWORD` with private values. Generate `MFA_ENCRYPTION_KEY` as URL-safe base64 for 32 random bytes; use URL-safe passwords for the two database URLs. The sensor password must match the dedicated `ingestion_service` account you create below. Keep `.env` out of version control.
3. Run `docker compose up --build` from the repository root.
4. Open <http://127.0.0.1:8080>. The API is at <http://127.0.0.1:8001>; development OpenAPI docs are at `/docs`.
5. Sign in with organization slug `default` and the bootstrap email/password you configured in `.env`.
6. For a repeatable, clearly labeled walkthrough, import `data/samples/auth_and_network_synthetic.json` from **Ingestion**. This synthetic file creates example findings; it is not a real network scan, incident, or live capture.
7. To monitor real traffic visible to this Windows computer, follow [`sensor/README.md`](sensor/README.md). Create a dedicated `ingestion_service` account for the sensor and configure it in the ignored `.env`; do not reuse the administrator login. After installing Npcap and the sensor dependencies, run `start_sensor_controller.ps1` in elevated PowerShell and leave it open, or optionally run `install_sensor_autostart.ps1` once as Administrator to register a hidden controller that starts at each sign-in. Use **Sensors** in the app to choose an adapter and start/stop capture. While it runs, **Events** shows received records and **Hosts** shows telemetry labels with recent-event timing. It does not see every other device on a Wi-Fi/LAN unless traffic is mirrored to the sensor.

Compose binds published services to loopback. Do not expose the development stack to an untrusted network. The initial administrator is created only if the database has no users. If the bootstrap credentials were omitted on first start, configure them and use `docker compose exec backend python -m app.core.bootstrap`.

The API and worker use the `sentinel_runtime` PostgreSQL role, which is not a superuser and cannot bypass row-level security. A one-shot migration service uses the separate, non-superuser `sentinel_migrator` schema-owner role; the long-running API and worker do not receive its credentials. Existing records are assigned to the `default` organization by migration `005`. To provision another organization, run `docker compose exec -it backend python -m app.core.tenants acme "Acme Ltd" admin@example.com`; the command prompts for the first administrator password and seeds that organization’s detection rules. Sign in using the new slug. This tenant boundary is application-mediated PostgreSQL RLS and still needs independent security review before commercial deployment.

Useful commands:

```text
docker compose ps
docker compose logs -f backend worker
docker compose down
```

`docker compose down -v` deletes the lab database and uploaded data.

## Local backend development

Use Python 3.12 (supported range is >=3.12,<3.14). Create a virtual environment in `backend`, install `requirements.txt`, and set `DATABASE_URL`, `SECRET_KEY`, and `SENTINEL_JOB_RUNNER=inline` in the environment. Start a local PostgreSQL 16 database, apply migrations with `alembic upgrade head`, then run `uvicorn app.main:app --reload` from `backend`. Set the bootstrap email/password before the first API start.

The UI can also run with Node 22: `npm install` and `npm run dev` from `frontend`. The Vite server proxies `/api` to `127.0.0.1:8000`.

## What is included

- FastAPI API with access/refresh token auth, role checks, audit records, upload job tracking, and health/readiness endpoints.
- PostgreSQL persistence and Alembic schema migrations.
- Redis/Celery background ingestion worker, with bounded upload size and row count.
- Generic JSON/CSV, Zeek, Suricata EVE, AWS CloudTrail, Azure Activity Log, and Microsoft Entra sign-in file normalizers; provider raw data is curated and malformed rows are quarantined. Cloud sources are file imports only; live provider API connectors are not implemented. See [cloud import guidance](docs/CLOUD_INGESTION.md).
- A shared, versioned SentinelAI event envelope validates imported and live sensor rows before persistence. Its field limits and current ECS/OSSEM mapping boundary are documented in [the event schema](docs/EVENT_SCHEMA.md); this is not full ECS/OSSEM conformance.
- Versioned built-in rules, evidence-linked detections, conservative case correlation, and optional offline Isolation Forest scoring.
- React analyst console for overview, detections, cases, events, telemetry-derived Hosts, sensor health and local start/stop controls, ingestion jobs, rules, and audit/report access. Administrators can review registered sensors and rotate or revoke their credentials.
- Optional Windows live host sensor that passively records initial TCP connection attempts and UDP headers, and can collect new Windows logon success/failure records, process starts, and selected service/task/audit-policy events when separately enabled. See [sensor setup](sensor/README.md).

## Scope and limitations

This remains a defensive lab prototype, not an approved commercial production deployment. Organization-scoped storage/runtime RLS and TOTP MFA are implemented. Daily tenant-scoped retention covers security events (90-day default) and uploaded source files (30-day default); administrators can set each policy from Settings (1–3650 days). Detection snapshots, cases, and audit history remain after event deletion. Operator backup/restore scripts and an optional protected HTTP metrics endpoint are available; they still require a successful recovery drill, encrypted off-host storage, configured alert delivery, and tested on-call procedures. A single-provider OIDC SSO flow is implemented for self-hosted installations, but it still needs verification with the operator's actual provider. Automated cloud log shipping, broader endpoint coverage, representative real-data detection validation, and independent security review remain incomplete. There is no automatic endpoint isolation, firewall change, or shell remediation. See [operations](docs/OPERATIONS.md), the [demo runbook](docs/DEMO_RUNBOOK.md), [threat model](docs/THREAT_MODEL.md), [API contract](docs/API.md), [architecture](docs/ARCHITECTURE.md), and [project status](docs/STATUS.md).

## XDR capability readiness

See [`docs/XDR_CAPABILITY_READINESS.md`](docs/XDR_CAPABILITY_READINESS.md) for the phased scope and acceptance criteria for sensor fleet identity, endpoint sources, cloud connectors, cross-source correlation, response simulation, and operational readiness.
