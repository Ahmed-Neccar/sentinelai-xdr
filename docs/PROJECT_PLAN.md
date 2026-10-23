# SentinelAI XDR — Project Plan

## Purpose

SentinelAI XDR is a **locally deployable defensive security monitoring and detection platform**. It ingest authorized telemetry, normalizes events, runs transparent detections, correlates related alerts into cases, and presents an analyst dashboard.

This is **not** a commercial XDR, an IPS, or a guarantee of detecting zero-days. Machine-learning scores are **investigation signals**, not proof of malice.

## Scope of the initial release

In scope:

- Local Docker Compose lab bound to localhost
- JSON/CSV ingestion with job tracking
- Zeek JSON and Suricata EVE JSON adapters
- Versioned rule-based detection with evidence
- Optional Isolation Forest anomaly scoring (separate from request handlers)
- Case management and conservative correlation
- RBAC (Administrator, Analyst, Auditor, Ingestion Service)
- Audit logging
- React dashboard backed by persisted data
- Synthetic demo dataset and reproducible evaluation artifacts

Out of scope (planned, labeled in UI):

- Automatic host isolation, firewall blocking, or shell-based remediation
- Live cloud log shipping (AWS/Azure/GCP)
- Multi-tenant SaaS isolation beyond a single-lab tenant
- Full Sigma language coverage
- Paid threat-intelligence feeds

## Nearby prior work (not forked)

A Flask prototype exists at `C:\Users\ahmed\MiniSIEM`. It uses in-memory counters and is not used as the codebase for this project. SentinelAI XDR is a new modular monolith with a real database and a documented threat model. `docs/TEST_PLAN.md` is a plan; it is not evidence that automated tests exist or pass.

## Environment snapshot (Phase 1 inspection)

| Tool | Observed |
|------|----------|
| Python | 3.12.10 via `py -3.12`; default `python` is 3.15.0 |
| Git | 2.54.0 |
| Docker | 29.3.1 |
| Docker Compose | v5.1.1 |
| Node.js / npm | Not on PATH at inspection time; frontend build targets Node 22 in Docker |
| PostgreSQL | Provided by Compose, not assumed host-installed |
| Existing repo | Empty git repo initialized at `~/Projects/sentinelai-xdr` |

**Compatibility assumption:** backend images and local venv use **Python 3.12**. Python 3.15 is not the supported runtime.

## Phases

| Phase | Goal | Exit criteria |
|-------|------|----------------|
| 1 | Docs, architecture, API, tests, decisions | Six core docs + STATUS.md |
| 2 | Monorepo, Compose, health, migrations, CI commands | Containers/health or documented local equivalent |
| 3 | Auth, RBAC, audit | Authz tests pass |
| 4 | Events + JSON/CSV ingestion | Sample import visible in API |
| 5 | Rule engine | Deterministic detection tests |
| 6 | Correlation + cases | Case lifecycle tests |
| 7 | Optional ML train/eval | Honest metrics, no leakage in splits |
| 8 | Zeek/Suricata adapters | Parser tests against sample logs |
| 9 | Dashboard, reports, empty/error states | Frontend build + critical tests |
| 10 | Validation, security checks, demo rehearsal | STATUS.md lists real results |

## Delivery principles

1. Small, verifiable steps; failing checks block the next feature.
2. No fabricated accuracy, screenshots, or integrations.
3. Secrets only via environment; `.env` is gitignored.
4. Simple modular monolith; Redis/Celery only for background jobs.
5. Response actions are **recommendations + lab simulation**, never privileged execution.

## Demo narrative (synthetic, labeled)

1. Bootstrap a development administrator.
2. Import `data/samples/auth_and_network_synthetic.json`.
3. Observe normalized events and rule detections (brute-force, port-scan-like, volume).
4. Open a correlated case, add a note, mark investigating.
5. View ML evaluation artifacts generated offline (if the optional extra is installed).
6. Export a report that states limitations.

## Success for a 2–4 week competition demo

A judge can clone/start the lab, log in, import labeled synthetic data, see detections with evidence, work a case, and read what the system does **not** claim.
