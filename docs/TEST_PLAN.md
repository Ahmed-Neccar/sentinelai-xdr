# SentinelAI XDR — Test Plan

> Status: partial automated coverage. `backend/tests/test_mfa_api_flow.py` and `backend/tests/test_tenant_rls.py` exercise MFA lifecycle and tenant isolation against PostgreSQL; the former is enabled in CI using the non-superuser runtime role. `backend/tests/test_competition_readiness.py` covers Windows-specific rules and source/time correlation; `sensor/tests/test_spool_replay.py` covers local queue retry behavior. The backend suite currently passes 36 tests at 57% statement coverage. See `docs/STATUS.md` for exact evidence; the remaining plan is not implemented or passing.

## Layers

1. **Unit** — parsers, normalizers, rule conditions, feature extraction, correlation grouping, permission helpers, CSV injection escaping.
2. **API integration** — FastAPI `TestClient` / httpx ASGI against a real PostgreSQL when available; SQLite is **not** used as a JSONB stand-in.
3. **Migration** — Alembic upgrade/downgrade on an empty database.
4. **AuthZ** — each role against representative endpoints (positive and negative).
5. **Ingestion abuse** — oversized file, wrong type, path-like filename, duplicate idempotency key, malformed rows.
6. **Detection** — every built-in rule has a fixture that must fire and a fixture that must not.
7. **ML** — split leakage checks; metrics computed from held-out data only; fallback when sklearn missing.
8. **Frontend** — component tests for login error, empty tables, severity badges; critical workflow if Node is available.
9. **Performance (basic)** — ingest 5k synthetic events; list events with pagination under a loose time bound.
10. **Security tooling** — `pip-audit` / `npm audit` when the toolchain is installed; failures recorded honestly in STATUS.md.

## Deterministic fixtures

Located under `data/samples/` and `backend/tests/fixtures/`.

| Fixture | Expected |
|---------|----------|
| repeated failed logins from one IP | `auth_bruteforce` detection |
| distributed failed logins under threshold | no brute-force detection |
| many destination ports from one source in window | `port_scan_like` |
| high connection count | `unusual_conn_volume` |
| mixed benign browsing | no high-severity rule hits |
| Zeek conn sample | normalized `zeek.conn` events |
| Suricata EVE sample | normalized `suricata.eve` events |

Synthetic data is labeled in filenames and reports as **synthetic**.

## Commands

Backend (from `backend/`):

```text
py -3.12 -m pytest -q
py -3.12 -m ruff check app tests
py -3.12 -m mypy app
```

Frontend (from `frontend/`, requires Node 22):

```text
npm test
npm run lint
npm run build
```

Compose:

```text
docker compose -f docker-compose.yml config
```

## Pass/fail policy

Do not weaken assertions to obtain a green run. Record skips (for example, Node missing) as **skips**, not passes.

## CI-friendly local sequence

1. `docker compose up -d postgres redis`
2. `alembic upgrade head`
3. backend pytest
4. optional frontend tests
5. `docker compose down` is operator-controlled; tests should not destroy operator data volumes unexpectedly
