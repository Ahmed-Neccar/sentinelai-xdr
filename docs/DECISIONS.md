# SentinelAI XDR — Architecture Decisions

## ADR-001: Modular monolith

**Decision:** Single FastAPI app + React SPA + PostgreSQL.

**Why:** Matches a 2–4 week solo demo, keeps transactions simple, avoids distributed tracing theater.

**Not chosen:** Microservices, Kafka, Elasticsearch.

## ADR-002: PostgreSQL JSONB for raw events

**Decision:** Normalized columns for queryable fields; original payload in JSONB.

**Why:** Analysts need both filtering and forensic fidelity. JSONB is indexed as needed later.

## ADR-003: Inline job runner + optional Celery

**Decision:** `JobRunner` protocol. Celery when Redis is configured; synchronous/thread runner for tests and degraded lab mode.

**Why:** Ingestion must not depend on the browser tab, but tests must not require a flaky broker. UI still records job state.

## ADR-004: Bearer access token in memory + refresh cookie

**Decision:** Short JWT access tokens. Refresh token in httpOnly cookie. No localStorage.

**Why:** XSS would otherwise steal long-lived tokens. CSRF risk on cookie refresh is reduced with `SameSite=Lax` and a dedicated refresh path.

## ADR-005: Argon2 password hashing

**Decision:** `pwdlib` / argon2-cffi.

**Why:** Current default recommendation versus unsalted SHA or deprecated `crypt`.

## ADR-006: Rule engine as the baseline; ML optional

**Decision:** Built-in versioned YAML/JSON rules with tests. Isolation Forest is offline-trained and optional at inference.

**Why:** Explainability for a cybersecurity competition. Anomaly scores are not marketed as probabilities.

## ADR-007: Conservative correlation

**Decision:** Group detections that share **host or IP and time window and related detection types**, not IP alone.

**Why:** NAT and shared egress would otherwise create junk mega-cases.

## ADR-008: No automated remediation

**Decision:** Recommendations only; lab “simulate response” writes an audit row.

**Why:** Unsafe automation is a larger risk than delayed containment in this product class.

## ADR-009: Python 3.12 in images despite host 3.15

**Decision:** Pin Docker and venv to 3.12.

**Why:** 3.12 is the requested supported line; host 3.15 was observed but is not the project runtime.

## ADR-010: Sigma subset, not full Sigma

**Decision:** Native condition language inspired by Sigma field-value and count-over-window. Unsupported: full Sigma pipelines, modifiers beyond `contains`/`startswith`/`endswith`, external lookups.

**Why:** Shipping a honest subset beats a broken “Sigma compatible” claim.

## ADR-011: Single lab tenant (superseded by ADR-013)

**Decision:** No multi-tenant key in v1. Isolation tests assert **role** isolation, not tenant isolation.

**Why:** One-operator demo. Introducing fake tenant IDs would imply a guarantee we do not enforce everywhere.

## ADR-013: Organization-scoped data and PostgreSQL row security

**Decision:** Tenant-owned rows carry an organization ID; verified access tokens select the organization context; PostgreSQL forced RLS policies apply to runtime queries. The API uses a separate non-superuser runtime role, while migrations use a separate database URL. Organizations are provisioned with a CLI command.

**Why:** The product needs a real tenant boundary before company use. Existing rows are migrated into the `default` organization. RLS is defense in depth against missing query filters; the API still belongs to the trusted computing base. Independent review and cross-tenant integration testing remain required before production approval.

## ADR-012: Development bootstrap

**Decision:** If `users` is empty and `SENTINEL_BOOTSTRAP_ADMIN_EMAIL` + password are set, create one administrator at startup.

**Why:** Reproducible lab. Not an unauthenticated backdoor; login still required. Disabled when users exist.
