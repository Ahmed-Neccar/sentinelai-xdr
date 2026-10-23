# SentinelAI XDR — Threat Model

## System statement

SentinelAI XDR is a **defensive lab/monitoring tool**. It processes untrusted telemetry. It must not become an attack pivot, a credential dump, or an unsupervised automation engine.

## Assets

- Analyst credentials, MFA factors, and session tokens
- Role assignments
- Imported telemetry (may contain internal IPs, hostnames, usernames)
- Detection evidence and case notes
- Audit logs (integrity)
- Model artifacts (poisoning / integrity)
- Database and Redis contents
- Bootstrap admin secret (development only)

## Actors

- Lab operator / administrator
- Security analyst
- Read-only auditor
- Ingestion service (machine account)
- Unauthenticated network peer on localhost
- Malicious telemetry author (compromised sensor or crafted file)
- Curious insider with a lower-privilege role

## Assumptions

- Compose is bound to localhost; the lab is **not** exposed to the internet by default.
- Operators do not reuse production passwords in `.env`.
- Host Docker daemon is trusted.
- No automatic privileged response actions are enabled.

## STRIDE summary

| Threat | Example | Mitigations |
|--------|---------|-------------|
| Spoofing | Stolen JWT, password spray, forged ingestion | Short-lived access tokens, Argon2 passwords, optional organization-enforced TOTP MFA, one-use recovery codes, throttled auth attempts, RBAC on every mutation, ingestion role scoped to ingest endpoints |
| Tampering | Edited detections, poisoned model files | Audit log, rule versioning, model files checksummed, migrations only via Alembic |
| Repudiation | “I did not close that case” | Append-style audit events with actor, action, target, timestamp |
| Information disclosure | Stack traces, secrets in logs, PII in exports | Generic 4xx/5xx bodies, redaction helpers, CSV formula escaping, CORS allowlist |
| Denial of service | Huge upload, zip bombs, unbounded queries | Size/row limits, pagination caps, rate limits, timeouts |
| Elevation of privilege | Hidden UI buttons, role self-assign | Server-side permission checks; auditors cannot mutate; no unauthenticated admin backdoor |

## Untrusted input

Treat as hostile:

- JSON/CSV/Zeek/Suricata files
- Event fields (`message`, `query`, `cmdline` if present)
- Case comments
- Saved filter strings
- Model outputs and SHAP text
- User-Agent and extra headers

**Never** execute imported content. Parsers must not `eval`, run shells, or follow attacker-controlled paths.

## Explicit non-goals / residual risk

- A local lab with Docker published ports is only as isolated as the host firewall.
- Synthetic detections are **not** validated against a production SOC corpus.
- Isolation Forest scores are not probabilities.
- ATT&CK mappings are **hypotheses**, not confirmed adversary attribution.
- Compose binds the published dashboard, API, and database ports to loopback; changing those bindings increases exposure risk.

## Response safety

The product **must not** isolate hosts, drop firewall rules, delete files, or run shell commands from a detection.

The case workflow currently records only simulated response proposals. Supported simulation types are allowlisted, analyst proposals require a different administrator to approve, and the simulation writes an audit record without contacting a host, account, network device, or cloud service. Any future real action framework requires a separate security review and:

1. Human approval by an authorized role
2. Allowlisted action + target
3. Audit of requester, approver, and timestamp
4. Lab simulation by default
5. Rollback notes and explicit endpoint authorization

## Secrets handling

- `.env` gitignored; `.env.example` placeholders only
- Default Compose passwords are **development-only** and documented as such
- No production credentials in source
- Bootstrap admin is created only when the user table is empty
- Production TOTP secrets must use AES-GCM with a separate 32-byte `MFA_ENCRYPTION_KEY`; the current development stack derives a key from `SECRET_KEY`. Recovery codes are keyed hashes. Back up and rotate the production key under a documented recovery procedure. Losing it makes enrolled TOTP secrets unusable.
- MFA challenges are short-lived and single-use; authenticator counters prevent replay; failed auth attempts are rate limited (Redis is required outside development).
