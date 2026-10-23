# SentinelAI XDR — Status

Last updated: 2026-10-23

## Completed

### Phase 1 — Inspection and documentation

- Inspected home directory: no existing SentinelAI repo; nearby `MiniSIEM` Flask prototype left untouched.
- Tools: Python 3.12.10 (`py -3.12`), host default Python 3.15.0 (not used), Git 2.54, Docker 29.3.1, Compose v5.1.1.
- Host Node.js/npm are not on PATH; the reproducible frontend build uses the Node 22 Docker stage.
- Initialized empty git repo at `C:\Users\ahmed\Projects\sentinelai-xdr`.
- Wrote `PROJECT_PLAN.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `API.md`, `TEST_PLAN.md`, `DECISIONS.md`.

### Phase 2 — Local application foundation

- Added Docker Compose services for PostgreSQL, Redis, FastAPI, Celery worker, and the dashboard; published ports bind to loopback.
- Added backend and frontend container builds, migration-on-start, service health checks, and Nginx API forwarding.
- Added a React/TypeScript console with in-memory access tokens, refresh-cookie session restoration, dashboard, event/detection/case/rule/audit views, ingestion upload, and report export.
- Added operator setup instructions and a labeled synthetic auth/network sample dataset.

### Existing backend capabilities (implementation present; verification pending)

- Auth and role checks, audit logging, user management, PostgreSQL models and initial migration.
- JSON/CSV, Zeek, and Suricata ingestion with job tracking and quarantine.
- Versioned detections, correlation, case workflow, optional offline ML support, summary/report endpoints.

### Live host monitoring

- Added authenticated live-session endpoints that persist normalized records into the normal event pipeline and run detections.
- Added a Windows Scapy/Npcap sensor that passively forwards initial TCP SYN and UDP header metadata; it does not send traffic or collect payloads. The user confirmed the live sensor forwarded records to the API on 2026-10-21.
- Added optional Windows Security log collection for new 4624/4625 sign-in and 4801 workstation-unlock events, without replaying old log history or collecting passwords/command lines.
- Added a low-severity Windows Remote Desktop logon review rule for successful RemoteInteractive sign-ins (4624 / LogonType 10); normal local logons and unlocks do not match it.
- Fixed the Remote Desktop rule to group by reported host label so a valid type-10 sign-in still matches when Windows omits its source IP; existing databases now seed rule version 3.
- Added opt-in Windows process creation collection (Security event 4688), limited to executable/parent names and process IDs; command lines are intentionally ignored. Added a medium-severity review rule for Word starting PowerShell.
- Added conservative correlation so credential and network-discovery findings from the same source IP and time window can share an investigation case.
- Replaced the Cases raw-JSON-only detail view with an investigation workspace showing linked detections, their evidence events, analyst notes, status history, case status controls, and human-review guidance.
- Extended case triage with status and priority filters, inline priority changes, and analyst assignment from the case table and case detail. Active analyst/administrator assignees are listed through a role-checked endpoint; assignment, priority, and severity are validated and written to the audit trail. Analysts can clear an assignment.
- Added filtered CSV exports for Events and Detections, with readable event names and process/network evidence fields. Exports contain the records loaded by the current view (up to its current API page size); they are not a full-history archive export.
- Added a Hosts inventory derived from observed event host labels, with first/last event times, event-type counts, recent telemetry, and related detections. This is an observed-activity view, not an agent heartbeat or verified asset inventory.
- Hosts and open host details refresh every five seconds; the view marks whether telemetry arrived in the last two minutes, and selecting an activity record or finding opens its event or detection investigation details. This is recent-data status, not proof that a sensor process is currently online.
- Added a Sensors page with live-session status refreshed every five seconds. The sensor sends a heartbeat every 10 seconds; the page reports Online, Signal delayed, or Stopped and shows last signal and ingested record totals. Online means the process checked in recently; it does not guarantee packet visibility or complete network coverage.
- Added a loopback-only Windows sensor controller. The Sensors page can enumerate local adapters and start/stop the sensor; stop requests drain queued records and close the session gracefully. Controller requests require the dashboard's exact local origin and host. The user must launch `start_sensor_controller.ps1` elevated and leave it running because the Docker-hosted web/API containers cannot directly access Npcap on Windows. Added an optional elevated Task Scheduler setup/removal script so the hidden controller can start automatically at sign-in; controller output is retained in `sensor/runtime/controller.log`.
- Event lists use readable names such as “Network connection” and “Successful sign-in,” with original event codes retained as supporting detail.
- Added administrator-only Enable/Disable controls to the Rules page, wired to the audited rule management endpoint; rule state remains restricted to administrators.
- Ingestion status refreshes every five seconds; Events and Detections refresh while open.
- Added Windows setup, readable network-adapter listing, permissions, coverage limits, and troubleshooting in `sensor/README.md`.
- Added best-effort sensor spool replay: failed header-only batches are retried while capture continues and remaining files are replayed into the next live session after API recovery. Retries are at-least-once; backend deduplication filters repeats. This is not a guaranteed durable queue.
- Added `docs/DEMO_RUNBOOK.md` with separate real-sensor and synthetic-data walkthroughs and a capability-accurate project summary.
- Coverage is the selected host adapter's visible traffic. It does not imply visibility into all clients on a switched or Wi-Fi LAN.

## Verification status

Verified on 2026-10-22:

- Frontend production TypeScript/Vite build completed successfully in Docker.
- After adding case triage controls, frontend TypeScript/Vite production build completed successfully in Docker; backend, worker, and frontend containers were rebuilt and restarted. `/api/v1/ready` reported database and Redis healthy and the dashboard returned HTTP 200.
- Latest `docker compose up --build -d` rebuilt backend, worker, and frontend successfully after the Rules control change.
- Targeted backend checks passed (4): Remote Desktop match with missing source IP; ordinary local-logon negative; Word→PowerShell match and unrelated-parent negative; same-IP/time correlation with mismatched-IP and out-of-window negatives.
- Sensor queue checks passed (2): an API failure leaves the queued file intact and a later successful retry sends/removes it; malformed files remain for manual recovery.
- After that rebuild, Compose reported backend healthy; `/api/v1/ready` returned `ready` with database and Redis available; dashboard returned HTTP 200.
- The user's Wi-Fi adapter was identified as Intel Wi-Fi 6 AX201, IP `192.168.1.169`, Npcap interface `\\Device\\NPF_{C71419D4-A77A-4AFF-B289-B4FC40CEDBCE}`. This is the active Wi-Fi adapter at verification time.
- Two real 6-second passive capture sessions on that Wi-Fi adapter both completed and forwarded 54 and 113 network records.
- During an additional live capture, the local backend was stopped for about 8 seconds and restarted. The sensor wrote batches to its local spool, retried them after recovery, and completed its session. The resulting job reported 176 accepted, 23 duplicate (deduplicated retry/overlap records), and 0 quarantined events; no spool files remained.
- Authenticated API readback confirmed `windows_remote_interactive_logon` is enabled at version 3.
- Frontend dependency lockfile was generated; Docker `npm ci` install and the production build both succeeded, with the package audit reporting zero vulnerabilities at that build.
- Compose backend `/api/v1/ready` returned `ready`; dashboard returned HTTP 200; configured administrator login succeeded.
- The real Wi-Fi sensor ran a 35-second passive capture and forwarded 60 network flow records. Authenticated API readback showed its session as Online during capture and Stopped after normal completion; another concurrently running session remained Online. This verified the heartbeat and session-state transitions against live sensor activity.
- Frontend build passed after adding the sensor control panel. The Python sensor/controller sources compile; the elevated local controller reported the host adapters, and the browser origin was accepted while an unrelated origin was rejected. An existing manually launched live session was detected, so the controller correctly avoids starting a duplicate. The full UI-driven start/stop transition still needs the user to stop that pre-existing capture and click the controls in the app.
- Authenticated `GET /hosts` returned three telemetry-derived host labels. The `Ahmed` detail endpoint returned 1,335 events, 25 recent events, and 9 linked detections in the current local database (counts change as data changes).
- The built frontend bundle contains the readable event label, recent-telemetry indicator, and administrator-only rule state control.
- The user previously confirmed live Npcap flow forwarding, Windows `auth.success`, and Windows process-start collection in this environment.
- `sensor/live_sensor.py --list-interfaces` now prints readable interface metadata; this verification environment exposed only its loopback adapter, so the user's active Wi-Fi/Ethernet adapter display must be confirmed on the target Windows host.

The Remote Desktop and Word-to-PowerShell rules were validated against controlled event fixtures; a real RDP sign-in and a real Word-launched PowerShell process were not generated on the user's computer. Correlation was validated with controlled evidence values. Windows logons still require enabled audit policy and `--windows-events`; process telemetry additionally requires Audit Process Creation and `--process-events`. The narrow checks above passed; the broader plan in `docs/TEST_PLAN.md` is not fully implemented or passing.

## Known limitations

- Frontend local toolchain depends on Node 22 (Docker image) if the host has no Node.
- Host Python 3.15 is not the supported runtime; the sensor venv should use Python 3.12.

## Remaining demonstration checks

1. Use `docs/DEMO_RUNBOOK.md` to demonstrate actual live traffic, event details, host recent-data status, and evidence-linked detections.
2. For a real-source demonstration of the two Windows-specific rules, wait for authorized RDP or Word→PowerShell activity to occur naturally; fixture validation confirms the matching logic, not that those events occurred on this computer.
3. Continue to describe findings as review signals and the sensor coverage as traffic visible to this one host adapter.


## Update — 2026-10-23

- Added `docs/XDR_CAPABILITY_READINESS.md` to define phased scope and acceptance criteria for sensor fleet identity, endpoint coverage, cloud connectors, cross-source correlation, human-approved response simulation, ML evaluation, and operations. The uncovered production capabilities remain future work; this plan does not claim they are implemented.
- Changed the Windows sensor and controller to require a dedicated `ingestion_service` account from `SENTINEL_SENSOR_EMAIL` / `SENTINEL_SENSOR_PASSWORD` instead of the bootstrap administrator login. Ingestion-only identities can list and operate only live sessions they created; analysts and administrators retain fleet-wide session access.
- Added focused ownership checks in `backend/tests/test_sensor_session_scope.py` and documented account setup through the administrator API. The account must be created with `POST /api/v1/users` and only the `ingestion_service` role.
- Python 3.12 bytecode compilation passed for backend app and tests. Pytest execution was unavailable in this environment because `pytest` is not installed in the Python 3.12 runtime; the change-specific tests have not yet been executed.
- Per-sensor enrollment and independent credential rotation/revocation, live cloud API polling, endpoint coverage beyond the listed Windows event IDs, rejection/expiry for response proposals, complete ML evaluation, and production operational controls remain future work. Response simulation records are implemented but never execute actions.

- Added offline JSON import adapters for AWS CloudTrail, Azure Activity Log, and Entra sign-in exports, three corresponding synthetic walkthrough files, curated provider payload retention, and initial AWS IAM / Azure role-change / Entra high-risk sign-in review rules. These are file adapters; live cloud API polling is not present.
- Added opt-in Windows Security event collection for service installation (4697), scheduled-task creation (4698), audit-policy changes (4719), and Security-log clearing (1102), with selected metadata only and no scheduled-task XML. Added related review rules and a Sensors UI option.

- Extended conservative correlation so Entra high-risk sign-ins and AWS/Azure identity-change findings can group with network discovery only when source IP and the existing 30-minute window agree. This does not yet correlate on account/device/resource identity alone.
- ML inference now rejects missing/mismatched model checksums and malformed metadata before attempting to load an artifact; a missing or invalid model still falls back to rules. This checksum is an integrity consistency check, not a signature against a local actor able to edit both files.

- Added migration-backed, audited response simulation proposals to case investigations. Analysts may propose one of three labeled simulations; proposals expire after seven days; a different administrator can approve or reject with an optional note; an administrator can record an approved simulation. No device, account, firewall, or cloud action is executed.
- Current Docker backend and production frontend images built successfully; Alembic reports revision 003 as head. The app was not started against the user database, and the Python test suite was not run in that pass.
- Added a locally persisted UUID and session metadata for each host sensor (hostname, version, selected capabilities); the Sensors table now displays the self-reported inventory and can detect duplicate sessions by ID. Credential-to-sensor binding and verified enrollment remain future work.
- Bound ingestion-only credentials to one sensor ID/data source at live start, reject cross-credential/source ID claims and a second recent live session, and removed offline file-upload permission from the ingestion_service role. Admin-managed account deactivation or password rotation revokes its tokens. A sensor fleet credential-management UI, cryptographic device enrollment, and race-safe DB uniqueness for simultaneous first enrollment remain future work.
- Backend Python compilation and Docker image build succeeded; the backend container is healthy, the dashboard responds HTTP 200, and an authenticated ingestion-only upload attempt is denied with HTTP 403. The current Windows controller is reachable, but its sensor process and last session are stopped; start it from the Sensors page when ready.

## Update — 2026-10-23 (sensor operation and registration)

- The Sensors start control now waits for the local process and matching API heartbeat before reporting success. Controller connection failures, early sensor exits, and missing heartbeats produce a specific visible error.
- Added a daily Celery Beat retention task (02:15 UTC). It applies each organization's 1–3650 day policy independently, deletes expired security events in bounded batches based on ingestion time, writes per-batch audit records, and retains detections, cases, and audit history. Fixed the Settings API to read/write the tenant-scoped composite-key setting correctly.
- Uploaded ingestion source files are not included in automatic retention cleanup; removing them needs an explicit policy because it irreversibly deletes the original import artifact.
- Added administrator sensor inventory, credential rotation, and revocation UI. Migration 004 enforces unique sensor ID, credential, and data source; credential lifecycle operations are audited and invalidate tokens/server sessions. Revoked sensors stop after their next denied heartbeat and discard unsent batches. The running host process exits after its next denied heartbeat (within 10 seconds) and discards unsent data.
- Rebuilt and restarted backend, worker, and frontend. Alembic is at `004 (head)`; API readiness reports the database and Redis healthy; the UI returns HTTP 200. Backend Ruff and MyPy pass; the frontend TypeScript/Vite production build succeeds.
- A short passive Wi-Fi capture via the local controller stayed running for the observation window, forwarded 10 flow records, created one sensor registration, and completed after the stop request.
- This verifies the Windows host capture path on this one machine and adapter. It does not establish whole-LAN visibility, broad endpoint detection, live cloud APIs, multi-tenant isolation, or commercial production readiness. The signed-in browser click was not automated because only an unauthenticated in-app browser was available; the local controller and API flow were verified directly.
## Update — 2026-10-23 (professional readiness hardening)

- Production-mode settings now reject the development secret, known development database passwords, missing Redis, non-Celery job execution, and non-HTTPS CORS origins. The Compose CORS value can be overridden through `.env`; development loopback origins remain the default.
- The web frontend now sends a restrictive Content Security Policy and standard framing, MIME, referrer, and browser-feature headers. The policy permits only the same-origin API and the loopback Windows sensor controller.
- Added configuration validation tests and a regression test for stable sensor source reuse when a controller version changes its source label. The focused suite passed (11 tests); Ruff passed for the changed Python files; backend and frontend images built and services returned healthy/readiness responses.
- This is an initial hardening step, not production approval. Tenant isolation, SSO/MFA, live cloud polling, retention/deletion execution, backup/restore rehearsal, centralized metrics/alerting, performance testing, broader detection validation, and independent security review remain incomplete.
- Added `.github/workflows/ci.yml`: pull requests and pushes run fresh PostgreSQL migrations, the full current backend tests with coverage, Ruff, MyPy, and a Node 22 production frontend build. Workflow dependencies are pinned to immutable action commits.
- Ran the backend CI sequence locally against a disposable PostgreSQL instance: migrations 001–004 applied, all 25 tests passed, Ruff passed, and MyPy passed. Current backend test coverage is 37%, so the suite is a working baseline rather than comprehensive assurance. The workflow has not run on GitHub because this project has no configured remote.

## Update — 2026-10-23 (organization isolation foundation)

- Added an `organizations` registry and organization IDs across user, sensor, ingestion, event, detection, case, model, settings, and audit records. Migration 005 backfills all existing rows into the `default` organization, changes selected unique keys to organization scope, and enables forced PostgreSQL row-level security.
- Login now accepts an organization slug; access and refresh tokens carry that organization and authenticated database sessions apply its transaction-local context. The dashboard now sends the selected organization slug.
- Added a one-shot Compose role provisioner. The API and worker use a non-superuser, non-`BYPASSRLS` runtime role; a separate one-shot migration service uses the non-superuser schema-owner role and does not pass its credentials to the long-running API/worker. Added a tenant provisioning CLI that creates an organization, its first administrator, and built-in detection rules.
- Added a PostgreSQL RLS integration test to CI that checks every tenant-owned model has forced RLS and verifies tenant row visibility, blocked cross-tenant writes, unscoped access, and runtime-role flags. On a clean isolated PostgreSQL database, migrations 001–005 completed, all 30 backend tests passed, Ruff and MyPy passed, and the production frontend build passed.
- Applied migration 005 to the local project database only after creating a 1.8 MB custom-format PostgreSQL backup at `.data/backups/sentinel-pretenant-20261023.dump`; `pg_restore --list` recognized the archive. The migration preserved two users and 24 ingestion/sensor session rows. The local API and dashboard both returned HTTP 200, and the backend connected as `sentinel_runtime` with neither superuser nor RLS-bypass privileges. API environment inspection confirmed the migration URL and bootstrap database password are absent.
- Remaining at this point: SSO, live cloud polling, broader endpoint coverage, retention/deletion execution, alerting/load tests, representative real-data rule validation, and independent security review. Tenant RLS is an application-mediated boundary, not a substitute for external review.

## Update — 2026-10-23 (TOTP MFA implemented and verified locally)

- Added an additive migration for organization MFA policy, encrypted TOTP secrets, replay tracking, challenge IDs, and hashed one-time recovery codes. Added enrollment, login challenge, required-MFA setup, recovery, disable, and administrator policy endpoints; production configuration requires a dedicated 32-byte MFA encryption key.
- Added MFA screens for authenticator enrollment, sign-in verification, organization enforcement, and recovery-code display. Added RFC 6238 and encrypted-secret/recovery-code unit tests.
- Verified in this session: Python 3.12 backend suite (36 passed, including PostgreSQL RLS and MFA API lifecycle), Ruff and MyPy; frontend TypeScript/Vite production build; migration 006 on an isolated restored copy and on the main DB; main data counts remained at 2 users and 24 ingestion/session rows; MFA API end-to-end (enrollment, TOTP replay rejection, single-use recovery codes, refresh, enable/disable policy, forced setup); local API readiness, OpenAPI MFA routes, and dashboard HTTP 200. Backend statement coverage is 57% overall and 81% for auth routes. A fresh 1.85 MB custom-format backup was inspected by `pg_restore --list` before the migration.
- Applied migration 006 to the local database and rebuilt/restarted backend, worker, and frontend. The restored test copy was dropped after its migration/RLS/MFA checks. MFA encryption uses the development-only SECRET_KEY-derived key in the current development stack; production must set and protect a separate `MFA_ENCRYPTION_KEY` and plan key recovery/rotation.
- Remaining: SSO, cloud live polling, broader endpoint coverage, retention/deletion execution, recurring and automated backup/restore operations, production alerting/load testing, representative real-data rule validation, and independent security review. This local verification is not commercial-production approval.

## Update — 2026-10-23 (network discovery host visibility)

- The bounded network-discovery code now attempts Scapy ARP discovery for directly connected IPv4 networks before selected TCP port checks. ARP-discovered devices remain visible even when every selected TCP port is filtered; each result explains whether it was discovered by ARP, TCP, or both. If Scapy/Npcap or local-link routing prevents ARP, the scan falls back to the existing bounded TCP checks.
- The sensor controller reports a unique scan ID, addresses checked, responding-device count, start/finish timestamps, and elapsed duration. The UI labels the host discovery source and clarifies hotspot/client isolation and firewall limitations.
- Ingestion raw-payload redaction now catches nested camelCase, snake_case, and hyphenated secret names such as `accessToken`, `client_secret`, `X-API-Key`, `Set-Cookie`, and `privateKey`; non-sensitive keys such as `userName` remain intact.
- `sensor/tests/test_network_discovery.py`: 14 tests passed, including ARP-discovered hosts with filtered ports. Focused backend parser/control tests passed (13 passed, one platform-dependent symlink test skipped). Ruff passed across all changed Python files. Frontend TypeScript no-emit check and Vite production build passed; build output was written to the separate Codex workspace because the source project folder is read-only in this execution context.
- Not verified on the user's active Wi-Fi/hotspot in this turn: actual ARP visibility, phone hotspot client isolation, and updated Docker image deployment. A real authorized-LAN check is still required. The utility still does not scan UDP, perform OS fingerprinting, or conduct vulnerability tests.

## Update — 2026-10-23 (canonical event schema validation)

- Added `NormalizedEventV1` and a shared validator for JSON/CSV, Zeek, Suricata, AWS, Azure, Entra, and live Windows event ingestion. Invalid normalized rows are quarantined with field-only errors; raw values are not included in validation messages. Schema v1 is a SentinelAI compatibility envelope with documented ECS relationships, not a full ECS/OSSEM implementation.
- Added `docs/EVENT_SCHEMA.md` to define field meanings, bounds, adapter coverage, and migration requirements before any future schema reinterpretation.
- Regression coverage verifies every adapter passes v1 and that invalid IP/port/schema version values fail safely. Focused backend tests passed (15 passed, one platform-dependent symlink test skipped); Ruff passed across changed files; MyPy passed on the five changed backend ingestion/API modules. Frontend TypeScript/Vite build and scanner tests remain green from the immediately preceding network-discovery update.

## Update — 2026-10-23 (canonical event identity hygiene)

- Fixed Zeek normalization: `uid` is a connection identifier, not an endpoint host ID. It now remains in `attributes.connection_id` and the dedup key; `host_id` is unset so it cannot falsely correlate unrelated endpoints.
- Fixed Suricata EVE normalization: top-level `host` is retained as `attributes.source_host_context`, not treated as verified endpoint identity. `host_id` remains unset absent endpoint provenance.
- Added regression tests for both identity mappings. Verification: focused backend tests 17 passed, 1 platform-dependent skip; Ruff passed; MyPy passed for the modified parser. No live Zeek/Suricata pipeline or deployed app was exercised in this check.

## Update — 2026-10-23 (sensor event-source diagnostics)

- Live sensor heartbeats now report the selected interface, cumulative forwarded event count and type counts, timestamp of the last forwarded record, configured Windows Security event IDs, IDs actually observed, and whether Windows log polling is enabled, disabled, or failed.
- The API validates bounds and rejects unknown diagnostic fields, negative counters, unsupported source states, oversized ID arrays, and overlong event names. Diagnostics are stored on the tenant-scoped data source config and included in live-session/registered-sensor responses; no new DB migration is needed.
- The Sensors table now renders capability names in plain language, reports forwarding and last-event state, and distinguishes selected Windows event IDs from IDs observed. A selected ID is only the sensor filter; it does not prove the Windows audit policy generates that event. An event observed proves receipt, not complete endpoint coverage.
- Added diagnostics schema tests, including invalid/duplicate Windows Event ID rejection. Focused backend tests: 26 passed, 1 platform-dependent skip; Ruff passed for the changed API/tests; MyPy passed for the API module; frontend TypeScript no-emit and production Vite build passed. Sensor Python syntax parsed successfully. The user's running Docker stack and live Windows sensor have not been updated or verified.

## Update — 2026-10-23 (read-only cloud connector foundation)

- Added tenant-scoped `CloudConnector` records and migration 008. The new table has forced RLS, organization-scoped foreign keys, a linked data source, encrypted credentials, a safe timestamp cursor, enable/status fields, and last-poll health fields.
- Added read-only AWS CloudTrail `LookupEvents`, Azure Activity Log list, and Microsoft Graph Entra sign-in pollers. Polling uses explicit provider credentials, AES-GCM encrypted at rest with a dedicated `CLOUD_CONNECTOR_ENCRYPTION_KEY`, OAuth client credentials for Microsoft APIs, bounded pagination, retry handling, safe cursor overlap, and the existing normalized ingestion/detection pipeline.
- Administrators can add, rotate, pause, enable, and manually poll cloud connectors through `/api/v1/cloud-connectors`; analysts can read health. Celery Beat queues enabled connectors every five minutes. The dashboard now has a Cloud connectors page with source setup and status.
- Added `docs/CLOUD_CONNECTORS.md` with permissions, setup, polling limits, and validation boundaries. Provider permissions remain read-only. Entra sign-in collection requires the provider's P1/P2 license. Azure built-in Monitoring Reader has broader effective access; operators should review it or use a narrower custom role.
- Verification: 68 backend tests passed; three skipped (PostgreSQL-backed MFA API flow not provisioned, Windows directory symlink unavailable, RLS test role not configured). Focused Ruff and MyPy passed. Frontend TypeScript and Vite production build passed. Alembic 001–008 applied successfully to a temporary PostgreSQL database, which was then dropped; the active application database was not migrated.
- No live AWS/Azure/Entra account was used. The running Compose stack has not been rebuilt or restarted, and migration 008 is not applied to that stack. Before use, set the dedicated connector key, deploy the new build/migration, and validate each provider against a user-owned test account. The earlier hotspot ARP acceptance test also remains unverified.
- Next: deploy migration 008 and updated containers after reviewing `.env` key configuration; configure one test cloud provider with narrowly scoped read access; validate end-to-end ingest, deduplication, retries, cursor recovery, health display, and revocation. Then continue endpoint coverage, entity-graph correlation, ML evaluation, backup/restore, monitoring, and independent security review.

## Deployment update — 2026-10-23

- Created the documented pre-deployment backup at `backups/manifest-20261023T181917Z.json`; SHA-256 checksums for the PostgreSQL dump and app-data archive both match.
- Generated a local `CLOUD_CONNECTOR_ENCRYPTION_KEY` in `.env` (secret value intentionally not recorded here). The first container startup exposed a missing Base64 padding issue; regenerated the key in the format required by settings validation.
- Built and started the updated backend, worker, Celery Beat, and frontend. Increased pip download timeout/retries in `backend/Dockerfile` after the package host timed out during the first build.
- Rebuilt the separately tagged `db-migrate` service and applied migration 008 to the application database. `alembic current` reports `008 (head)`.
- Final local checks: backend healthy; `/api/v1/ready` returns HTTP 200; `/api/v1/cloud-connectors` returns HTTP 401 when unauthenticated, confirming the route is registered and protected; frontend returns HTTP 200. PostgreSQL, Redis, worker, and Celery Beat are running.
- No AWS/Azure/Entra credentials were available, so live provider polling remains unverified. Hotspot ARP visibility is still pending.

## Follow-up — live-cost choice and hotspot ARP check (2026-10-23)

- Compared official provider pricing and prerequisites. Selected AWS CloudTrail Event History as the first live integration candidate: the `LookupEvents` API for the built-in 90-day management-event history has no CloudTrail charge. No AWS account exists yet, so live provider validation is blocked until the user creates/accesses an account and supplies a narrowly scoped `cloudtrail:LookupEvents` credential through the local UI. No AWS resources or paid CloudTrail features were created.
- Ran the project's ARP-only host discovery against the active private Wi-Fi `/24`. It returned the local host and gateway only; no second client was visible. This confirms basic ARP visibility on that link, but does not establish phone-hotspot client-to-client visibility or isolation.
- The real scan exposed a bug where the scanner compared an IP-address string against an IP network. Fixed `sensor/network_discovery.py` to parse the response before membership testing. Verification: all 15 `sensor/tests/test_network_discovery.py` tests passed and Ruff passed; the ARP-only scan then completed with two responders.
