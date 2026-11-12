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

## Update — 2026-10-24 (user-confirmed local validation and production boundary)

- The user confirmed AWS CloudTrail events are visible in SentinelAI after polling. This validates the configured AWS path in this local lab; it is not evidence of Azure/Entra validation or a production deployment.
- The user confirmed the Windows sensor/controller was started and later confirmed that Windows events are listed and the source filter now works. The Devices view showed the Ahmed host seen within the last two minutes and its event count increased from 16,666 to 16,671. This confirms recent sensor telemetry/heartbeat; it does not by itself prove every optional Windows audit category is enabled.
- `docs/OPERATIONS.md` was corrected to reflect current OIDC and read-only cloud-polling implementation and to state what remains unverified for commercial production.
- Next production-readiness milestone: perform a backup/restore rehearsal only against an isolated clone, then record measured recovery time and data-loss window. Do not run `scripts/restore.ps1` against the user's active workspace as a test. Follow with encrypted off-host backup/key recovery, alert delivery/on-call, load and tenant-isolation validation, detection evaluation, and independent security review.
- No application code, database, or running service was changed in this update. No tests were run for the documentation-only correction.

## Update — 2026-10-24 (sensor identity proof)

- Added a per-installation Ed25519 signing key stored under ignored `sensor/runtime/`; the key does not leave the host.
- Sensor-only live session starts pin the key to the registered sensor after verifying a signed request. Heartbeats, event batches, and session finishes now require a fresh signature over the HTTP method, path, sensor ID, timestamp, and exact request body.
- Added migration 009 to store the pinned public key and included a public-key fingerprint in the administrator sensor-registration response. Older registrations adopt a key after both server and sensor software are upgraded and the sensor starts with its existing dedicated credential.
- This is trust-on-first-use device identity. It does not provide hardware-backed attestation or protect the private key from an administrator who can read the Windows project directory. Live signed-session compatibility remains unverified until the updated controller reconnects.
- Migration 009 was applied to the local database; the API reports ready with database and Redis healthy. The sensor virtual environment now has `cryptography==50.0.2`. No sensor/controller process was running at verification time, so signed enrollment and live event forwarding still need confirmation after the elevated controller is started.

## Update — 2026-10-24 (isolated backup/restore rehearsal)

- Verified the existing 2026-10-23 backup manifest checksums and safely listed/extracted its app-data archive in an ephemeral container. The database restored successfully in an isolated, network-disabled PostgreSQL container, but its Alembic revision was 007; do not use that older snapshot to recover the current deployment without applying/reviewing migrations.
- Created a fresh backup from the running deployment with `scripts/backup.ps1`; manifest SHA-256 verification passed. The new backup is `backups/manifest-20261024T032658Z.json`.
- Repeated the rehearsal using the fresh backup. Database restore completed in a separate, disposable, network-disabled PostgreSQL container; verification found 24 application tables and Alembic revision 009. The app-data archive checksum, listing, and extraction also passed in an ephemeral container.
- The active database, app-data volume, and application services were not modified or restarted by the rehearsal. Temporary containers were removed.
- Recovery duration and recovery-point objective were not formally measured. The verified backup remains on the same machine; encrypted off-host storage and key recovery are still outstanding.

## Update — 2026-10-24 (off-site backup preparation)

- Added an S3 uploader that verifies the local manifest and SHA-256 values before sending the database dump, app-data archive, and manifest to a timestamped prefix. It explicitly requests SSE-S3 over TLS, verifies remote size/encryption/hash metadata, avoids replacing different existing objects, and uploads the manifest last as a completion marker.
- Added least-privilege writer and bucket-policy templates, a private Windows credential-profile setup script, manual and daily scheduled backup wrappers, and operator guidance for public-access blocking, versioning, lifecycle expiry, and key protection.
- AWS CLI and local AWS profiles are unavailable in this environment; the existing CloudTrail reader identity is intentionally read-only. A private S3 backup bucket was provisioned later in this update. No telemetry or backup file has been transmitted to AWS.
- Live off-site backup remains pending: configure a dedicated writer identity and its local profile, choose an explicit retention policy, authorize backup transfer, then run the uploader and verify the S3 objects. S3 SSE-S3 encrypts at rest without separate KMS key charges; AWS account MFA and recovery remain necessary.

## Update — 2026-10-24 (workstreams 1–5 validation)

- Fixed a stale registered-sensor source-rename test to match the asynchronous endpoint and its current signed-enrollment contract. The focused test passed.
- Hardened simulated response proposals: case/proposal rows are locked during creation and state transitions; a concurrent duplicate idempotency request now returns the existing matching proposal or a controlled 409 conflict.
- Verification: all 68 runnable backend tests passed; three integration/platform tests were skipped because their PostgreSQL test roles/database or Windows symlink capability are not configured. All 20 sensor tests passed (the two spool-replay tests ran from an isolated copy in the permitted temporary workspace because their fixture writes under `sensor/.data`).
- Live acceptance still required: two independent sensors with separate revocation/isolation; per-event Windows policy fixtures and volume/privacy checks; Azure/Entra live API validation; production tenant-separated correlation fixtures; and response target binding/security review. The S3 bucket exists, but writer credentials, lifecycle retention, and backup transfer are still pending.

## Update — 2026-10-24 (S3 bucket provisioned)

- Created `sentinelai-xdr-offsite-20261024-a84f39` in AWS `us-east-1`. It has Block Public Access enabled, Bucket owner enforced object ownership, versioning enabled, and default SSE-S3 encryption.
- Applied a bucket policy denying non-TLS requests and requiring the `AES256` server-side encryption header for uploads under `sentinelai-xdr/`. The bucket is currently empty.
- Remaining before backup operation: configure the 30-day lifecycle expiry for current/noncurrent versions, create a dedicated least-privilege writer identity, configure its credential locally without exposing it, and obtain authorization to upload the PostgreSQL dump and app-data archive to this bucket. No backup data has been sent to AWS.


## Verification update — 2026-10-24 (workstreams 1–5)

- Added signed sensor proof regression coverage for valid requests, body/path/identity tampering, timestamp expiry, and replay rejection.
- Verification after the latest changes: backend 74 passed, 3 skipped; sensor 20 passed; Ruff passed for the modified API/test files; frontend Vite production build passed.
- The local AWS bucket is private, versioned, TLS-only, and enforces SSE-S3 for the backup prefix. It remains empty pending the user's action-time decisions on retention expiry, dedicated writer access, and upload of named local backup files.

- Follow-up: created the enabled sentinelai-xdr-30-day-retention lifecycle rule for the sentinelai-xdr/ prefix. Current versions expire after 30 days and noncurrent versions are permanently deleted after 30 days.
- Created IAM user sentinelai-backup-writer with console access disabled and attached SentinelAIBackupWriterPolicy, scoped to s3:GetObject and s3:PutObject under this bucket prefix. No access key has been created or exposed. The user must create the key and store it locally with scripts/configure_aws_backup_profile.ps1 before off-site transfer can run.

- Prepared current local snapshot manifest-20261024T054504Z.json; database dump (2,567,679 bytes) and app-data archive (430,838 bytes) both match their SHA-256 manifest entries. No S3 objects have been uploaded yet.

- Retention note: because the bucket is versioned, expiry at day 30 creates a delete marker; that version is then deleted after a further 30 days as a noncurrent version. A version that remains current until expiration can therefore remain stored for about 60 days from upload.

## Update — 2026-11-10 (first off-site backup uploaded and verified)

- Fixed `scripts/upload_offsite_backup.py`: the writer identity has no `s3:ListBucket`, so S3 answers 403 rather than 404 for a key that does not exist and the pre-upload existence check aborted every first upload. A 403 is now treated as "absent" only before an upload; post-upload verification is unchanged and still rejects it. Checked against a stub S3 client (403/404 pre-check, 403 after upload, identical existing object, different existing object, 500).
- `scripts/configure_aws_backup_profile.ps1` now refuses a secret that is not 40 valid characters, after a failed paste stored a 1-character secret.
- The user created the `sentinelai-backup-writer` access key and stored it locally; `sts:GetCallerIdentity` confirmed the profile resolves to that user. The credential file ACL is limited to the user's Windows account.
- Ran `scripts/offsite_backup.ps1`. A fresh local backup `manifest-20261110T093405Z.json` was created and uploaded to `s3://sentinelai-xdr-offsite-20261024-a84f39/sentinelai-xdr/20261110T093405Z/` (database dump 3,008,527 bytes, app-data archive 25,171,082 bytes, manifest 298 bytes).
- Independent verification with the writer profile: each of the three objects was downloaded again and its SHA-256 and size match the local file and manifest; each reports SSE-S3 (`AES256`) and a version ID. The 2026-10-24 snapshot was not uploaded; the script always uploads a fresh backup.
- Incident note: during setup an access key belonging to `sentinelai-cloudtrail-reader` (ID ending `WEHAU`) was pasted into the assistant chat. The user reported on 2026-11-10 that the key was deleted in IAM; this was not independently verified because the writer identity cannot read IAM. Whether the SentinelAI AWS cloud connector was re-keyed afterwards is not confirmed.
- Still open: a restore test from S3 using a separate read/administrator identity, the daily off-site scheduled task (`scripts/install_offsite_backup_task.ps1`, not installed), measured recovery objectives, and cleanup of the two extra local backups from failed attempts on 2026-11-10. These changes are on branch `fix/offsite-upload-403-precheck`.

## Update — 2026-11-10 (repository hygiene)

- Committed the work that had accumulated since the handoff baseline as separate commits (signed sensor identity and migration 009, response-simulation locking, event source labels, app-data volume init, off-site S3 backup tooling, documentation) and merged the branch into `master`. The default branch of this repository is `master`, not `main`.
- Before committing, fixed what the existing CI workflow would have rejected: nine Ruff findings in `app/api/v1/ingest.py` and `router.py` (import order, line length) and two MyPy errors in `ingest.py` and `events.py`. These are formatting and type-annotation changes only. Afterwards: backend 74 passed, 3 skipped; sensor 20 passed; `ruff check app tests` and `mypy app` pass. The running containers were not rebuilt for this.
- `ruff check .` over the whole backend still reports 71 findings in `alembic/` (mostly line length in applied migrations). CI does not lint that directory and applied migrations were left untouched.
- `Etik_Hacker_Vize_Notlari_Modul_1-3.2.md` in the project root is unrelated to this project and was deliberately left untracked.
- No Git remote is configured and the GitHub CLI is not installed on this host, so `.github/workflows/ci.yml` has still never run. Source code exists only on this machine until a remote is added and pushed.

## Update — 2026-11-10 (restore rehearsal from S3, measured)

- Downloaded `sentinelai-xdr/20261110T093405Z/` from S3 into a temporary directory with the writer profile (its `s3:GetObject` permission), verified both artifacts against the downloaded manifest, and restored the dump into a disposable `postgres:16-alpine` container started with `--network none`. The live database, volume, and services were not touched; the container and downloaded copy were deleted afterwards.
- Result: `pg_restore --exit-on-error` exited 0. The restored database is at Alembic 009 with 24 tables, 21 forced-RLS tables and 21 policies, 25,546 security events, 112 detections, 27 cases, 2 users, 753 audit rows, 1 sensor registration, and 1 cloud connector. The app-data archive extracted to 250 files (about 155 MB) under `uploads/` and `ml/`.
- Measured on this host: download and hash verification 7.8 s; PostgreSQL start 2.2 s; database restore 2.0 s; app-data extraction 1.8 s — about 14 s for the data steps at the current size (3 MB dump, 25 MB archive).
- This is not a full recovery-time objective. It excludes provisioning a replacement host, installing Docker, obtaining the source code and images, restoring `.env`, starting the application, and an application-level check (sign-in, event, case, audit record). The application was not started against the restored copy.
- Recovery-point: the newest event in the backup was ingested 8 min 59 s before the backup timestamp, which reflects event arrival, not loss. The actual data-loss window equals the time since the last successful off-site upload. Uploads are manual today, so that window is unbounded; with the daily task installed it would be up to 24 hours.
- Gaps found: (1) `.env` is not in the backup. Without its `MFA_ENCRYPTION_KEY` and `CLOUD_CONNECTOR_ENCRYPTION_KEY` (or the `SECRET_KEY` they are derived from in development), restored TOTP secrets and cloud-connector credentials cannot be decrypted. These keys need a separate protected copy. (2) The restore requires roles `sentinel_migrator` and `sentinel_runtime` to exist first. (3) Source code is still not stored off this machine. (4) The rehearsal used the writer identity; a dedicated read identity for restores does not exist yet.

## Update — 2026-11-10 (daily off-site backup task installed)

- Installed the Windows scheduled task `SentinelAI Daily Off-site Backup` with `scripts/install_offsite_backup_task.ps1`. It runs `scripts/offsite_backup.ps1` daily at 03:00 local time as the signed-in user with limited rights, and starts at the next opportunity if the time was missed. The backup was deliberately not added to Celery Beat: the job drives Docker from the host and the writer credential should stay out of the containers.
- Verified by triggering the task once through Task Scheduler: last result 0, new backup `20261110T095014Z` created, and all three S3 objects present with matching SHA-256 metadata and SSE-S3. The first unattended 03:00 run (2026-11-11) has not happened yet.
- Limits: the task runs only while this Windows user is signed in and Docker Desktop is running; it writes no log file and sends no failure notification, so a failed run is visible only in Task Scheduler history or as a missing S3 prefix. Local files in `backups/` are not pruned (about 28 MB per day at the current size); S3 copies follow the 30-day lifecycle rule. `scripts/remove_backup_task.ps1` removes only the local-backup task; remove this one with `Unregister-ScheduledTask -TaskName "SentinelAI Daily Off-site Backup"`.

## Update — 2026-11-10 (alert notification channels)

- Added tenant-scoped notification channels (generic webhook with optional HMAC signature, Slack-compatible webhook, Telegram bot), a delivery outbox, an administrator API, and a **Notifications** page with Turkish translations. Migration 010 adds `notification_channels` and `notification_deliveries`, both with forced RLS. See `docs/OPERATIONS.md` → Alert notifications for behaviour and limits.
- New detections at or above a channel's minimum severity queue a message in the same transaction; Celery Beat delivers every 30 seconds with five attempts and backoff. Messages exclude the finding summary unless enabled per channel and never include raw events. Destinations are encrypted, HTTPS only, no redirects, and refused when they resolve to non-public addresses.
- Verification: backend 104 passed, 3 skipped (30 new tests cover URL rules, the internal-address guard, address pinning with the TLS host name, redirect refusal, secret-free errors, signature, payloads, input validation); Ruff and MyPy pass; frontend production build passes. Took backup `20261110T100103Z`, then applied migration 010 and rebuilt the stack: Alembic `010 (head)`, both tables report forced RLS, the unauthenticated API returns 401, readiness and dashboard are healthy.
- Live pipeline check: a temporary channel pointing at a public host name that resolves to 127.0.0.1 was queued directly in the database; the scheduled worker run picked it up within 30 seconds and recorded `Destination resolves to a non-public address` with one attempt. The temporary channel was removed and both tables are empty.
- Not verified: a successful delivery to a real Slack, Telegram, or webhook receiver (no destination was available), the signed-in UI flow, the outbox logic against PostgreSQL in automated tests (covered only by the live check above), and behaviour under a burst of findings. No channel is configured, so nothing is being sent yet.
- Follow-up, same day: the user created a generic webhook channel in the Notifications page (minimum severity `high`, summary excluded) and pressed **Send test**. Database records show the channel creation and test request in the audit log, and one test delivery marked `sent` on the first attempt 26 seconds after it was queued, with no error. This confirms the signed-in UI flow and a successful HTTPS delivery (the receiver answered 2xx). Receipt was reported by the user and not observed independently. A notification triggered by a real detection, the Slack and Telegram formats against real services, and the signature check on a receiver remain unverified.
- Load test and ML evaluation (same day): see `docs/PERFORMANCE_AND_ML_EVALUATION.md`. In an isolated Compose project, 160,000 synthetic events ingested at 430–530 events/s with no failures; the API saturates at about 75–115 requests/s on one Uvicorn process; text search and `/hosts` degrade with stored events; the worker peaked at 1.9 GB because detection loads every event from the last two hours. No ML model is deployed (no artifact, scikit-learn not in the image). Evaluated offline on a seeded synthetic population with the project's settings, the Isolation Forest flags about 15 % of benign entities by construction, flags every NAT gateway, and does not beat two fixed thresholds; it should stay disabled. These are single-run laptop measurements and synthetic-data results, not capacity guarantees or a real-world false-positive rate. The live database was not loaded with test data.
- Detection window memory (same day): `run_detection_for_job` now selects only the ten columns the detectors read instead of loading full ORM entities with their raw payloads. The same events are evaluated. Repeating the 160,000-event load test in the isolated stack, worker peak memory fell from 1,875 MiB to 1,337 MiB (about 29 %) with unchanged ingestion throughput and no errors; one run each, so treat the size of the gain as approximate. The window still loads every event from the last two hours, so memory still grows with event rate. Against the real database, in a transaction that was rolled back, the new window returned the same event IDs and identical dictionaries as the previous code and the detection run completed. That check covered a window of only 23 events.
- Dependency lock (same day): added `backend/requirements.lock` (75 packages with SHA-256 hashes, resolved for Linux and Python 3.12 with the versions of the then-running image as constraints) and `sensor/requirements.lock` (pip freeze of the Windows sensor environment, no hashes). The backend image and CI now install with `--require-hashes`. After rebuilding the live stack from the lock, `pip freeze` in the new image is identical to the previous image, the worker reports ready, a scheduled task succeeded, readiness and the dashboard are healthy. The CI change is untested because CI has never run. `requirements-ml.txt` and base image tags are not locked.
- Encrypted `.env` backup (same day): added `scripts/env_backup.py` with `backup_env.ps1` and `restore_env.ps1` (scrypt + AES-256-GCM, interactive passphrase, never overwrites files) and a reminder in `backup.ps1`. Six tests cover round trip, wrong passphrase, tampering, and overwrite refusal. The operator then ran `scripts\backup_env.ps1`: `backups/env-20261110T143750Z.enc` exists with the expected header, its size equals `.env` plus the 52-byte envelope, it contains no plaintext marker, and `.env` has not changed since. It was not decrypted here because the passphrase is the operator's, so the restore path with the real file is unverified beyond the tool's own write-time check. The encrypted file stays local and is not uploaded off-site.
- Documentation (same day): rewrote `README.md` and added `DEPLOYMENT.md` (installation, configuration, production-mode checks, TLS and exposure, dependency lock, upgrades, recovery on a replacement host, built-in hardening and its gaps). While writing it, noted that the API trusts the first `X-Forwarded-For` value for audit records without checking the sender; this is documented as a deployment requirement and not fixed.
- Verification for the four items above: backend 113 passed, 3 skipped; sensor 20 passed; Ruff and MyPy pass. Backup `20261110T142910Z` was taken before the rebuild.
- Unattended off-site backup confirmed (2026-11-12): the scheduled task ran on 2026-11-11 at 03:00 and on 2026-11-12 at 04:51 local time (started late after the machine woke), both with result 0. All three objects for `20261111T000003Z` and `20261112T015131Z` are present in S3 with SSE-S3.
- Git remote (2026-11-12): pushed `master` to the private GitHub repository `ahmeduni126-gif/sentinelai-xdr` after scanning the full history for credentials (none found; `.env`, `backups/`, and sensor keys are untracked). The repository returns 404 without sign-in, and the remote `master` matches the local commit. Only `master` was pushed. Source code now exists off this machine. The CI workflow should have started on this push, but its result has not been observed: no authenticated GitHub session was available to read it. Until someone checks the Actions tab, CI is still unverified, including the new hash-pinned install step.
- CI first runs (2026-11-12): the first run failed in "Run Windows sensor parser tests" with `ModuleNotFoundError: No module named 'scapy'`; the workflow had never installed the sensor's dependencies, which went unnoticed because CI had never run. Added an install step for `sensor/requirements.txt`, after reproducing the fix in a `python:3.12-slim` container (lock install, sensor tests 20 passed, Ruff and MyPy clean). The user reported the following run green. The run log was not read here, so which tests were skipped in CI (for example whether the RLS test's `TENANT_TEST_DATABASE_URL` is set) is not confirmed.
- Incident during deployment: the rebuild installed `kombu` 5.7.0, an unpinned dependency of Celery, which rejects `redis==5.2.1`; the worker crash-looped for about three minutes, during which queued ingestion and cloud polling did not run. Pinned `kombu==5.6.2` and rebuilt; the worker is ready and a cloud poll succeeded afterwards. Other transitive dependencies are still unpinned, so a future rebuild can break the same way until a full lock file exists.

## Update — 2026-11-12 (two independent sensors, live test)

- Setup: a second sensor ran in a VirtualBox Windows 10 guest on a host-only network (`192.168.56.0/24`), with its own `ingestion_service` account (`sensor-vm@localhost.local`, created with `scripts/create_sensor_account.ps1`) and its own generated identity. The guest reached the loopback-only API through `scripts/sensor_lab_network.ps1` (port forwarding plus a firewall rule limited to the host-only subnet), over plain HTTP. The host sensor ran at the same time under `sensor@localhost.local`.
- Independent enrollment: two `sensor_registrations` rows with different sensor IDs, credentials and data sources (`Ahmed-live-sensor`, `vm-win10-sensor`).
- Concurrent ingestion: both sessions were `running` and both event counts rose over the same 45 seconds (host 127 to 166, guest 88 to 99); each sensor's events landed only under its own data source and host record.
- Separate revocation: the administrator revoked the guest sensor in the panel at 08:04:46 UTC. Its registration became `revoked`, its account inactive with the token version incremented, its session closed, and `sensor.registration.revoked` was audited with `closed_sessions: 1`. The guest's last event was 8 seconds before the revoke and its count stayed at 172. The host registration stayed `active` and its count kept rising (577 to 647 in the following 30 seconds).
- Sensor accounts are isolated from analyst APIs: signed in as the host sensor account, `GET` on events, detections, cases, hosts, users, audit logs, rules, notification channels, registered sensors and ingestion jobs all returned 403, as did creating a user, rotating or revoking a sensor, and file upload. Only its own live-session listing returned 200.
- Not tested here: a sensor presenting another sensor's ID or key, replayed requests, a second session with the same credential, and re-login from the guest after revocation (the server-side state makes it impossible, but the attempt was not observed). The guest connection was unencrypted; a sensor on a real network still requires TLS.
- Interface fix: the "Registered sensors" panel was a collapsed disclosure with its marker hidden, so it looked empty. It now opens by default.
