# SentinelAI XDR — Capability Readiness Plan

This plan closes the documented gaps without changing the product into a generic small-business monitoring tool. SentinelAI remains a defensive XDR platform: collect authorized endpoint, network, identity, and cloud signals; normalize and correlate them; support evidence-based analyst investigation; and keep response human-approved and auditable.

## Current baseline

Implemented now: local Docker deployment; role-based user access and audit logging; JSON/CSV, Zeek, and Suricata file ingestion; passive Windows-host TCP/UDP metadata; optional Windows Security logon/unlock and process-start telemetry; transparent rules; limited IP/time detection correlation; case workflow; and a local analyst console.

The baseline is a lab prototype. A checked-in connector or rule is not proof of operational coverage. Each source needs a documented setup path, health signal, representative fixtures, and an end-to-end verification before it is called ready.

The bounded Network discovery utility now attempts ARP host discovery on directly connected IPv4 links in addition to the selected TCP checks, and reports the scan address count and discovered-device count. This improves host visibility when selected ports are filtered, but does not bypass hotspot/client isolation or routed network boundaries. It remains a limited discovery aid, not a full Nmap replacement or XDR telemetry source.

All existing import adapters and live Windows event batches now pass through a shared `NormalizedEventV1` validator before persistence. It enforces timestamp, IP/port, severity, identifier length, and schema-version constraints and quarantines an invalid row without echoing its values. See `docs/EVENT_SCHEMA.md`. This is a versioned SentinelAI envelope with documented ECS field relationships, not full ECS/OSSEM conformance.

## Workstreams and exit criteria

### 1. Sensor identity and fleet management — first

- Give each sensor a distinct revocable ingestion credential; stop using a human administrator login in the sensor controller.
- A local UUID and Ed25519 key now persist under ignored `sensor/runtime/`; the API pins the public key and requires signed live-start, heartbeat, event-batch, and finish requests. Sessions also report host, version, selected capabilities, heartbeat, and status. Host name and capabilities remain self-reported; key enrollment is trust-on-first-use, not hardware-backed attestation. The Sensors table displays session details and matches duplicate online sessions by stable ID.
- The first live-session start binds a sensor-only account to one sensor ID and data source. Rebinding, claiming a source owned by another credential, registering that ID under another source, and starting a second recent session are rejected. Existing source metadata alone is not enough to claim a source; a matching session previously created by that credential is required for legacy binding.
- Sensor-only accounts can no longer upload offline import files; their API access is limited to their own live-session creation, heartbeat, event batches, finish, and session listing. Standard administrator user deactivation/password rotation revokes issued tokens. Migration 004 now enforces one-to-one sensor ID, credential, and data-source uniqueness under concurrent enrollment. Administrators can list registrations, revoke access, or rotate a sensor credential from the Sensors page; these operations invalidate tokens and close server-side sessions. A running host process exits when its next heartbeat is rejected (within 10 seconds), then discards unsent batches.
- Support rotation/revocation and show the owning sensor and health details in the Sensors view. Credential lifecycle is implemented. Signed requests and key pinning are implemented in code; deployment/migration compatibility and multi-device operation still need live verification. Hardware-backed attestation and multi-tenant fleet administration remain open.
- Exit when two independent sensors can enroll, ingest concurrently, be separately revoked, and remain isolated from analyst APIs. Current binding supports independent credentials and pinned keys, but this multi-sensor acceptance condition remains unverified.

### 2. Endpoint signal coverage

- Keep existing logon and process-start collection opt-in and privacy-limited.
- Define a versioned endpoint event contract and add Windows service/task/persistence and security-control-change signals only through supported Windows audit sources. Opt-in allowlisted metadata now includes account lifecycle and security-group membership events, service/task changes, audit-policy changes, and Security-log clearing; this is a partial source, not full endpoint coverage.
- Add per-source audit-policy diagnostics and clear event volume/privacy controls.
- Exit when each supported event has a fixture, a positive and negative detection check where relevant, and documented Windows policy prerequisites. Do not claim full EDR coverage.

### 3. Network and identity/cloud connectors

- Keep the passive host sensor as one network source; document TAP/SPAN/router placement for broader authorized visibility.
- Provider-specific offline import adapters cover AWS CloudTrail, Azure Activity Log, and Entra sign-in exports. A first read-only polling foundation now exists for all three providers: AES-GCM encrypted credentials, tenant-scoped connector records and data sources, timestamp cursors with overlap, bounded pagination, retry handling, manual/scheduled polling, and connector health UI. See `docs/CLOUD_CONNECTORS.md`.
- Fixture contracts, encryption checks, pagination host checks, full migration-chain application to a temporary PostgreSQL database, and the frontend production build passed. No provider credentials or customer tenant were configured for live validation.
- Continue to verify provider-specific least-privilege access, account licensing and retention, concurrency behavior, API rate limits, and event coverage in separately configured test accounts. Do not report cloud integration as operational until read-only end-to-end ingestion is verified.

### 4. Detection quality and correlation

- Version schemas and rules, expose rule provenance and data requirements, and distinguish “not observed” from “no threat.”
- Correlation now recognizes Entra high-risk sign-ins and AWS/Azure identity-change detections as credential-family findings that can join network discovery only when they share a source IP and the configured 30-minute window. Correlation also uses tenant-scoped SHA-256 keys derived from shared host, device, account, resource, or user evidence; it requires an allowed finding-family relationship and valid timestamps inside the configured window. Broader, source-specific correlation remains future work.
- Maintain benign and positive fixtures for every built-in rule and report source coverage gaps.
- Exit when deterministic rule fixtures, correlation boundaries, and API authorization checks pass; rule matches remain investigation leads.

### 5. Analyst workflow and response readiness

- Preserve evidence-linked cases, assignment, notes, status history, and audit trail.
- The case workspace supports allowlisted simulation records (host isolation, account disable, source-IP block) and three real, sensor-enforced actions: an IP block, a network isolation of the sensor computer and the disabling of one local Windows account. Analysts can propose; a different administrator must approve; the chosen sensor applies the action to itself for a limited time and only if it was started with that action allowed. Every stage is audited and notified. The server never contacts a host, a directory or a cloud tenant; command execution remains out of scope. See `docs/OPERATIONS.md` and `docs/THREAT_MODEL.md`. These actions have been run only on one lab computer.
- Proposals expire after seven days and a different administrator can reject them with an audited note. Approval/rejection attempts also transition overdue proposals to an audited expired state. Response transitions now lock the proposal row, and proposal creation locks the case; a concurrent retry with the same idempotency key returns the existing matching proposal or a controlled conflict. Remaining: bind targets to verified assets/identity entities and conduct a dedicated security review before considering any real response capability. These controls still record simulations only; they do not contact endpoints or providers.

### 6. ML and operational readiness

- Treat Isolation Forest as optional anomaly scoring, not a probability or verdict. Keep deterministic rules as the baseline.
- Require a documented dataset/version, leakage-safe held-out evaluation, baseline comparison, calibration/limitations, artifact integrity, and a disable/fallback path before exposing any score as useful operational evidence.
- Daily tenant-scoped security-event and source-file retention is implemented (bounded cleanup, per-batch audit records, configurable 1–3650 day settings, and explicit preservation of ingestion job metadata, detection snapshots, cases, and audit history).
- Operator backup/restore scripts cover PostgreSQL and the app-data volume, verify SHA-256 manifests, prune old local sets and prompt before replacing current data. An isolated restore rehearsal passed, and a restore from the S3 copy was measured (about 14 seconds at lab size). The off-site uploader runs daily against a private, versioned, encrypted S3 bucket with a 30-day retention rule; a failed backup writes a marker file and can post to a webhook. A full rebuild of a host from backups has not been rehearsed.
- An optional bearer-token protected metrics endpoint reports process-local HTTP request totals and latency histograms. Silent sensors, failing cloud connectors and failed notification deliveries are reported in the panel and by notification (see `docs/OPERATIONS.md`); a metrics collector, durable metrics storage, alerting on a stopped worker or scheduler and on-call procedures remain operator-level work.
- Upgrade/migration checks against the real database, broader telemetry validation, and independent security review remain necessary before any production claim.
- Exit when results can be reproduced from a recorded dataset and operational recovery/security checks are documented and exercised.

## Delivery order

1. Least-privilege sensor identity and fleet health.
2. Versioned endpoint event contract and additional audited endpoint signals.
3. Read-only cloud identity/activity connectors and connector health.
4. Cross-source entity correlation and rule coverage.
5. Human-approved simulated response workflow.
6. Reproducible ML evaluation and deployment hardening.

Organization-scoped records, login context, a tenant provisioning command, forced PostgreSQL RLS, and separate non-superuser runtime roles are implemented. Single-provider OIDC SSO with authorization-code PKCE is implemented for a self-hosted installation; it requires pre-provisioned accounts and still needs verification against the operator's provider. The test suite includes an RLS integration test when CI provisions that runtime role. Remaining production readiness includes endpoint coverage beyond selected Windows audit events, live cloud API polling, a verified backup/restore rehearsal with encrypted off-host storage, alert delivery, broader load and real-data detection validation, and independent security review. This repository remains a lab prototype, not a commercial-ready XDR. External cloud sources require user-owned test accounts and credentials; without them, live integration remains unverified. Whole-LAN capture requires authorized network infrastructure and cannot be provided by a normal Wi-Fi client adapter.
