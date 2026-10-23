# Canonical event contract

SentinelAI stores imported and live telemetry using the versioned `NormalizedEventV1` contract in `backend/app/ingestion/schema.py`. Every file adapter and the live Windows sensor batch pass through the same validator before persistence. Records that fail are quarantined individually; the error reports the row and invalid field names without echoing the input value.

## Version 1 fields

| Field | Meaning | Validation |
| --- | --- | --- |
| `event_time` | Time reported by the source | Required; stored as timezone-aware UTC |
| `event_type` | SentinelAI event family or source-specific type | Required, non-empty, at most 128 characters |
| `src_ip`, `dst_ip` | Source and destination addresses | Optional IPv4 or IPv6 |
| `src_port`, `dst_port` | Transport ports | Optional integers from 0 through 65535 |
| `host_id` | Source-provided device identifier or host label | Optional, at most 255 characters; adapter must document which meaning it uses |
| `severity` | Normalized severity | `informational`, `low`, `medium`, `high`, or `critical` |
| `attributes` | Source-neutral and source-specific event details | JSON object; source-specific keys must be documented and minimized |
| `raw_payload` | Curated, redacted evidence retained for investigation | JSON object; secrets are redacted by key before storage |
| `schema_version` | Canonical contract version | Must equal `1` |
| `dedup_key` | Source event identity when available | Optional, at most 256 characters |

## Relationship to ECS / OSSEM

Version 1 is SentinelAI's compatibility envelope, not a claim of full ECS or OSSEM conformance. The current direct mappings are:

- `event_time` → ECS `@timestamp`
- `src_ip` / `src_port` → ECS `source.ip` / `source.port`
- `dst_ip` / `dst_port` → ECS `destination.ip` / `destination.port`
- `severity` → normalized SentinelAI severity; an ECS `event.severity` numeric mapping is not currently stored
- `event_type`, `host_id`, and `attributes` need source-aware mapping before they can map losslessly to ECS `event.*`, `host.*`, `user.*`, `process.*`, and `cloud.*`

Do not infer an ECS `host.id` from a value that is only a hostname. New adapters must preserve source provenance in `attributes.adapter` and add field mappings with positive and negative fixtures. A future schema revision should introduce unambiguous `host.name`, `host.id`, `user.name`, `process.*`, `event.provider`, `event.action`, and source-ingest metadata with an additive migration and a compatibility plan; do not silently reinterpret v1 values.

## Adapter coverage

The shared validator covers generic JSON/CSV, Zeek connection rows, Suricata EVE, AWS CloudTrail exports, Azure Activity Log exports, Entra sign-in exports, and live Windows sensor events. Cloud adapters remain file imports; validation does not imply that live cloud polling exists. Validation establishes shape and field bounds; it does not establish source authenticity, detection correctness, or complete telemetry coverage.
