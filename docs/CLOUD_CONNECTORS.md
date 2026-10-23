# Cloud connectors

SentinelAI currently includes read-only pollers for AWS CloudTrail management events, Azure Activity Log records for one subscription, and Microsoft Entra sign-in logs. Provider results pass through the existing versioned event normalizers and ingestion job path. A connector record, mock contract test, or successful local migration does not prove access to a real customer tenant.

## Permissions and prerequisites

- **AWS CloudTrail:** use an IAM principal whose policy permits `cloudtrail:LookupEvents` in the configured region. The connector supplies explicit access key credentials and does not fall back to an instance profile or local AWS profile. CloudTrail `LookupEvents` has provider-side request limits; SDK retries are enabled. See [AWS's CloudTrail IAM examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_id-based-policy-examples.html).
- **Azure Activity Log:** the app registration uses client-credentials OAuth against Microsoft management APIs. Assign the service principal the narrowest role that can read `Microsoft.Insights/eventtypes/management/values` at the target subscription. Azure's built-in Monitoring Reader is a broader read convenience role; review its effective permissions before assigning it. See the [Activity Logs list API](https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01) and [Azure Monitor built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/monitor).
- **Microsoft Entra sign-ins:** grant Microsoft Graph application permission `AuditLog.Read.All` and admin consent. Microsoft requires an Entra ID P1 or P2 license to download sign-in logs through Graph. See the [Graph sign-in list permissions](https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0) and [sign-in resource licensing note](https://learn.microsoft.com/graph/api/resources/signin?view=graph-rest-1.0).

These pollers only issue provider token and event-list requests. No cloud write, response, user-management, or configuration operation is implemented.

## Configure

1. Keep `SENTINEL_ENV=development` for the local lab, or configure all production secrets as described in `.env.example`.
2. Set `CLOUD_CONNECTOR_ENCRYPTION_KEY` to a URL-safe base64 encoding of 32 random bytes. Keep it stable and private; use a key distinct from `MFA_ENCRYPTION_KEY`. The API encrypts provider credentials with AES-GCM before storing them. The worker needs the same key to poll. Losing or replacing the key makes stored credentials unreadable; re-enter credentials after a key change.
3. Sign in as an administrator and open **Cloud connectors**. Enter the provider IDs and credentials in the form. The UI never reads a credential back from the API.
4. Use **Poll now** for the first check. Enabled connectors are then queued every five minutes by Celery Beat.

The first poll starts with a 15-minute lookback. Each successful poll keeps an overlapping time cursor to avoid boundary loss; event IDs provide duplicate suppression in the common event pipeline. Provider pagination is bounded to ten pages per poll. When a page limit is reached, the connector reports `partial` and resumes from the oldest returned event on the next pass. A failed poll does not advance the cursor. Source health shows poll status, last successful poll, and a response-safe error message.

## API

- `GET /api/v1/cloud-connectors` — administrators and analysts can view source health; credentials and cursor values are omitted.
- `POST /api/v1/cloud-connectors` — administrators create a connector; credentials are accepted once and encrypted at rest.
- `PUT /api/v1/cloud-connectors/{id}` — administrators rotate credentials or replace provider settings.
- `PATCH /api/v1/cloud-connectors/{id}` — administrators enable or pause polling.
- `DELETE /api/v1/cloud-connectors/{id}` — administrators revoke a connector, erase its stored ciphertext, and keep source/event history.
- `POST /api/v1/cloud-connectors/{id}/poll` — administrators queue a poll.

All connector records are tenant-scoped, protected by forced PostgreSQL RLS, and audited. Connectors keep their own data source and ingestion-job references so event provenance remains visible.

## Validation boundary

Unit tests exercise provider request contracts with mocked responses, credential encryption, retry-safe pagination boundaries, and rejected pagination hosts. The migration has been applied to a temporary PostgreSQL database. No AWS account, Azure subscription, or Entra tenant was configured for this validation. Live permissions, rate limits, provider retention, and end-to-end telemetry must be confirmed in a user-owned test tenant before calling any connector operationally ready.
