# Cloud identity and control-plane log import

SentinelAI currently imports these provider exports as files; it does not connect to AWS, Azure, or Microsoft Graph, store cloud API credentials, or poll provider APIs. Use only exports from accounts you are authorized to monitor.

## Supported adapters

| Adapter | Expected export | Normalized signals | Privacy handling |
|---|---|---|---|
| `aws_cloudtrail` | CloudTrail JSON event array or `{ "Records": [...] }` | `cloud.aws.cloudtrail`, action, service, actor, account, region, outcome, source IP | Keeps a curated allowlist; omits request/response parameters and unrecognized identity fields |
| `azure_activity` | Azure Activity Log JSON array or `{ "value": [...] }` | `cloud.azure.activity`, operation, caller, subscription, tenant, status, source IP | Omits `claims` and arbitrary `properties`; keeps selected operation metadata |
| `entra_signin` | Microsoft Graph sign-in JSON array or `{ "value": [...] }` | `auth.success` / `auth.failure`, account, app, device ID, risk, source IP | Keeps selected status/device fields; omits token claims and unrecognized device fields |

All provider events use the same persisted event model and detection pipeline. Provider raw payloads are reduced to a provider-specific allowlist. Do not import exports containing secrets or data outside your retention policy. These files may still contain personal and account identifiers; protect the database and local `.env` accordingly.

## Synthetic walkthrough files

Use **Ingestion** and select the matching adapter for one of these clearly labeled examples:

- `data/samples/aws_cloudtrail_synthetic.json`
- `data/samples/azure_activity_synthetic.json`
- `data/samples/entra_signin_synthetic.json`

They use reserved example IP addresses and synthetic identities. They are fixtures, not real cloud activity. Expected review signals include a successful AWS IAM credential change, a successful Azure role assignment write, and a high-risk Entra sign-in.

## Live connector work remaining

Live connectors need provider-specific read-only credentials, secure secret storage, tenant/account setup, per-provider cursors, rate-limit/retry handling, and end-to-end verification against a test account. None of that is implemented here. A successful file import must not be described as a live cloud integration.
