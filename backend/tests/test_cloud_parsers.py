from datetime import UTC, datetime

from app.ingestion.parsers import (
    load_records,
    normalize_aws_cloudtrail,
    normalize_azure_activity,
    normalize_entra_signin,
)


def test_cloudtrail_maps_identity_and_omits_sensitive_request_payloads() -> None:
    result = normalize_aws_cloudtrail(
        {
            "eventTime": "2026-10-23T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "eventID": "evt-1",
            "awsRegion": "eu-west-1",
            "sourceIPAddress": "203.0.113.7",
            "recipientAccountId": "123456789012",
            "userIdentity": {"type": "IAMUser", "userName": "analyst", "accountId": "123456789012"},
            "requestParameters": {"secretAccessKey": "must-not-be-stored"},
        },
        1,
    )
    assert result["event_type"] == "cloud.aws.cloudtrail"
    assert result["src_ip"] == "203.0.113.7"
    assert result["attributes"]["action"] == "CreateAccessKey"
    assert "requestParameters" not in result["raw_payload"]


def test_azure_activity_maps_failed_control_plane_operation() -> None:
    result = normalize_azure_activity(
        {
            "eventTimestamp": "2026-10-23T10:00:00Z",
            "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
            "category": {"value": "Administrative"},
            "caller": "admin@example.local",
            "callerIpAddress": "203.0.113.8",
            "resourceId": ("/subscriptions/sub-1/resourceGroups/rg/providers/"
                "Microsoft.Authorization/roleAssignments/x"),
            "subscriptionId": "sub-1",
            "status": {"value": "Failed"},
            "claims": {"access_token": "must-not-be-stored"},
        },
        1,
    )
    assert result["event_type"] == "cloud.azure.activity"
    assert result["attributes"]["cloud_status"] == "Failed"
    assert result["attributes"]["action"] == "Microsoft.Authorization/roleAssignments/write"
    assert "claims" not in result["raw_payload"]


def test_entra_signin_normalizes_failure_and_curates_device_fields() -> None:
    result = normalize_entra_signin(
        {
            "id": "signin-1",
            "createdDateTime": "2026-10-23T10:00:00Z",
            "userPrincipalName": "analyst@example.local",
            "ipAddress": "203.0.113.9",
            "appDisplayName": "Portal",
            "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
            "deviceDetail": {
                "deviceId": "device-1",
                "displayName": "workstation",
                "browser": "Example",
                "trustType": "joined",
            },
            "tokenIssuerName": "must-not-be-stored",
        },
        1,
    )
    assert result["event_type"] == "auth.failure"
    assert result["attributes"]["username"] == "analyst@example.local"
    assert "tokenIssuerName" not in result["raw_payload"]
    assert "trustType" not in result["raw_payload"]["deviceDetail"]


def test_cloud_provider_export_wrappers_are_unpacked() -> None:
    rows = load_records(
        b'{"Records":[{"eventName":"DescribeInstances"}]}', "events.json", "aws_cloudtrail", 10
    )
    assert rows == [{"eventName": "DescribeInstances"}]


def test_cloud_control_plane_rules_match_successful_changes_only() -> None:
    from app.detection.builtin_rules import BUILTIN_RULES
    from app.detection.engine import evaluate_rule

    specs = {item["rule_id"]: item for item in BUILTIN_RULES}
    aws = {
        "id": "aws-1",
        "event_time": datetime(2026, 10, 23, 10, 0, tzinfo=UTC),
        "event_type": "cloud.aws.cloudtrail",
        "account_id": None,
        "attributes": {
            "account_id": "123456789012",
            "service": "iam.amazonaws.com",
            "action": "CreateAccessKey",
            "cloud_status": "success",
        },
    }
    assert len(evaluate_rule(specs["aws_iam_credential_or_policy_change"], [aws])) == 1
    failed = {**aws, "id": "aws-2", "attributes": {**aws["attributes"], "cloud_status": "failure"}}
    assert evaluate_rule(specs["aws_iam_credential_or_policy_change"], [failed]) == []

    azure = {
        "id": "azure-1",
        "event_time": aws["event_time"],
        "event_type": "cloud.azure.activity",
        "attributes": {
            "subscription_id": "sub-1",
            "action": "Microsoft.Authorization/roleAssignments/write",
            "outcome": "success",
        },
    }
    assert len(evaluate_rule(specs["azure_role_assignment_change"], [azure])) == 1


def test_entra_high_risk_signin_rule_matches_only_successful_signin() -> None:
    from app.detection.builtin_rules import BUILTIN_RULES
    from app.detection.engine import evaluate_rule

    spec = next(item for item in BUILTIN_RULES if item["rule_id"] == "entra_high_risk_signin")
    event = {
        "id": "signin-risk",
        "event_time": datetime(2026, 10, 23, 10, 0, tzinfo=UTC),
        "event_type": "auth.success",
        "attributes": {
            "source_name": "microsoft.entra.signin",
            "risk_level": "high",
            "username": "user@example.invalid",
        },
    }
    assert len(evaluate_rule(spec, [event])) == 1
    failed = {**event, "event_type": "auth.failure"}
    assert evaluate_rule(spec, [failed]) == []


def test_azure_activity_reads_caller_address_and_resource_from_management_api_shape() -> None:
    result = normalize_azure_activity(
        {
            "eventTimestamp": "2026-11-12T08:41:25Z",
            "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
            "status": {"value": "Succeeded"},
            "caller": "admin@example.com",
            "httpRequest": {"clientIpAddress": "203.0.113.7", "method": "PUT"},
            "claims": {"ipaddr": "198.51.100.9", "name": "must not be stored"},
            "resourceId": "/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/r",
            "resourceType": {"value": "Microsoft.Authorization/roleAssignments"},
            "resourceProviderName": {"value": "Microsoft.Authorization"},
            "resourceGroupName": "",
            "eventDataId": "abc",
        },
        1,
    )
    assert str(result["src_ip"]) == "203.0.113.7"
    attributes = result["attributes"]
    assert attributes["resource_id"].endswith("/roleAssignments/r")
    assert attributes["cloud_resource"] == "Microsoft.Authorization/roleAssignments"
    assert attributes["service"] == "Microsoft.Authorization"
    assert result["raw_payload"]["callerIpAddress"] == "203.0.113.7"
    assert "claims" not in result["raw_payload"]
    assert "resourceGroupName" not in result["raw_payload"]


def test_azure_activity_falls_back_to_claims_address_and_tolerates_none() -> None:
    base = {"eventTimestamp": "2026-11-12T08:41:25Z", "operationName": "x/read"}
    from_claims = normalize_azure_activity({**base, "claims": {"ipaddr": "198.51.100.9"}}, 1)
    assert str(from_claims["src_ip"]) == "198.51.100.9"
    assert normalize_azure_activity({**base, "httpRequest": "junk"}, 1)["src_ip"] is None
