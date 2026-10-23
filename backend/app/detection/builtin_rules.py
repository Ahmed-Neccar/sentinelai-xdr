"""Built-in rules. Thresholds are lab defaults, not universal truths."""

BUILTIN_RULES: list[dict] = [
    {
        "rule_id": "office_spawns_powershell",
        "title": "Microsoft Word started PowerShell",
        "description": (
            "Windows process-creation telemetry shows winword.exe starting powershell.exe. "
            "This can be legitimate automation; review the parent/child evidence and host context."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "process.start",
            "attributes.source_name": "windows.security",
            "attributes.process_name": {"op": "contains", "value": "powershell.exe"},
            "attributes.parent_process_name": {"op": "contains", "value": "winword.exe"},
        },
        "mitre": [
            {
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "justification": (
                    "PowerShell launched by Word is a useful behavior to review, "
                    "but is not inherently malicious."
                ),
            }
        ],
    },
    {
        "rule_id": "windows_service_installed",
        "title": "Windows service installed",
        "description": (
            "Windows Security reports a service installation. Review the service path, account, "
            "change window, and host context."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.service_install",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_scheduled_task_created",
        "title": "Windows scheduled task created",
        "description": (
            "Windows Security reports a scheduled task creation. The task payload is intentionally "
            "not collected; review the task through authorized endpoint tooling."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.scheduled_task",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_scheduled_task_changed",
        "title": "Windows scheduled task changed",
        "description": (
            "Windows Security reports a scheduled task was changed. Review the task name, actor, "
            "and approved change context. Task XML and command content are not collected."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.scheduled_task_changed",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_scheduled_task_deleted",
        "title": "Windows scheduled task deleted",
        "description": (
            "Windows Security reports a scheduled task was deleted. Review whether removal was "
            "approved and expected."
        ),
        "severity": "low",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.scheduled_task_deleted",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_audit_policy_changed",
        "title": "Windows audit policy changed",
        "description": (
            "Windows Security reports an audit policy change. Confirm whether the change was "
            "approved and expected."
        ),
        "severity": "high",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.security.audit_policy_change",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_security_log_cleared",
        "title": "Windows Security log cleared",
        "description": (
            "Windows Security reports its audit log was cleared. Verify the actor, maintenance "
            "context, and centralized log retention."
        ),
        "severity": "high",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.security.log_cleared",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_account_created",
        "title": "Windows account created",
        "description": (
            "Windows Security reports a new account. Confirm the requester, target account, "
            "and approved provisioning activity."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.identity.account_created",
            "attributes.source_name": "windows.security",
        },
        "mitre": [],
    },
    {
        "rule_id": "windows_security_group_member_added",
        "title": "Windows security group membership added",
        "description": (
            "Windows Security reports a member added to a security-enabled group. Review the "
            "actor, member, group, and change approval; this signal is not proof of compromise."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.identity.group_member_added",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Persistence",
                "technique_id": "T1098",
                "justification": (
                    "Adding an account to a security group can change its effective access."
                ),
            }
        ],
    },
    {
        "rule_id": "windows_remote_interactive_logon",
        "title": "Windows Remote Desktop logon observed",
        "description": (
            "A Windows Security 4624 event reports a RemoteInteractive (LogonType 10) sign-in. "
            "Windows may omit the source IP. This is a review signal, "
            "not proof of unauthorized access."
        ),
        "severity": "low",
        "version": 3,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "auth.success",
            "attributes.source_name": "windows.security",
            "attributes.logon_type": "10",
        },
        "mitre": [
            {
                "tactic": "Lateral Movement",
                "technique_id": "T1021.001",
                "justification": "Windows reported a successful Remote Desktop interactive logon.",
            }
        ],
    },
    {
        "rule_id": "aws_iam_credential_or_policy_change",
        "title": "AWS identity or access policy changed",
        "description": (
            "CloudTrail reports a successful high-impact IAM credential or policy change. "
            "Review the actor, account, target, and approved change context."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["account_id"],
        "threshold": 1,
        "match": {
            "event_type": "cloud.aws.cloudtrail",
            "attributes.service": "iam.amazonaws.com",
            "attributes.cloud_status": "success",
            "attributes.action": {
                "op": "in",
                "value": [
                    "CreateAccessKey",
                    "CreateLoginProfile",
                    "AttachUserPolicy",
                    "PutUserPolicy",
                    "CreatePolicyVersion",
                    "UpdateAssumeRolePolicy",
                    "AddUserToGroup",
                ],
            },
        },
        "mitre": [],
    },
    {
        "rule_id": "azure_role_assignment_change",
        "title": "Azure role assignment changed",
        "description": (
            "Azure Activity Log reports a successful role assignment write. Confirm the actor, "
            "scope, and approved change before treating it as suspicious."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["subscription_id"],
        "threshold": 1,
        "match": {
            "event_type": "cloud.azure.activity",
            "attributes.action": "Microsoft.Authorization/roleAssignments/write",
            "attributes.outcome": "success",
        },
        "mitre": [],
    },
    {
        "rule_id": "entra_high_risk_signin",
        "title": "High-risk Microsoft Entra sign-in",
        "description": (
            "Microsoft Entra reports a successful sign-in with an aggregated medium or high risk "
            "level. "
            "Review the account, device, application, and provider context."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["username"],
        "threshold": 1,
        "match": {
            "event_type": "auth.success",
            "attributes.source_name": "microsoft.entra.signin",
            "attributes.risk_level": {"op": "in", "value": ["medium", "high"]},
        },
        "mitre": [],
    },
    {
        "rule_id": "auth_bruteforce",
        "title": "Repeated authentication failures",
        "description": "Count of auth.failure events from one source IP in a short window.",
        "severity": "high",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["src_ip"],
        "threshold": 8,
        "match": {"event_type": "auth.failure"},
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "justification": (
                    "Repeated failures from one IP resemble password guessing in lab auth logs."
                ),
            }
        ],
    },
    {
        "rule_id": "suspicious_login_pattern",
        "title": "Suspicious login pattern (failures then success)",
        "description": (
            "auth.success after several auth.failure events from the same IP in 10 minutes."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 600,
        "group_by": ["src_ip"],
        "threshold": 4,
        "match": {"event_type": ["auth.failure", "auth.success"]},
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "justification": (
                    "Failure burst plus success can indicate a guessed password in synthetic "
                    "datasets."
                ),
            }
        ],
    },
    {
        "rule_id": "port_scan_like",
        "title": "Port-scan-like connection pattern",
        "description": (
            "Many distinct destination ports from one source. Distinct-port counting is applied "
            "in a specialized evaluator."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 120,
        "group_by": ["src_ip"],
        "threshold": 12,
        "match": {"event_type": ["net.conn", "zeek.conn", "suricata.flow"]},
        "mitre": [
            {
                "tactic": "Discovery",
                "technique_id": "T1046",
                "justification": (
                    "High unique destination ports from one source can resemble network scanning "
                    "in lab traffic."
                ),
            }
        ],
        "unique_field": "dst_port",
    },
    {
        "rule_id": "unusual_conn_volume",
        "title": "Unusual connection volume",
        "description": "High count of connection events from one host or IP.",
        "severity": "low",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["src_ip"],
        "threshold": 40,
        "match": {"event_type": ["net.conn", "zeek.conn", "suricata.flow"]},
        "mitre": [],
    },
    {
        "rule_id": "auth_bruteforce_username",
        "title": "Potential brute-force against one username",
        "description": "Repeated auth.failure against the same username.",
        "severity": "high",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["username"],
        "threshold": 10,
        "match": {"event_type": "auth.failure"},
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique_id": "T1110.001",
                "justification": (
                    "Many failures for one account resemble password spraying/guessing in lab logs."
                ),
            }
        ],
    },
    {
        "rule_id": "suspicious_traffic_dns",
        "title": "Suspicious DNS-like high volume",
        "description": "High volume of dns.query events from one source.",
        "severity": "low",
        "version": 1,
        "window_seconds": 120,
        "group_by": ["src_ip"],
        "threshold": 30,
        "match": {"event_type": "dns.query"},
        "mitre": [],
    },
    {
        "rule_id": "repeat_high_severity",
        "title": "Repeated high-severity events from one source",
        "description": "Multiple high or critical events from the same source IP.",
        "severity": "high",
        "version": 1,
        "window_seconds": 600,
        "group_by": ["src_ip"],
        "threshold": 5,
        "match": {"severity": ["high", "critical"]},
        "mitre": [],
    },
]
