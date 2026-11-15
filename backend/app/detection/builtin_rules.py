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
        "version": 2,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.service_install",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Persistence",
                "technique_id": "T1543.003",
                "justification": (
                    "A new Windows service can be a persistence mechanism; most installs "
                    "are routine software changes."
                ),
            }
        ],
    },
    {
        "rule_id": "windows_scheduled_task_created",
        "title": "Windows scheduled task created",
        "description": (
            "Windows Security reports a scheduled task creation. The task payload is intentionally "
            "not collected; review the task through authorized endpoint tooling."
        ),
        "severity": "medium",
        "version": 2,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.scheduled_task",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Persistence",
                "technique_id": "T1053.005",
                "justification": (
                    "A new scheduled task can run code later or at logon; most tasks are "
                    "routine administration."
                ),
            }
        ],
    },
    {
        "rule_id": "windows_scheduled_task_changed",
        "title": "Windows scheduled task changed",
        "description": (
            "Windows Security reports a scheduled task was changed. Review the task name, actor, "
            "and approved change context. Task XML and command content are not collected."
        ),
        "severity": "medium",
        "version": 2,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.persistence.scheduled_task_changed",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Persistence",
                "technique_id": "T1053.005",
                "justification": (
                    "Changing a scheduled task can redirect what it runs; most changes are "
                    "routine administration."
                ),
            }
        ],
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
        "version": 2,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.security.audit_policy_change",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Defense Evasion",
                "technique_id": "T1562.002",
                "justification": (
                    "Weakening audit policy can hide later activity; policy changes are "
                    "also routine hardening."
                ),
            }
        ],
    },
    {
        "rule_id": "windows_security_log_cleared",
        "title": "Windows Security log cleared",
        "description": (
            "Windows Security reports its audit log was cleared. Verify the actor, maintenance "
            "context, and centralized log retention."
        ),
        "severity": "high",
        "version": 2,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.security.log_cleared",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Defense Evasion",
                "technique_id": "T1070.001",
                "justification": (
                    "Clearing the Security log removes evidence; it is rare in normal "
                    "operation and worth review."
                ),
            }
        ],
    },
    {
        "rule_id": "windows_account_created",
        "title": "Windows account created",
        "description": (
            "Windows Security reports a new account. Confirm the requester, target account, "
            "and approved provisioning activity."
        ),
        "severity": "medium",
        "version": 2,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "endpoint.identity.account_created",
            "attributes.source_name": "windows.security",
        },
        "mitre": [
            {
                "tactic": "Persistence",
                "technique_id": "T1136.001",
                "justification": (
                    "A new local account can give an intruder a way back; most accounts "
                    "are created by administrators."
                ),
            }
        ],
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
        "version": 2,
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
        "mitre": [
            {
                "tactic": "Persistence",
                "technique_id": "T1098",
                "justification": (
                    "Changing identities or their permissions can keep or widen access; "
                    "most changes are routine administration."
                ),
            }
        ],
    },
    {
        "rule_id": "azure_role_assignment_change",
        "title": "Azure role assignment changed",
        "description": (
            "Azure Activity Log reports a successful role assignment write. Confirm the actor, "
            "scope, and approved change before treating it as suspicious."
        ),
        "severity": "medium",
        "version": 2,
        "window_seconds": 300,
        "group_by": ["subscription_id"],
        "threshold": 1,
        "match": {
            "event_type": "cloud.azure.activity",
            "attributes.action": "Microsoft.Authorization/roleAssignments/write",
            "attributes.outcome": "success",
        },
        "mitre": [
            {
                "tactic": "Privilege Escalation",
                "technique_id": "T1098.003",
                "justification": (
                    "Adding a cloud role can widen access; most assignments are routine "
                    "administration."
                ),
            }
        ],
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
        "version": 2,
        "window_seconds": 300,
        "group_by": ["username"],
        "threshold": 1,
        "match": {
            "event_type": "auth.success",
            "attributes.source_name": "microsoft.entra.signin",
            "attributes.risk_level": {"op": "in", "value": ["medium", "high"]},
        },
        "mitre": [
            {
                "tactic": "Initial Access",
                "technique_id": "T1078.004",
                "justification": (
                    "A high-risk sign-in may be use of a stolen cloud account; the "
                    "provider's risk signal can be wrong."
                ),
            }
        ],
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
        "min_failures": 3,
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
    {
        "rule_id": "aws_cloudtrail_logging_tampered",
        "title": "AWS CloudTrail logging stopped or changed",
        "description": (
            "CloudTrail reports a successful change that can stop or narrow audit logging "
            "(StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors). Confirm the actor and "
            "that the change was approved; attackers disable logging to hide later activity."
        ),
        "severity": "high",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["account_id"],
        "threshold": 1,
        "match": {
            "event_type": "cloud.aws.cloudtrail",
            "attributes.service": "cloudtrail.amazonaws.com",
            "attributes.cloud_status": "success",
            "attributes.action": {
                "op": "in",
                "value": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"],
            },
        },
        "mitre": [
            {
                "tactic": "Defense Evasion",
                "technique_id": "T1562.008",
                "justification": (
                    "Disabling or narrowing cloud audit logging is a known evasion step."
                ),
            }
        ],
    },
    {
        "rule_id": "azure_diagnostic_logging_deleted",
        "title": "Azure diagnostic or logging setting deleted",
        "description": (
            "Azure Activity Log reports a successful deletion of a diagnostic setting, which can "
            "remove log export. Confirm the actor, scope, and approved change."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["subscription_id"],
        "threshold": 1,
        "match": {
            "event_type": "cloud.azure.activity",
            "attributes.action": "Microsoft.Insights/diagnosticSettings/delete",
            "attributes.outcome": "success",
        },
        "mitre": [
            {
                "tactic": "Defense Evasion",
                "technique_id": "T1562.008",
                "justification": "Removing log export reduces visibility of later activity.",
            }
        ],
    },
    {
        "rule_id": "azure_network_security_rule_changed",
        "title": "Azure network security rule written",
        "description": (
            "Azure Activity Log reports a successful network security group rule write. Review "
            "whether the rule opens inbound access and whether the change was approved."
        ),
        "severity": "medium",
        "version": 1,
        "window_seconds": 300,
        "group_by": ["subscription_id"],
        "threshold": 1,
        "match": {
            "event_type": "cloud.azure.activity",
            "attributes.action": "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "attributes.outcome": "success",
        },
        "mitre": [],
    },
]


def _office_spawn_rule(parent: str, label: str) -> dict:
    return {
        "rule_id": f"{parent.split('.')[0]}_spawns_powershell",
        "title": f"{label} started PowerShell",
        "description": (
            f"Windows process-creation telemetry shows {parent} starting powershell.exe. "
            "This can be legitimate automation (macros, add-ins); review the parent/child "
            "evidence and host context."
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
            "attributes.parent_process_name": {"op": "contains", "value": parent},
        },
        "mitre": [
            {
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "justification": (
                    f"PowerShell launched by {label} is worth reviewing, "
                    "but is not inherently malicious."
                ),
            }
        ],
    }


BUILTIN_RULES.extend(
    _office_spawn_rule(parent, label)
    for parent, label in (
        ("excel.exe", "Microsoft Excel"),
        ("outlook.exe", "Microsoft Outlook"),
        ("powerpnt.exe", "Microsoft PowerPoint"),
    )
)

BUILTIN_RULES.append(
    {
        "rule_id": "password_spray",
        "title": "Password spraying: many accounts tried from one address",
        "description": (
            "One source address failed to sign in as many different accounts in ten minutes. "
            "Spraying tries a few common passwords against many accounts to stay under "
            "per-account lockouts. Shared gateways and monitoring tools can look the same."
        ),
        "severity": "high",
        "version": 1,
        "window_seconds": 600,
        "group_by": ["src_ip"],
        "distinct_field": "username",
        "threshold": 6,
        "match": {"event_type": "auth.failure"},
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique_id": "T1110.003",
                "justification": "Many accounts, few attempts each, from one source.",
            }
        ],
    }
)


def _process_rule(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    match: dict,
    tactic: str,
    technique_id: str,
    justification: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "version": 1,
        "window_seconds": 300,
        "group_by": ["host_id"],
        "threshold": 1,
        "match": {
            "event_type": "process.start",
            "attributes.source_name": "windows.security",
            **match,
        },
        "mitre": [
            {"tactic": tactic, "technique_id": technique_id, "justification": justification}
        ],
    }


_REVIEW = " Review the parent and child evidence and the host's role; this can be legitimate."

BUILTIN_RULES.extend(
    [
        _process_rule(
            f"wmi_spawns_{child.split('.')[0]}",
            f"WMI started {child.split('.')[0].title()}",
            f"Windows process-creation telemetry shows WmiPrvSE.exe starting {child}. "
            "Remote or scripted WMI execution looks like this." + _REVIEW,
            "medium",
            {
                "attributes.process_name": {"op": "contains", "value": child},
                "attributes.parent_process_name": {"op": "contains", "value": "wmiprvse.exe"},
            },
            "Execution",
            "T1047",
            "Commands started by the WMI provider host can be remote execution through WMI.",
        )
        for child in ("powershell.exe", "cmd.exe")
    ]
    + [
        _process_rule(
            f"{host.split('.')[0]}_spawns_powershell",
            f"{host.split('.')[0].title()} started PowerShell",
            f"Windows process-creation telemetry shows {host} starting powershell.exe. "
            "Script hosts launching a shell are a common first stage of malicious scripts."
            + _REVIEW,
            "medium",
            {
                "attributes.process_name": {"op": "contains", "value": "powershell.exe"},
                "attributes.parent_process_name": {"op": "contains", "value": host},
            },
            "Execution",
            "T1059",
            "A script host starting a shell is worth reviewing, but is not inherently malicious.",
        )
        for host in ("wscript.exe", "cscript.exe", "mshta.exe")
    ]
    + [
        _process_rule(
            rule_id,
            title,
            f"Windows process-creation telemetry shows a program running from {place}, "
            "a folder that ordinary users can write to and where downloaded or dropped "
            "files often land." + _REVIEW,
            severity,
            {"attributes.process_name": {"op": "contains", "value": needle}},
            "Execution",
            "T1204",
            "Programs run from user-writable folders are often user-launched downloads.",
        )
        for rule_id, title, place, needle, severity in (
            (
                "process_from_temp_folder",
                "Program started from a temporary folder",
                "a temporary folder",
                "\\appdata\\local\\temp\\",
                "medium",
            ),
            (
                "process_from_downloads_folder",
                "Program started from the Downloads folder",
                "the Downloads folder",
                "\\downloads\\",
                "low",
            ),
            (
                "process_from_public_folder",
                "Program started from the Public folder",
                "the shared Public folder",
                "\\users\\public\\",
                "medium",
            ),
        )
    ]
)


# Experimental long-window rules. They were written after the simulation showed that every slow
# attack slips under the 5- and 10-minute windows, and measured on separate seeds (research/results/
# ADAY_KURALLAR.md). The simulation does not contain the real-world noise that would make them fire,
# such as a phone with a stale password retrying all day, so they ship switched off.
_SLOW_NOTE = (
    " Experimental and off by default: measured only on simulated data, where it caught most slow "
    "attacks at a low false positive rate; on real networks expect extra alerts from retrying "
    "clients and monitoring tools."
)
BUILTIN_RULES.extend(
    [
        {
            "rule_id": "auth_bruteforce_username_slow",
            "title": "Slow brute force against one username",
            "description": (
                "Many sign-in failures for one account spread over an hour, below the burst rules."
                + _SLOW_NOTE
            ),
            "severity": "medium",
            "version": 1,
            "default_enabled": False,
            "window_seconds": 3600,
            "group_by": ["username"],
            "threshold": 10,
            "match": {"event_type": "auth.failure"},
            "mitre": [
                {
                    "tactic": "Credential Access",
                    "technique_id": "T1110.001",
                    "justification": (
                        "Low-and-slow guessing keeps each burst under per-minute thresholds."
                    ),
                }
            ],
        },
        {
            "rule_id": "password_spray_slow",
            "title": "Slow password spraying",
            "description": (
                "One source failed to sign in as many different accounts within an hour."
                + _SLOW_NOTE
            ),
            "severity": "medium",
            "version": 1,
            "default_enabled": False,
            "window_seconds": 3600,
            "group_by": ["src_ip"],
            "distinct_field": "username",
            "threshold": 8,
            "match": {"event_type": "auth.failure"},
            "mitre": [
                {
                    "tactic": "Credential Access",
                    "technique_id": "T1110.003",
                    "justification": (
                        "Spraying spread over an hour avoids the ten-minute spray rule."
                    ),
                }
            ],
        },
        {
            "rule_id": "port_scan_slow",
            "title": "Slow port scan",
            "description": (
                "Many distinct destination ports from one source within an hour." + _SLOW_NOTE
            ),
            "severity": "low",
            "version": 1,
            "default_enabled": False,
            "window_seconds": 3600,
            "group_by": ["src_ip"],
            "threshold": 40,
            "unique_field": "dst_port",
            "match": {"event_type": ["net.conn", "zeek.conn", "suricata.flow"]},
            "mitre": [
                {
                    "tactic": "Discovery",
                    "technique_id": "T1046",
                    "justification": "A slow scan stays under the two-minute port-scan window.",
                }
            ],
        },
    ]
)
