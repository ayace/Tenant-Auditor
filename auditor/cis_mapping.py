# CIS Microsoft 365 Foundations Benchmark v3.0 control mappings

CIS_CONTROLS = {
    "MFA Registration": {
        "id": "CIS 1.1.1",
        "title": "Ensure MFA is enabled for all users in the Microsoft 365 tenant",
    },
    "Conditional Access": {
        "id": "CIS 1.1.2",
        "title": "Ensure Microsoft Authenticator is configured to protect against MFA fatigue",
    },
    "Legacy Auth Blocked": {
        "id": "CIS 1.1.4",
        "title": "Ensure that legacy authentication is blocked via Conditional Access",
    },
    "Admin Role Hygiene": {
        "id": "CIS 1.2.1",
        "title": "Ensure administrative accounts are separate and cloud-only",
    },
    "Mailbox Forwarding": {
        "id": "CIS 6.1.1",
        "title": "Ensure the option to automatically forward emails is disabled",
    },
    "Password Policy": {
        "id": "CIS 2.1.1",
        "title": "Ensure that password protection is enabled for on-prem Active Directory",
    },
    "SSPR Enabled": {
        "id": "CIS 1.1.5",
        "title": "Ensure Self-Service Password Reset is enabled",
    },
}
