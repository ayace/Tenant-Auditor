import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}

def check_legacy_auth(headers):
    resp = requests.get(
        f"{GRAPH_BASE}/identity/conditionalAccess/policies",
        headers=headers
    )
    resp.raise_for_status()
    policies = resp.json().get("value", [])

    blocking_policies = []
    for policy in policies:
        if policy.get("state") != "enabled":
            continue
        conditions = policy.get("conditions", {})
        client_app_types = set(conditions.get("clientAppTypes", []))
        grant_controls = policy.get("grantControls") or {}
        operator = grant_controls.get("operator")
        built_in_controls = grant_controls.get("builtInControls", [])

        blocks_legacy = (
            client_app_types & LEGACY_CLIENT_TYPES
            and "block" in built_in_controls
        )
        if blocks_legacy:
            blocking_policies.append(policy.get("displayName"))

    return {
        "legacy_auth_blocked": len(blocking_policies) > 0,
        "blocking_policies": blocking_policies
    }
