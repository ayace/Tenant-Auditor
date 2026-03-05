import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_conditional_access(headers):
    resp = requests.get(f"{GRAPH_BASE}/identity/conditionalAccess/policies", headers=headers)
    resp.raise_for_status()
    policies = resp.json().get("value", [])

    results = []
    for policy in policies:
        results.append({
            "name": policy.get("displayName"),
            "state": policy.get("state"),  # enabled, disabled, enabledForReportingButNotEnforced
            "id": policy.get("id")
        })

    return {
        "total": len(policies),
        "enabled": sum(1 for p in results if p["state"] == "enabled"),
        "disabled": sum(1 for p in results if p["state"] == "disabled"),
        "report_only": sum(1 for p in results if p["state"] == "enabledForReportingButNotEnforced"),
        "policies": results
    }
