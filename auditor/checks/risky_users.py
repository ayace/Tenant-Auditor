import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_risky_users(headers):
    resp = requests.get(f"{GRAPH_BASE}/identityProtection/riskyUsers", headers=headers)

    if resp.status_code == 403:
        return {"error": "Requires Entra ID P2 license", "users": []}
    if resp.status_code != 200:
        return {"error": f"Unexpected error: {resp.status_code}", "users": []}

    users = resp.json().get("value", [])
    results = []

    for user in users:
        results.append({
            "user": user.get("userPrincipalName"),
            "display_name": user.get("userDisplayName"),
            "risk_level": user.get("riskLevel"),       # none, low, medium, high
            "risk_state": user.get("riskState"),       # atRisk, confirmedCompromised, remediated, dismissed
            "risk_detail": user.get("riskDetail"),
            "last_updated": user.get("riskLastUpdatedDateTime")
        })

    return {"users": results}
