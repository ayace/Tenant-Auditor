import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_password_policy(headers):
    resp = requests.get(
        f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName,passwordPolicies",
        headers=headers
    )
    resp.raise_for_status()
    users = resp.json().get("value", [])

    results = []
    for user in users:
        policies = user.get("passwordPolicies") or ""
        never_expires = "DisablePasswordExpiration" in policies

        results.append({
            "user": user.get("userPrincipalName"),
            "display_name": user.get("displayName"),
            "password_never_expires": never_expires,
            "policies": policies or "default"
        })

    return results
