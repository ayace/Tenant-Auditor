import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_sspr(headers):
    resp = requests.get(f"{GRAPH_BASE}/policies/authorizationPolicy", headers=headers)

    if resp.status_code == 403:
        return {"error": "Requires Policy.Read.All permission", "enabled": None}

    resp.raise_for_status()
    data = resp.json()

    # allowedToUseSSPR can be: "none", "adminOnly", "all"
    allowed = data.get("allowedToUseSSPR", "none")

    return {
        "enabled": allowed != "none",
        "scope": allowed,       # none | adminOnly | all
        "default_user_role_permissions": data.get("defaultUserRolePermissions", {})
    }
