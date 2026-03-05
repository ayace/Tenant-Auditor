import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_mfa(headers):
    users_resp = requests.get(f"{GRAPH_BASE}/users", headers=headers)
    users_resp.raise_for_status()
    users = users_resp.json().get("value", [])

    results = []
    for user in users:
        uid = user["id"]
        name = user["displayName"]
        upn = user["userPrincipalName"]

        auth_resp = requests.get(
            f"{GRAPH_BASE}/users/{uid}/authentication/methods",
            headers=headers
        )
        if auth_resp.status_code != 200:
            results.append({"user": upn, "display_name": name, "mfa_registered": "unknown"})
            continue

        methods = auth_resp.json().get("value", [])
        method_types = [m.get("@odata.type", "") for m in methods]

        # Password alone = no MFA
        non_password = [m for m in method_types if "password" not in m.lower()]
        mfa_registered = len(non_password) > 0

        results.append({
            "user": upn,
            "display_name": name,
            "mfa_registered": mfa_registered,
            "methods": non_password
        })

    return results
