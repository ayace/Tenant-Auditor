import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_guest_users(headers):
    resp = requests.get(
        f"{GRAPH_BASE}/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,createdDateTime,accountEnabled",
        headers=headers
    )
    resp.raise_for_status()
    guests = resp.json().get("value", [])

    results = []
    for g in guests:
        results.append({
            "user": g.get("userPrincipalName"),
            "display_name": g.get("displayName"),
            "enabled": g.get("accountEnabled", True),
            "created": g.get("createdDateTime")
        })

    return {"total": len(results), "guests": results}
