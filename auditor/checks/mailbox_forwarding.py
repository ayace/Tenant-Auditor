import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def check_mailbox_forwarding(headers):
    users_resp = requests.get(
        f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName",
        headers=headers
    )
    users_resp.raise_for_status()
    users = users_resp.json().get("value", [])

    results = []
    for user in users:
        uid = user["id"]
        upn = user["userPrincipalName"]
        name = user["displayName"]

        mb_resp = requests.get(
            f"{GRAPH_BASE}/users/{uid}/mailboxSettings",
            headers=headers
        )

        if mb_resp.status_code != 200:
            results.append({"user": upn, "display_name": name, "forwarding": None, "status": "unavailable"})
            continue

        settings = mb_resp.json()
        forward_address = settings.get("forwardingSmtpAddress")

        results.append({
            "user": upn,
            "display_name": name,
            "forwarding_address": forward_address,
            "status": "forwarding" if forward_address else "clean"
        })

    return results
