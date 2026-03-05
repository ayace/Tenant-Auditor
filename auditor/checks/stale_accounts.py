import requests
from datetime import datetime, timezone, timedelta

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
STALE_DAYS = 90

def check_stale_accounts(headers):
    resp = requests.get(
        f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName,signInActivity,accountEnabled",
        headers=headers
    )

    if resp.status_code == 403:
        # signInActivity requires Entra ID P1/P2 — fall back to basic user list
        resp = requests.get(
            f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName,accountEnabled",
            headers=headers
        )
        resp.raise_for_status()
        users = resp.json().get("value", [])
        return [
            {
                "user": u["userPrincipalName"],
                "display_name": u["displayName"],
                "enabled": u.get("accountEnabled", True),
                "status": "no_signin_data"
            }
            for u in users
        ]

    resp.raise_for_status()
    users = resp.json().get("value", [])

    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
    results = []

    for user in users:
        sign_in_activity = user.get("signInActivity")
        upn = user["userPrincipalName"]
        name = user["displayName"]
        enabled = user.get("accountEnabled", True)

        if sign_in_activity is None:
            results.append({"user": upn, "display_name": name, "enabled": enabled, "status": "no_signin_data"})
            continue

        last_signin_str = sign_in_activity.get("lastSignInDateTime")
        if not last_signin_str:
            results.append({"user": upn, "display_name": name, "enabled": enabled, "status": "never_signed_in"})
            continue

        last_signin = datetime.fromisoformat(last_signin_str.replace("Z", "+00:00"))
        stale = last_signin < cutoff

        results.append({
            "user": upn,
            "display_name": name,
            "enabled": enabled,
            "last_signin": last_signin_str,
            "status": "stale" if stale else "active"
        })

    return results
