import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

HIGHLY_PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}

def check_admin_roles(headers):
    resp = requests.get(f"{GRAPH_BASE}/directoryRoles", headers=headers)
    if resp.status_code == 403:
        return {"error": "Requires RoleManagement.Read.All permission", "roles": []}
    resp.raise_for_status()

    roles = resp.json().get("value", [])
    results = []

    for role in roles:
        role_id = role.get("roleTemplateId")
        role_name = role.get("displayName")

        members_resp = requests.get(
            f"{GRAPH_BASE}/directoryRoles/{role['id']}/members",
            headers=headers
        )
        if members_resp.status_code != 200:
            continue

        members = members_resp.json().get("value", [])
        if not members:
            continue

        is_privileged = role_id in HIGHLY_PRIVILEGED_ROLES

        results.append({
            "role": role_name,
            "role_template_id": role_id,
            "is_privileged": is_privileged,
            "member_count": len(members),
            "members": [
                {"name": m.get("displayName"), "upn": m.get("userPrincipalName")}
                for m in members
            ]
        })

    return {"roles": results}
