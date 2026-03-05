"""
Scoring weights (total = 100 points):
  MFA registered for all users         25 pts
  Conditional Access policies exist    20 pts
  Legacy auth blocked                  15 pts
  No highly privileged role sprawl     15 pts
  No mailbox forwarding                10 pts
  Password expiration enforced          8 pts
  SSPR enabled                          7 pts
"""

def score_mfa(mfa_results):
    if not mfa_results:
        return 25, 25, []
    total = len(mfa_results)
    no_mfa = [r for r in mfa_results if r["mfa_registered"] is False]
    if total == 0:
        return 25, 25, []
    pct = (total - len(no_mfa)) / total
    earned = round(25 * pct)
    issues = [f"{r['display_name']} has no MFA registered" for r in no_mfa]
    return earned, 25, issues


def score_conditional_access(ca):
    if ca.get("enabled", 0) > 0:
        return 20, 20, []
    if ca.get("total", 0) == 0:
        return 0, 20, ["No Conditional Access policies configured"]
    return 5, 20, ["No CA policies are currently enabled"]


def score_legacy_auth(legacy):
    if legacy.get("error"):
        return None, 15, []
    if legacy.get("legacy_auth_blocked"):
        return 15, 15, []
    return 0, 15, ["No Conditional Access policy blocks legacy authentication"]


def score_admin_roles(roles_data):
    if roles_data.get("error"):
        return None, 15, []
    roles = roles_data.get("roles", [])
    privileged = [r for r in roles if r.get("is_privileged")]
    issues = []
    deductions = 0
    for r in privileged:
        if r["member_count"] > 2:
            issues.append(f"{r['role']} has {r['member_count']} members (consider reducing)")
            deductions += 5
    earned = max(0, 15 - deductions)
    return earned, 15, issues


def score_mailbox_forwarding(fwd_results):
    forwarding = [r for r in fwd_results if r["status"] == "forwarding"]
    if not forwarding:
        return 10, 10, []
    issues = [f"{r['display_name']} is forwarding mail to {r['forwarding_address']}" for r in forwarding]
    return 0, 10, issues


def score_password_policy(pw_results):
    never_expires = [r for r in pw_results if r["password_never_expires"]]
    if not never_expires:
        return 8, 8, []
    issues = [f"{r['display_name']} has password set to never expire" for r in never_expires]
    pct = (len(pw_results) - len(never_expires)) / len(pw_results)
    return round(8 * pct), 8, issues


def score_sspr(sspr):
    if sspr.get("error"):
        return None, 7, []
    if sspr.get("enabled"):
        return 7, 7, []
    return 0, 7, ["Self-Service Password Reset is not enabled"]


def calculate_score(results):
    sections = []
    total_earned = 0
    total_possible = 0

    checks = [
        ("MFA Registration",            score_mfa(results["mfa"])),
        ("Conditional Access",           score_conditional_access(results["conditional_access"])),
        ("Legacy Auth Blocked",          score_legacy_auth(results["legacy_auth"])),
        ("Admin Role Hygiene",           score_admin_roles(results["admin_roles"])),
        ("Mailbox Forwarding",           score_mailbox_forwarding(results["mailbox_forwarding"])),
        ("Password Policy",              score_password_policy(results["password_policy"])),
        ("SSPR Enabled",                 score_sspr(results["sspr"])),
    ]

    from auditor.cis_mapping import CIS_CONTROLS
    for name, (earned, possible, issues) in checks:
        cis = CIS_CONTROLS.get(name, {})
        if earned is None:
            sections.append({"name": name, "earned": None, "possible": possible, "issues": issues, "skipped": True, "cis": cis})
            continue
        total_earned += earned
        total_possible += possible
        sections.append({"name": name, "earned": earned, "possible": possible, "issues": issues, "skipped": False, "cis": cis})

    overall = round((total_earned / total_possible) * 100) if total_possible > 0 else 0

    return {
        "overall": overall,
        "earned": total_earned,
        "possible": total_possible,
        "sections": sections
    }
