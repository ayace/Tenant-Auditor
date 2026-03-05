from datetime import datetime, timezone

def _score_color(score):
    if score >= 80:
        return "#22c55e"  # green
    if score >= 50:
        return "#f59e0b"  # amber
    return "#ef4444"      # red

def _score_label(score):
    if score >= 80:
        return "Good"
    if score >= 50:
        return "Needs Attention"
    return "At Risk"

def _badge(text, color):
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600">{text}</span>'

def _section(title, rows_html, score_section=None):
    score_html = ""
    if score_section and not score_section.get("skipped"):
        earned = score_section["earned"]
        possible = score_section["possible"]
        pct = round((earned / possible) * 100) if possible else 0
        color = _score_color(pct)
        score_html = f'<span style="float:right;color:{color};font-weight:700">{earned}/{possible} pts</span>'
    elif score_section and score_section.get("skipped"):
        score_html = '<span style="float:right;color:#94a3b8;font-size:0.85em">skipped (license)</span>'

    return f"""
    <div style="background:#1e293b;border-radius:8px;padding:20px;margin-bottom:16px">
      <h2 style="margin:0 0 12px;font-size:1.1em;color:#e2e8f0">{title}{score_html}</h2>
      <div style="clear:both"></div>
      {rows_html}
    </div>"""

def _row(icon, text, sub=""):
    sub_html = f'<div style="color:#94a3b8;font-size:0.85em;margin-top:2px">{sub}</div>' if sub else ""
    return f'<div style="padding:6px 0;border-bottom:1px solid #334155;color:#cbd5e1">{icon} {text}{sub_html}</div>'

def generate_html(tenant_id, results, score):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    overall = score["overall"]
    color = _score_color(overall)
    label = _score_label(overall)

    # ── MFA section ──────────────────────────────────────────────────────────
    mfa_rows = ""
    for r in results["mfa"]:
        if r["mfa_registered"] is True:
            mfa_rows += _row("✅", r["display_name"], r["user"])
        elif r["mfa_registered"] is False:
            mfa_rows += _row("❌", f"{r['display_name']} — no MFA registered", r["user"])
        else:
            mfa_rows += _row("⚠️", f"{r['display_name']} — unknown", r["user"])
    mfa_section = _section("MFA Registration", mfa_rows or _row("—", "No users found"),
                           next((s for s in score["sections"] if s["name"] == "MFA Registration"), None))

    # ── Conditional Access ───────────────────────────────────────────────────
    ca = results["conditional_access"]
    ca_rows = _row("📋", f"Total policies: {ca['total']} &nbsp;|&nbsp; Enabled: {ca['enabled']} &nbsp;|&nbsp; Disabled: {ca['disabled']} &nbsp;|&nbsp; Report-only: {ca['report_only']}")
    if ca["total"] == 0:
        ca_rows += _row("❌", "No Conditional Access policies found")
    for p in ca["policies"]:
        icons = {"enabled": "✅", "disabled": "❌", "enabledForReportingButNotEnforced": "⚠️"}
        ca_rows += _row(icons.get(p["state"], "•"), p["name"])
    ca_section = _section("Conditional Access Policies", ca_rows,
                          next((s for s in score["sections"] if s["name"] == "Conditional Access"), None))

    # ── Stale Accounts ───────────────────────────────────────────────────────
    stale_rows = ""
    for r in results["stale_accounts"]:
        if r["status"] == "stale":
            stale_rows += _row("❌", r["display_name"], f"Last login: {r['last_signin']}")
        elif r["status"] == "never_signed_in":
            stale_rows += _row("⚠️", f"{r['display_name']} — never signed in", r["user"])
        elif r["status"] == "no_signin_data":
            stale_rows += _row("—", f"{r['display_name']} — requires Entra P1/P2", r["user"])
        else:
            stale_rows += _row("✅", r["display_name"], f"Last login: {r.get('last_signin', 'N/A')}")
    stale_section = _section("Stale Accounts (90+ days)", stale_rows or _row("✅", "No stale accounts found"))

    # ── Risky Users ──────────────────────────────────────────────────────────
    risky = results["risky_users"]
    if risky.get("error"):
        risky_rows = _row("—", risky["error"])
    elif not risky["users"]:
        risky_rows = _row("✅", "No risky users detected")
    else:
        risky_rows = ""
        for r in risky["users"]:
            risky_rows += _row("❌", f"{r['display_name']} — {r['risk_level']} risk", f"{r['risk_state']} | {r['user']}")
    risky_section = _section("Risky Users", risky_rows)

    # ── Admin Roles ──────────────────────────────────────────────────────────
    roles_data = results["admin_roles"]
    if roles_data.get("error"):
        roles_rows = _row("—", roles_data["error"])
    elif not roles_data["roles"]:
        roles_rows = _row("✅", "No active directory roles found")
    else:
        roles_rows = ""
        for r in roles_data["roles"]:
            icon = "⚠️" if (r["is_privileged"] and r["member_count"] > 2) else "✅"
            members = ", ".join(m["name"] for m in r["members"] if m["name"])
            roles_rows += _row(icon, f"{r['role']} — {r['member_count']} member(s)", members)
    roles_section = _section("Admin Role Assignments", roles_rows,
                             next((s for s in score["sections"] if s["name"] == "Admin Role Hygiene"), None))

    # ── Guest Users ──────────────────────────────────────────────────────────
    guests = results["guest_users"]
    if guests["total"] == 0:
        guest_rows = _row("✅", "No guest users found")
    else:
        guest_rows = ""
        for g in guests["guests"]:
            enabled = "enabled" if g["enabled"] else "disabled"
            guest_rows += _row("⚠️", g["display_name"], f"{g['user']} | {enabled} | created: {g['created']}")
    guest_section = _section(f"Guest Users ({guests['total']} found)", guest_rows)

    # ── Legacy Auth ──────────────────────────────────────────────────────────
    legacy = results["legacy_auth"]
    if legacy.get("legacy_auth_blocked"):
        legacy_rows = _row("✅", "Legacy authentication is blocked")
        for p in legacy["blocking_policies"]:
            legacy_rows += _row("📋", p)
    else:
        legacy_rows = _row("❌", "No policy blocking legacy authentication protocols")
    legacy_section = _section("Legacy Authentication", legacy_rows,
                              next((s for s in score["sections"] if s["name"] == "Legacy Auth Blocked"), None))

    # ── Mailbox Forwarding ───────────────────────────────────────────────────
    fwd_rows = ""
    for r in results["mailbox_forwarding"]:
        if r["status"] == "forwarding":
            fwd_rows += _row("❌", f"{r['display_name']} — forwarding enabled", r["forwarding_address"])
        elif r["status"] == "unavailable":
            fwd_rows += _row("—", f"{r['display_name']} — no mailbox", r["user"])
        else:
            fwd_rows += _row("✅", r["display_name"], r["user"])
    fwd_section = _section("Mailbox Forwarding Rules", fwd_rows or _row("✅", "No forwarding rules found"),
                           next((s for s in score["sections"] if s["name"] == "Mailbox Forwarding"), None))

    # ── Password Policy ──────────────────────────────────────────────────────
    pw_rows = ""
    for r in results["password_policy"]:
        if r["password_never_expires"]:
            pw_rows += _row("⚠️", f"{r['display_name']} — password never expires", r["user"])
        else:
            pw_rows += _row("✅", r["display_name"], r["user"])
    pw_section = _section("Password Policy", pw_rows or _row("✅", "All accounts have password expiration enforced"),
                          next((s for s in score["sections"] if s["name"] == "Password Policy"), None))

    # ── SSPR ─────────────────────────────────────────────────────────────────
    sspr = results["sspr"]
    if sspr.get("error"):
        sspr_rows = _row("—", sspr["error"])
    elif sspr.get("enabled"):
        sspr_rows = _row("✅", f"SSPR is enabled — scope: {sspr['scope']}")
    else:
        sspr_rows = _row("❌", "Self-Service Password Reset is not enabled")
    sspr_section = _section("Self-Service Password Reset", sspr_rows,
                            next((s for s in score["sections"] if s["name"] == "SSPR Enabled"), None))

    # ── Score breakdown ───────────────────────────────────────────────────────
    score_rows = ""
    for s in score["sections"]:
        if s["skipped"]:
            score_rows += f'<tr><td style="padding:6px 8px">{s["name"]}</td><td style="color:#94a3b8;text-align:center">skipped</td><td></td></tr>'
        else:
            pct = round((s["earned"] / s["possible"]) * 100) if s["possible"] else 0
            bar_color = _score_color(pct)
            bar = f'<div style="background:#334155;border-radius:4px;height:8px;width:100px;display:inline-block;vertical-align:middle"><div style="background:{bar_color};width:{pct}%;height:8px;border-radius:4px"></div></div>'
            score_rows += f'<tr><td style="padding:6px 8px;color:#cbd5e1">{s["name"]}</td><td style="text-align:center;color:{bar_color};font-weight:600">{s["earned"]}/{s["possible"]}</td><td style="padding-left:8px">{bar}</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Tenant Security Audit Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; padding: 32px; }}
    a {{ color: #60a5fa; }}
  </style>
</head>
<body>
  <div style="max-width:860px;margin:0 auto">

    <div style="margin-bottom:32px">
      <h1 style="font-size:1.8em;font-weight:700;color:#f1f5f9">Tenant Security Audit Report</h1>
      <p style="color:#94a3b8;margin-top:4px">Tenant ID: {tenant_id} &nbsp;|&nbsp; Generated: {now}</p>
    </div>

    <div style="background:#1e293b;border-radius:12px;padding:28px;margin-bottom:24px;display:flex;align-items:center;gap:32px">
      <div style="text-align:center">
        <div style="font-size:4em;font-weight:800;color:{color};line-height:1">{overall}</div>
        <div style="color:{color};font-weight:600;font-size:1.1em">{label}</div>
        <div style="color:#94a3b8;font-size:0.85em;margin-top:4px">{score['earned']}/{score['possible']} points</div>
      </div>
      <div style="flex:1">
        <table style="width:100%;border-collapse:collapse">
          {score_rows}
        </table>
      </div>
    </div>

    {mfa_section}
    {ca_section}
    {legacy_section}
    {roles_section}
    {guest_section}
    {stale_section}
    {risky_section}
    {fwd_section}
    {pw_section}
    {sspr_section}

  </div>
</body>
</html>"""

    return html


def save_report(html, path="report.html"):
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  Report saved to: {path}")
