#!/usr/bin/env python3
"""
Access Control Audit (User & Role Review)
- Reads data/users.csv
- Flags Segregation of Duties (SoD) conflicts
- Flags privileged accounts without MFA
- Flags dormant accounts (>90 days no login)
- Flags privileged non-person accounts (Service/Shared)
- Flags inactive accounts that still have roles
Outputs:
- output/findings.csv
- output/summary.json
- output/report.md
"""
import os, json
import pandas as pd
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data", "users.csv")
OUTD = os.path.join(BASE, "output")
os.makedirs(OUTD, exist_ok=True)

# --- Config ---
PRIVILEGED_ROLES = {
    "GlobalAdmin", "PrivilegedRoleAdmin", "UserAdmin", "SecurityAdmin",
    "BillingAdmin", "ExchangeAdmin", "SharePointAdmin", "HelpdeskAdmin", "DBA_Prod"
}

SOD_CONFLICTS = [
    ("GlobalAdmin", "BillingAdmin"),
    ("UserAdmin", "SecurityAdmin"),
    ("Developer", "DBA_Prod"),
    ("ExchangeAdmin", "SharePointAdmin"),
]

DORMANT_DAYS = 90

def parse_roles(s):
    if not isinstance(s, str) or not s.strip():
        return []
    return [r.strip() for r in s.split(";") if r.strip()]

def risk_from_issues(issues):
    # High if any SoD or privileged without MFA or privileged non-person
    if any("SoD conflict" in i for i in issues): return "High"
    if any("privileged role(s) without MFA" in i for i in issues): return "High"
    if any("Privileged non-person account" in i for i in issues): return "High"
    # Medium for dormant or inactive with roles
    if any("Dormant account" in i for i in issues): return "Medium"
    if any("Inactive account still has roles" in i for i in issues): return "Medium"
    return "Low" if issues else "Compliant"

def main():
    today = datetime.utcnow().date()
    df = pd.read_csv(DATA)
    findings = []
    for _, row in df.iterrows():
        roles = parse_roles(row.get("roles", ""))
        issues = []
        # SoD conflicts
        role_set = set(roles)
        for a, b in SOD_CONFLICTS:
            if a in role_set and b in role_set:
                issues.append(f"SoD conflict: {a} + {b}")
        # Privileged without MFA
        priv_roles = sorted(role_set & PRIVILEGED_ROLES)
        mfa = bool(row.get("mfa_enabled", False))
        if priv_roles and not mfa:
            issues.append(f"Has privileged role(s) without MFA: {', '.join(priv_roles)}")
        # Dormant account
        try:
            last_login = datetime.strptime(str(row.get('last_login', '1900-01-01')), "%Y-%m-%d").date()
            days = (today - last_login).days
            if bool(row.get("active", True)) and days > DORMANT_DAYS:
                issues.append(f"Dormant account: last login {days} days ago")
        except Exception:
            issues.append("Invalid last_login date format")
        # Privileged non-person accounts
        acct_type = str(row.get("account_type", "User"))
        if acct_type in ("Service", "Shared") and priv_roles:
            issues.append(f"Privileged non-person account ({acct_type})")
        # Inactive but has roles
        if not bool(row.get("active", True)) and roles:
            issues.append("Inactive account still has roles assigned")
        risk = risk_from_issues(issues)
        findings.append({
            "username": row.get("username"),
            "email": row.get("email"),
            "account_type": acct_type,
            "roles": ";".join(roles),
            "mfa_enabled": bool(row.get("mfa_enabled", False)),
            "last_login": row.get("last_login"),
            "active": bool(row.get("active", True)),
            "issues": " | ".join(issues),
            "risk_level": risk
        })
    out_df = pd.DataFrame(findings)
    out_csv = os.path.join(OUTD, "findings.csv")
    out_df.to_csv(out_csv, index=False)

    # Summary
    summary = {
        "total_accounts": len(out_df),
        "by_risk": out_df["risk_level"].value_counts().to_dict(),
        "high_risk_examples": out_df[out_df["risk_level"]=="High"][["username","issues"]].head(5).to_dict(orient="records")
    }
    with open(os.path.join(OUTD, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Report
    lines = []
    lines.append("# Access Control Audit Report\n")
    lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}\n")
    lines.append(f"Total accounts reviewed: {summary['total_accounts']}\n")
    lines.append("## Risk Overview\n")
    for k,v in summary["by_risk"].items():
        lines.append(f"- **{k}**: {v}")
    lines.append("\n## High-Risk Findings (samples)\n")
    if summary["high_risk_examples"]:
        for ex in summary["high_risk_examples"]:
            lines.append(f"- {ex['username']}: {ex['issues']}")
    else:
        lines.append("- None")
    lines.append("\n## Full Findings Table (Top 20)\n")
    head = out_df.head(20).copy()
    # Keep relevant columns
    head = head[["username","account_type","roles","mfa_enabled","last_login","active","risk_level","issues"]]
    lines.append(head.to_markdown(index=False))
    with open(os.path.join(OUTD, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    main()
