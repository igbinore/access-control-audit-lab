# Access Control Audit — Starter Lab

**IT audit** lab that automates a user & role access review. It detects:
- **Segregation of Duties (SoD) conflicts** (e.g., `GlobalAdmin + BillingAdmin`)
- **Privileged accounts without MFA**
- **Dormant** (>90 days) or **inactive** users with roles
- **Service/Shared** accounts holding privileged roles

**Deliverables:** `output/findings.csv`, `output/report.md` (optional PDF), `output/summary.json`  
See also: [`controls_map.md`](./controls_map.md) for ISO/NIST/COBIT mappings.

---

## Run it (Windows Command Prompt)

```bat
cd /d C:\Users\<YOU>\Downloads\access-control-audit-lab
python scripts\audit_access.py
:: or
py -3 scripts\audit_access.py
Open results

bat
Copy code
start output\findings.csv
notepad output\report.md
notepad output\summary.json
Want a PDF? Open output\report.md and print to Microsoft Print to PDF (save as output\Access_Control_Audit_Report.pdf).

Controls tested
SoD conflicts: GlobalAdmin + BillingAdmin, UserAdmin + SecurityAdmin, Developer + DBA_Prod

MFA on privileged roles: required for admin roles (Global/Security/Exchange/SharePoint, DBA_Prod, etc.)

Dormancy / inactivity: last login > 90 days, or inactive user still has roles

Non-person privileged accounts: Service/Shared accounts should not hold admin roles

Results (example from my run)
yaml
Copy code
Total accounts reviewed: <paste from output/summary.json>
Risk levels: {"High": x, "Medium": y, "Compliant": z}
Sample high-risk:
- alice: SoD conflict (GlobalAdmin + BillingAdmin)
- grace: Has privileged role(s) without MFA: SecurityAdmin
- shared-helpdesk: Privileged non-person account (Shared)
Make it your own
Replace data/users.csv with a sanitized Entra/AD/Okta export (no real PII).

Add/remove SoD pairs at the top of scripts/audit_access.py.

Map findings to frameworks in controls_map.md.

Repo structure
pgsql
Copy code
access-control-audit-lab/
├─ data/
│  └─ users.csv
├─ scripts/
│  └─ audit_access.py
└─ output/
   ├─ findings.csv
   ├─ report.md  (and/or Access_Control_Audit_Report.pdf)
   └─ summary.json
Disclaimer
Sample data only—sanitize any real exports before sharing.