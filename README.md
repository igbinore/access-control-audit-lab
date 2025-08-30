# Access Control Audit — Starter Lab

This lab helps you practice a **user & role access review** like an IT auditor.

## What you'll do
1. Load a small user list.
2. Check for **Segregation of Duties (SoD)** conflicts (e.g., GlobalAdmin + BillingAdmin).
3. Find **privileged accounts** without **MFA**.
4. Spot **dormant accounts** (no login in 90+ days).
5. Flag **service/shared** accounts holding privileged roles.
6. Export an **audit report** and a **findings CSV** you can share.

> Everything is simple and self-contained. You can replace the sample users with your own exports later.

---

## Folder structure
```
access_control_audit_lab/
├── data/
│   └── users.csv            # sample data (you can edit)
├── scripts/
│   └── audit_access.py      # run this script
└── output/                  # reports are generated here
```

## Step-by-step (simple)
1. **Download** this folder (use the ZIP below).
2. If you want, open `data/users.csv` and change/add users.
   - `roles` are separated by semicolons like `GlobalAdmin;SecurityAdmin`
   - `mfa_enabled` is `True` or `False`
   - `account_type` can be `User`, `Service`, or `Shared`
3. **Run the audit** (from the folder root):
   ```bash
   python3 scripts/audit_access.py
   ```
4. **Open results** in `output/`:
   - `findings.csv` — each account with issues and risk
   - `summary.json` — quick totals and examples
   - `report.md` — human‑readable summary for your README or PDF

## What the script checks
- **SoD conflicts** (bad role pairs):  
  - `GlobalAdmin` + `BillingAdmin`  
  - `UserAdmin` + `SecurityAdmin`  
  - `Developer` + `DBA_Prod`
- **Privileged roles without MFA** (e.g., `GlobalAdmin`, `SecurityAdmin`, `DBA_Prod`)
- **Dormant accounts** (>90 days since last login)
- **Privileged non‑person accounts** (Service/Shared with admin roles)
- **Inactive accounts with roles** (should be removed)

## How to explain this on LinkedIn
> *“Built an Access Control Audit lab that detects SoD conflicts, flags privileged accounts without MFA, and identifies dormant/shared/service accounts. Produced a findings CSV and a clean Markdown report—mimicking a real audit deliverable.”*

---

## Next steps (optional)
- Replace the sample `users.csv` with a real export from Entra/AD/Okta (remove secrets).
- Add more SoD pairs to the script (easy Python list).
- Pipe `report.md` into a PDF for portfolio uploads.

Good luck! 🚀
