# Access Control Audit Report

Generated: 2025-08-29 17:19:20Z

# Executive Summary
- Scope: User & role access review (privileged roles, MFA, SoD, dormancy, inactive).
- Method: Automated checks using a Python script; results in CSV + Markdown.
- Key Risks: <add 2–3 from findings.csv, e.g., "Privileged roles without MFA", "SoD conflicts">.
- Impact: Fraud/unauthorized changes; increased breach exposure.
- Top Actions: Enforce MFA on admins; fix SoD conflicts; disable/recertify dormant/inactive; remove roles from inactive.


Total accounts reviewed: 12

## Risk Overview

- **High**: 7
- **Compliant**: 3
- **Medium**: 2

## High-Risk Findings (samples)

- alice: Has privileged role(s) without MFA: GlobalAdmin, SecurityAdmin
- carol: SoD conflict: UserAdmin + SecurityAdmin
- dave: SoD conflict: Developer + DBA_Prod
- grace: Has privileged role(s) without MFA: ExchangeAdmin, SharePointAdmin | Dormant account: last login 200 days ago
- heidi: Has privileged role(s) without MFA: HelpdeskAdmin

## Full Findings Table (Top 20)

| username        | account_type   | roles                         | mfa_enabled   | last_login   | active   | risk_level   | issues                                                                                                        |
|:----------------|:---------------|:------------------------------|:--------------|:-------------|:---------|:-------------|:--------------------------------------------------------------------------------------------------------------|
| alice           | User           | GlobalAdmin;SecurityAdmin     | False         | 2025-08-24   | True     | High         | Has privileged role(s) without MFA: GlobalAdmin, SecurityAdmin                                                |
| bob             | User           | BillingAdmin;BillingReader    | True          | 2025-08-17   | True     | Compliant    |                                                                                                               |
| carol           | User           | UserAdmin;SecurityAdmin       | True          | 2025-08-27   | True     | High         | SoD conflict: UserAdmin + SecurityAdmin                                                                       |
| dave            | User           | Developer;DBA_Prod            | True          | 2025-07-20   | True     | High         | SoD conflict: Developer + DBA_Prod                                                                            |
| eve             | User           | ReadOnly                      | True          | 2025-04-21   | True     | Medium       | Dormant account: last login 130 days ago                                                                      |
| frank           | User           | HRManager                     | True          | 2025-08-28   | True     | Compliant    |                                                                                                               |
| grace           | User           | ExchangeAdmin;SharePointAdmin | False         | 2025-02-10   | True     | High         | Has privileged role(s) without MFA: ExchangeAdmin, SharePointAdmin | Dormant account: last login 200 days ago |
| heidi           | User           | HelpdeskAdmin                 | False         | 2025-08-21   | True     | High         | Has privileged role(s) without MFA: HelpdeskAdmin                                                             |
| ivan            | User           | ReadOnly                      | True          | 2024-07-25   | False    | Medium       | Inactive account still has roles assigned                                                                     |
| joy             | User           | SalesRep                      | True          | 2025-08-22   | True     | Compliant    |                                                                                                               |
| svc-backup      | Service        | SecurityAdmin                 | False         | 2025-06-30   | True     | High         | Has privileged role(s) without MFA: SecurityAdmin | Privileged non-person account (Service)                   |
| shared-helpdesk | Shared         | HelpdeskAdmin                 | False         | 2025-08-25   | True     | High         | Has privileged role(s) without MFA: HelpdeskAdmin | Privileged non-person account (Shared)                    |