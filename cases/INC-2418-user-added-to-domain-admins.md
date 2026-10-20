# INC-2418 — User added to Domain Admins

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2418)

| Field | Value |
|---|---|
| Category | Identity / Privilege escalation |
| Priority | High |
| Detection source | Windows Security log (DC01) |
| Affected entity | svc_backup2 → Domain Admins |
| Opened | 2026-10-08 23:47 UTC |

**Summary:** A service account was added to Domain Admins at night, with no change ticket.

## 1. Evidence
### Event 4728
```text
EventID   : 4728  A member was added to a security-enabled global group
Time      : 2026-10-08 23:41:07 UTC
Computer  : DC01.harbourline.local
Subject   : HARBOURLINE\helpdesk.tmp   (Logon ID 0x3E7A1F)
Member    : CN=svc_backup2,OU=Service Accounts,DC=harbourline,DC=local
Group     : Domain Admins
```

### Logons
```text
23:38:55  4624  helpdesk.tmp  LogonType 10 (RDP)  from 10.20.30.77 (JUMP-02)
helpdesk.tmp was created 2026-10-08 22:10 — not in HR or the access request system
```

### Change calendar
```text
No approved change for Domain Admins membership this week.
Domain Admins owner: Infrastructure (only 3 named admins expected)
```

## 2. Hunting query (KQL)
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)       // added to global / local / universal group
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Administrators")
| project TimeGenerated, Computer, SubjectAccount, MemberName, TargetUserName
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| Account | `HARBOURLINE\helpdesk.tmp` |  |
| Account | `svc_backup2` |  |
| Host | `JUMP-02 (10.20.30[.]77)` |  |

## 4. MITRE ATT&CK mapping
- [T1098](https://attack.mitre.org/techniques/T1098/) — Account Manipulation *(Persistence)*
- [T1136.002](https://attack.mitre.org/techniques/T1136/002/) — Create Account: Domain Account *(Persistence)*
- [T1078.002](https://attack.mitre.org/techniques/T1078/002/) — Valid Accounts: Domain Accounts *(Privilege Escalation)*

## 5. L1 runbook (internal KB SOC-AD-002 — Privileged group changes)
1. Check who made the change and whether a change ticket exists.
2. Check the account that made the change — is it known and expected?
3. No ticket and an unknown actor: treat as privilege escalation; escalate immediately (L1 does not edit AD).
4. Preserve the events.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

An unknown account created two hours earlier added a service account to Domain Admins at night with no change. Possible domain compromise.

## 7. Model ticket notes
- **Short description:** Unauthorised Domain Admins addition by unknown account — escalated
- **Investigation:** Event 4728 on DC01 at 23:41: helpdesk.tmp added svc_backup2 to Domain Admins. helpdesk.tmp was created at 22:10, not in HR/IAM, and logged on via RDP from JUMP-02. No change ticket.
- **Actions:** Preserved event logs. Paged Infrastructure on-call. No AD changes made by L1.
- **Next step:** Escalated to L2/IR as P1 — possible domain compromise starting from JUMP-02.

## References
- [Microsoft — Monitoring AD for signs of compromise](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
- [MITRE ATT&CK T1098](https://attack.mitre.org/techniques/T1098/)

[← Back to casebook](README.md)
