# INC-2404 — Password spray with one success

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2404)

| Field | Value |
|---|---|
| Category | Identity / Password spray |
| Priority | High |
| Detection source | Microsoft Sentinel |
| Affected entity | 18 user accounts |
| Opened | 2026-10-05 12:07 UTC |

**Summary:** One external IP failed logins against 18 accounts, then one sign-in succeeded over a legacy protocol (no MFA).

## 1. Evidence
### Alert
```text
Analytic rule : Password spray — many accounts, one source IP
Source IP     : 198.51.100.77  (hosting provider, no prior history)
Window        : 11:40–12:05 UTC
Failures      : 54 (error 50126 — invalid username or password) across 18 users
Success       : 1
```

### Sign-in logs
```text
12:03:18  j.walsh@harbourline.example  198.51.100.77  Client: Authenticated SMTP  Result: Success  MFA: Not applied (legacy auth)
12:03:19  r.kelly@harbourline.example  198.51.100.77  Client: Authenticated SMTP  Result: 50126
12:03:21  s.obrien@harbourline.example 198.51.100.77  Client: Authenticated SMTP  Result: 50126
```

### Mailbox
```text
12:06:02  j.walsh  Send — 212 outbound messages in 3 minutes (external recipients)
```

## 2. Hunting query (KQL)
```kql
// Spray pattern: one IP, many users, few attempts each
SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress == "198.51.100.77"
| summarize Attempts = count(),
            Users = dcount(UserPrincipalName),
            Successes = countif(ResultType == "0"),
            Apps = make_set(ClientAppUsed)
    by IPAddress
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| IP | `198.51.100[.]77` |  |
| Account | `j.walsh@harbourline[.]example` | Compromised |

## 4. MITRE ATT&CK mapping
- [T1110.003](https://attack.mitre.org/techniques/T1110/003/) — Brute Force: Password Spraying *(Credential Access)*
- [T1078.004](https://attack.mitre.org/techniques/T1078/004/) — Valid Accounts: Cloud Accounts *(Initial Access)*

## 5. L1 runbook (internal KB SOC-ID-007 — Password spray response)
1. Confirm the spray pattern (one IP, many users, low attempts per user).
2. Check for any successful sign-in from that IP.
3. No success: block the IP and close.
4. Any success: treat the account as compromised — disable/revoke sessions per policy and escalate.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

A spray with a successful sign-in, no MFA and 212 outbound emails is a compromised account sending spam/phishing. Needs L2 and identity team.

## 7. Model ticket notes
- **Short description:** Password spray — j.walsh compromised via legacy SMTP auth — escalated
- **Investigation:** 198.51.100.77 attempted 18 accounts (54 failures). j.walsh succeeded at 12:03 via Authenticated SMTP — legacy auth bypassed MFA. Account sent 212 external emails within 3 minutes.
- **Actions:** Revoked sessions and disabled j.walsh per runbook. Blocked 198.51.100.77. Raised request to disable SMTP AUTH for the tenant.
- **Next step:** Escalated to L2: password reset, mailbox rules review, outbound spam clean-up, legacy auth policy.

## References
- [Microsoft — Password spray investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray)
- [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)

[← Back to casebook](README.md)
