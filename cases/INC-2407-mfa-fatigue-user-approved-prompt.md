# INC-2407 — MFA fatigue — user approved prompt

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2407)

| Field | Value |
|---|---|
| Category | Identity / MFA fatigue |
| Priority | High |
| Detection source | Microsoft Sentinel |
| Affected entity | Aoife Murphy · HR |
| Opened | 2026-10-06 07:48 UTC |

**Summary:** User received 23 MFA push prompts in 10 minutes late at night and approved the last one.

## 1. Evidence
### Alert
```text
Analytic rule : Multiple MFA denials followed by approval
User          : aoife.murphy@harbourline.example
Window        : 2026-10-06 01:12–01:22 UTC
Denied/ignored: 22   Approved: 1 (01:22:05)
Source IP     : 203.0.113.150 (residential proxy, Romania)
```

### Sign-in logs
```text
01:22:05  203.0.113.150  Office 365 Exchange Online  Success  MFA: Approved (push)  Device: unregistered  Browser: Chrome/Linux
01:23:40  203.0.113.150  Microsoft Authenticator — Register security info   Success
```

### Audit logs
```text
01:23:41  User registered new authentication method: Authenticator app "Pixel 7"
01:25:10  New inbox rule created: Name "." — Move messages containing "payroll" to RSS Feeds
```

### User interview
```text
Aoife says her phone kept buzzing in the night and she pressed Approve "to make it stop".
She does not own a Pixel 7.
```

## 2. Hunting query (KQL)
```kql
// Users with many MFA denials then a success
SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize Denied = countif(ResultType in ("500121", "50074")),
            Success = countif(ResultType == "0"),
            IPs = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where Denied >= 5 and Success >= 1
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| IP | `203.0.113[.]150` |  |
| MFA device | `Authenticator 'Pixel 7' (attacker)` |  |

## 4. MITRE ATT&CK mapping
- [T1621](https://attack.mitre.org/techniques/T1621/) — Multi-Factor Authentication Request Generation *(Credential Access)*
- [T1098.005](https://attack.mitre.org/techniques/T1098/005/) — Account Manipulation: Device Registration *(Persistence)*
- [T1564.008](https://attack.mitre.org/techniques/T1564/008/) — Hide Artifacts: Email Hiding Rules *(Defense Evasion)*

## 5. L1 runbook (internal KB SOC-ID-009 — MFA fatigue / push bombing)
1. Check MFA logs for many denials followed by an approval.
2. Check for new MFA methods, inbox rules or mailbox access after the approval.
3. Revoke sessions, remove the rogue MFA method, disable the account per policy.
4. Escalate — the attacker had a valid session.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

The attacker got in, registered their own MFA device and hid payroll emails. That is a compromised account with persistence.

## 7. Model ticket notes
- **Short description:** MFA fatigue — account compromised, attacker MFA added — escalated
- **Investigation:** 22 prompts denied/ignored then approved at 01:22 from residential proxy 203.0.113.150. Attacker registered 'Pixel 7' Authenticator and created a hidden '.' rule moving 'payroll' mail to RSS Feeds. User confirms she approved to stop the prompts.
- **Actions:** Revoked all sessions, removed the rogue Authenticator method, disabled the account pending reset, removed the inbox rule (exported first as evidence).
- **Next step:** Escalated to L2: check for payroll/BEC fraud, review mailbox access, recommend number matching.

## References
- [MITRE ATT&CK T1621](https://attack.mitre.org/techniques/T1621/)
- [Microsoft — How number matching works in MFA push](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match)

[← Back to casebook](README.md)
