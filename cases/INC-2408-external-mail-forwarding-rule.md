# INC-2408 — External mail forwarding rule

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2408)

| Field | Value |
|---|---|
| Category | Email / Business email compromise |
| Priority | High |
| Detection source | Defender for Cloud Apps |
| Affected entity | Declan Shaw · Finance Director |
| Opened | 2026-10-06 09:30 UTC |

**Summary:** A new inbox rule forwards every email with 'invoice' or 'bank' to a free webmail address.

## 1. Evidence
### Alert
```text
Policy : Suspicious inbox forwarding
User   : declan.shaw@harbourline.example
Rule   : "Sync" — If subject/body contains "invoice" OR "bank" OR "payment"
         -> Forward to accounts.dshaw@freemail-box.example
         -> Mark as read, Move to Archive
```

### Audit logs
```text
Operation : New-InboxRule
ClientIP  : 198.51.100.200
UserAgent : python-requests/2.31
Time      : 2026-10-06 03:14 UTC
```

### Sign-in logs
```text
03:10  198.51.100.200  Success  MFA: satisfied by token  (session from 2026-10-04 AiTM phishing page?)
Normal pattern for this user: Dublin office 192.0.2.10 and home ISP only
```

## 2. Hunting query (KQL)
```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend Params = tostring(Parameters)
| where Params has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project TimeGenerated, UserId, ClientIP, Params
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| Email | `accounts.dshaw@freemail-box[.]example` |  |
| IP | `198.51.100[.]200` |  |

## 4. MITRE ATT&CK mapping
- [T1114.003](https://attack.mitre.org/techniques/T1114/003/) — Email Collection: Email Forwarding Rule *(Collection)*
- [T1564.008](https://attack.mitre.org/techniques/T1564/008/) — Hide Artifacts: Email Hiding Rules *(Defense Evasion)*
- [T1550.004](https://attack.mitre.org/techniques/T1550/004/) — Use Alternate Authentication Material: Web Session Cookie *(Defense Evasion)*

## 5. L1 runbook (internal KB SOC-EMAIL-005 — Business email compromise — first response)
1. Check who created the rule, from where, and with what client.
2. Forwarding to an external personal address from an unknown IP = treat as BEC.
3. Disable the rule (export first), revoke sessions, block the external address.
4. Escalate — finance mailbox, possible payment fraud.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

A script from an unknown IP created a hidden external forward on the Finance Director's mailbox. Classic BEC — high fraud risk.

## 7. Model ticket notes
- **Short description:** BEC — external forwarding rule on Finance Director mailbox — escalated
- **Investigation:** Rule 'Sync' forwards invoice/bank/payment mail to freemail-box.example and archives it. Created at 03:14 from 198.51.100.200 with python-requests — not the user's normal locations. Sign-in used an existing token (likely stolen session cookie).
- **Actions:** Exported and disabled rule, revoked sessions, blocked external address and IP. Asked Finance to hold any bank-detail changes received since 2026-10-04.
- **Next step:** Escalated to L2: scope what was forwarded, check for AiTM phishing on 04 Oct, notify Finance and legal if payments affected.

## References
- [MITRE ATT&CK T1114.003](https://attack.mitre.org/techniques/T1114/003/)
- [Microsoft — Compromised email account response](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account)

[← Back to casebook](README.md)
