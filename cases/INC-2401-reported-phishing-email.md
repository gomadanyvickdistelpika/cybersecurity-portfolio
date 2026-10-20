# INC-2401 — Reported phishing email

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2401)

| Field | Value |
|---|---|
| Category | Email / Phishing |
| Priority | Medium |
| Detection source | Defender for Office 365 |
| Affected entity | Maya Chen · Finance |
| Opened | 2026-10-05 09:14 UTC |

**Summary:** User reported an unexpected 'Microsoft 365 password expiry' email. She says she did not enter her password.

## 1. Evidence
### Alert
```text
AlertName      : Email reported by user as malware or phish
Severity       : Medium
NetworkMessageId: 7c1f0e2a-91d4-4b8e-a0f1-2d9b5e7c3a10
Recipient      : maya.chen@harbourline.example
ReportedAt     : 2026-10-05T09:12:47Z
```

### Headers
```text
From:            "Microsoft 365 Security" <no-reply@m365-security-alerts.example>
Return-Path:     <bounce@mailer-7731.example>
Subject:         Action required: your password expires today
Received:        from mailer-7731.example (198.51.100.23)
Authentication-Results: spf=fail smtp.mailfrom=mailer-7731.example;
                 dkim=none; dmarc=fail action=none header.from=m365-security-alerts.example
X-MS-Exchange-Organization-SCL: 5
Body link:       hxxps://login-microsoftonline-security[.]example/auth?u=maya.chen
```

### User interview
```text
09:20  Analyst call with Maya Chen
- Opened the message on her laptop, hovered over the button, did NOT click.
- Did not reply, open attachments or enter credentials.
- No unexpected MFA prompts on her phone today.
```

### Telemetry
```text
UrlClickEvents  (last 24h, Url has "login-microsoftonline-security")  -> 0 rows
SigninLogs      (maya.chen, last 24h)  -> 4 rows, all Dublin office IP 192.0.2.10, compliant device
EmailEvents     (same sender, last 7d) -> 3 recipients: maya.chen, ops.lead, ap.clerk  (all Delivered)
```

## 2. Hunting query (KQL)
```kql
// Find every copy of the campaign and any clicks
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain == "m365-security-alerts.example"
    or SenderIPv4 == "198.51.100.23"
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId
| join kind=leftouter (
    UrlClickEvents
    | where Url has "login-microsoftonline-security.example"
    | project NetworkMessageId, ClickTime = Timestamp, ActionType
  ) on NetworkMessageId
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| Sender | `no-reply@m365-security-alerts[.]example` |  |
| Domain | `login-microsoftonline-security[.]example` |  |
| URL | `hxxps://login-microsoftonline-security[.]example/auth` |  |
| IP | `198.51.100[.]23` | Sending server |

## 4. MITRE ATT&CK mapping
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/) — Phishing: Spearphishing Link *(Initial Access)*

## 5. L1 runbook (internal KB SOC-EMAIL-001 — User-reported phishing triage)
1. Check sender, SPF/DKIM/DMARC results, the link and how many people received it.
2. Confirm with the user: did they click, enter a password, open an attachment or approve an MFA prompt?
3. If there was no interaction and no sign of account compromise: quarantine all copies, block the sender and URL, tell the user, close.
4. Escalate if anyone clicked, entered credentials, ran a file, approved MFA, or if the campaign is wide.

## 6. Decision
**Resolved at L1** · Classification: **True positive**

The email is malicious, but nobody clicked, no credentials were entered, and sign-ins are clean. Quarantine and blocking are inside the L1 runbook, so L1 can close it.

## 7. Model ticket notes
- **Short description:** Reported phishing email — no user interaction — contained
- **Investigation:** SPF fail, DKIM none, DMARC fail; display name impersonates Microsoft. Link points to a look-alike login page. 3 recipients found; UrlClickEvents shows 0 clicks. User confirms no click, no credentials, no MFA approval. Sign-ins for the last 24h are from the Dublin office on a compliant device.
- **Actions:** Soft-deleted/quarantined all 3 copies. Blocked sender domain, sending IP and URL in Tenant Allow/Block List. Thanked the user and sent a short 'how to spot this' note to the 3 recipients.
- **Next step:** Closed at L1. Reopen if any new click or sign-in alert appears for these recipients.

## References
- [Microsoft — Phishing investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)
- [MITRE ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/)

[← Back to casebook](README.md)
