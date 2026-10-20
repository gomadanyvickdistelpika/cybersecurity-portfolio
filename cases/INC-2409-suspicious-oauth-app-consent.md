# INC-2409 — Suspicious OAuth app consent

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2409)

| Field | Value |
|---|---|
| Category | Identity / Illicit consent |
| Priority | High |
| Detection source | Microsoft Entra audit logs |
| Affected entity | Tomás Reilly · Marketing |
| Opened | 2026-10-06 11:05 UTC |

**Summary:** User granted a new third-party app full access to mail and files after clicking a 'shared document' link.

## 1. Evidence
### Alert
```text
Activity  : Consent to application
App name  : "DocuView Secure Share"
Publisher : Unverified
AppId     : 9b1e2f44-0c7a-4d1e-8f2b-55a0c3d9e111
Permissions (delegated): Mail.Read, Mail.Send, Files.ReadWrite.All, offline_access
```

### App activity
```text
11:02  App read 1,204 messages from tomas.reilly mailbox
11:03  App downloaded 86 files from OneDrive
11:04  App sent 40 emails "Tomás shared a document with you" to external contacts
Reply URL: hxxps://docuview-share[.]example/callback
```

### User interview
```text
Tomás clicked 'Open document' in an email from a known supplier and clicked 'Accept' on the permissions page.
```

## 2. Hunting query (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend App = tostring(TargetResources[0].displayName),
         User = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, User, App, Result
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| App ID | `9b1e2f44-0c7a-4d1e-8f2b-55a0c3d9e111` |  |
| URL | `hxxps://docuview-share[.]example/callback` |  |

## 4. MITRE ATT&CK mapping
- [T1528](https://attack.mitre.org/techniques/T1528/) — Steal Application Access Token *(Credential Access)*
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/) — Phishing: Spearphishing Link *(Initial Access)*

## 5. L1 runbook (internal KB SOC-ID-011 — Illicit consent grant)
1. Review the app: publisher verified? Permissions requested? Reply URL?
2. Check what the app has already done with its access.
3. Revoke the consent and disable the app's service principal per policy.
4. Escalate if the app read or sent data.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

An unverified app with mail and file permissions already took data and spread the lure. Password reset alone does not stop OAuth tokens.

## 7. Model ticket notes
- **Short description:** Illicit OAuth consent — data accessed, lure sent — escalated
- **Investigation:** Unverified app 'DocuView Secure Share' granted Mail.Read, Mail.Send, Files.ReadWrite.All, offline_access. Read 1,204 messages, downloaded 86 files, sent 40 lures to external contacts.
- **Actions:** Revoked OAuth grants, disabled the service principal, blocked reply URL domain. Recommended admin-consent workflow.
- **Next step:** Escalated to L2: data-exposure assessment and contact affected external recipients.

## References
- [Microsoft — App consent grant investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)

[← Back to casebook](README.md)
