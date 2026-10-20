# INC-2415 — Departing employee mass download

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2415)

| Field | Value |
|---|---|
| Category | Insider / Data exfiltration |
| Priority | High |
| Detection source | Defender for Cloud Apps / Insider Risk |
| Affected entity | Paul Quinn · Sales (leaving Friday) |
| Opened | 2026-10-08 16:10 UTC |

**Summary:** A user who resigned downloaded 3,400 SharePoint files and uploaded a large archive to a personal cloud drive.

## 1. Evidence
### Alert
```text
Policy : Mass download by a single user
User   : paul.quinn@harbourline.example
Files  : 3,412 from "Sales — Customer Accounts" (Confidential)
Window : 15:20–15:55 UTC
```

### HR context
```text
HR flag: resignation submitted 2026-09-30, last day 2026-10-09.
Joining a competitor (per HR, do not contact the user directly).
```

### Endpoint / proxy
```text
16:02  LT-SAL-019  7z.exe a C:\Temp\backup.7z  (2.1 GB)
16:05  chrome.exe upload -> personal-drive-cloud[.]example   2.1 GB   Allowed (category: Personal storage)
```

## 2. Hunting query (KQL)
```kql
CloudAppEvents
| where Timestamp > ago(1d)
| where AccountDisplayName == "Paul Quinn"
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Files = count(), Sites = make_set(tostring(RawEventData.SiteUrl)) by bin(Timestamp, 15m)
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| Domain | `personal-drive-cloud[.]example` |  |

## 4. MITRE ATT&CK mapping
- [T1530](https://attack.mitre.org/techniques/T1530/) — Data from Cloud Storage *(Collection)*
- [T1560.001](https://attack.mitre.org/techniques/T1560/001/) — Archive Collected Data: Archive via Utility *(Collection)*
- [T1567.002](https://attack.mitre.org/techniques/T1567/002/) — Exfiltration Over Web Service: Exfiltration to Cloud Storage *(Exfiltration)*

## 5. L1 runbook (internal KB SOC-INS-001 — Insider data theft — leaver)
1. Confirm volume and sensitivity of the data.
2. Check HR context (leaver / notice period).
3. Do NOT contact the user. Preserve evidence.
4. Escalate to L2 and the insider-risk / HR / legal process.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

Confidential customer data was archived and uploaded to personal storage by a leaver joining a competitor. This needs HR/legal, not an L1 closure.

## 7. Model ticket notes
- **Short description:** Leaver exfiltrated Confidential customer data to personal cloud — escalated
- **Investigation:** 3,412 Confidential files downloaded 15:20–15:55, archived to backup.7z (2.1 GB) at 16:02 and uploaded to personal-drive-cloud.example at 16:05. HR confirms resignation, last day 09 Oct, joining competitor.
- **Actions:** Evidence preserved. No contact with user. Requested blocking personal storage category for this user via policy.
- **Next step:** Escalated to L2 and Insider Risk/HR/Legal per KB SOC-INS-001.

## References
- [MITRE ATT&CK T1567.002](https://attack.mitre.org/techniques/T1567/002/)

[← Back to casebook](README.md)
