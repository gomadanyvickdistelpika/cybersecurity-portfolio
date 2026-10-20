# INC-2414 — Office macro launched PowerShell

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2414)

| Field | Value |
|---|---|
| Category | Endpoint / Malicious document |
| Priority | High |
| Detection source | Defender for Endpoint |
| Affected entity | LT-PRC-007 · Ciarán Hughes |
| Opened | 2026-10-07 13:40 UTC |

**Summary:** Excel opened an attachment and immediately started encoded PowerShell, which wrote a scheduled task.

## 1. Evidence
### Process tree
```text
outlook.exe
 └─ excel.exe  "C:\Users\chughes\AppData\Local\...\PO_44871.xlsm"
     └─ powershell.exe -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...
         └─ schtasks.exe /create /sc minute /mo 30 /tn "OneDriveSyncCheck" /tr "C:\Users\Public\odsync.exe"
```

### Email
```text
From    : purchasing@supplier-orders[.]example
Subject : PO 44871 — urgent revision
Attachment: PO_44871.xlsm  (macro-enabled)  — user clicked "Enable Content"
```

### File events
```text
13:38:10  FileCreated  C:\Users\Public\odsync.exe   (SHA256 a1b2...ef90, unsigned)
13:38:12  ScheduledTaskCreated  OneDriveSyncCheck
```

## 2. Hunting query (KQL)
```kql
// Office apps spawning script interpreters
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| Sender | `purchasing@supplier-orders[.]example` |  |
| File | `PO_44871.xlsm` |  |
| File | `C:\Users\Public\odsync[.]exe` |  |
| Task | `OneDriveSyncCheck` |  |

## 4. MITRE ATT&CK mapping
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/) — Phishing: Spearphishing Attachment *(Initial Access)*
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/) — User Execution: Malicious File *(Execution)*
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — Command and Scripting Interpreter: PowerShell *(Execution)*
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/) — Scheduled Task/Job: Scheduled Task *(Persistence)*

## 5. L1 runbook (internal KB SOC-EDR-005 — Malicious Office document)
1. Office app → script interpreter is almost never legitimate.
2. Check for dropped files and persistence (scheduled tasks, run keys, services).
3. Isolate, collect evidence, purge the email from all mailboxes.
4. Escalate.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

Code ran and set up persistence. That is a compromised endpoint, not a blocked attempt.

## 7. Model ticket notes
- **Short description:** Macro → PowerShell → persistence on LT-PRC-007 — escalated
- **Investigation:** User enabled macros in PO_44871.xlsm. Excel spawned hidden encoded PowerShell, which dropped unsigned odsync.exe and created scheduled task 'OneDriveSyncCheck' every 30 minutes.
- **Actions:** Isolated device, purged email from all mailboxes, blocked sender domain and file hash.
- **Next step:** Escalated to L2; recommend blocking macros from internet files via policy.

## References
- [MITRE ATT&CK T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)

[← Back to casebook](README.md)
