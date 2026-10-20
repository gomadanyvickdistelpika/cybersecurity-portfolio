# INC-2406 — Ransomware behaviour on laptop

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2406)

| Field | Value |
|---|---|
| Category | Endpoint / Ransomware |
| Priority | Critical |
| Detection source | EDR + file server alerts |
| Affected entity | ENG-LT-091 · Kai Morgan |
| Opened | 2026-10-05 15:02 UTC |

**Summary:** Mass file renames to .lockd and shadow-copy deletion seen from one engineering laptop, including on a mapped share.

## 1. Evidence
### Alert
```text
15:00:11  Ransomware behaviour detected   Severity: High
15:00:14  Shadow copy deletion            Severity: High
15:01:30  File server: 1,840 files renamed in 90s on \\fs01\engineering by HARBOURLINE\kmorgan
```

### Process tree
```text
winword.exe
 └─ cmd.exe /c %TEMP%\svc_upd.exe
     └─ svc_upd.exe
         ├─ vssadmin.exe delete shadows /all /quiet
         ├─ wbadmin.exe delete catalog -quiet
         └─ (writes README_RESTORE.txt in every folder)
```

### File events
```text
15:00:20  C:\Users\kmorgan\Documents\design_spec.docx -> design_spec.docx.lockd
15:00:20  C:\Users\kmorgan\Documents\BOM_rev3.xlsx   -> BOM_rev3.xlsx.lockd
15:01:02  \\fs01\engineering\Projects\P-118\drawing.dwg -> drawing.dwg.lockd
... 1,840 more
```

### Ransom note
```text
README_RESTORE.txt
"Your files are encrypted. Contact us on hxxp://lockd-support[.]example ..."
```

## 2. Hunting query (KQL)
```kql
// Mass renames from one host in a short window
DeviceFileEvents
| where Timestamp > ago(2h)
| where ActionType == "FileRenamed" and FileName endswith ".lockd"
| summarize Files = count(), First = min(Timestamp), Last = max(Timestamp) by DeviceName, InitiatingProcessFileName
| order by Files desc
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| File | `svc_upd.exe` |  |
| Extension | `.lockd` |  |
| URL | `hxxp://lockd-support[.]example` |  |

## 4. MITRE ATT&CK mapping
- [T1486](https://attack.mitre.org/techniques/T1486/) — Data Encrypted for Impact *(Impact)*
- [T1490](https://attack.mitre.org/techniques/T1490/) — Inhibit System Recovery *(Impact)*
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/) — User Execution: Malicious File *(Execution)*

## 5. L1 runbook (internal KB SOC-IR-001 — Suspected ransomware — first 15 minutes)
1. Do NOT try to clean up. Contain first.
2. Isolate the device immediately and disconnect the user's sessions to file shares.
3. Raise a Critical incident and call the on-call IR lead — do not wait for the queue.
4. Preserve evidence (do not reboot, do not delete the note).

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

Active encryption plus backup deletion on a shared drive is a Critical incident. L1 contains and escalates straight away.

## 7. Model ticket notes
- **Short description:** Active ransomware on ENG-LT-091 — share affected — Critical escalation
- **Investigation:** Word spawned cmd → svc_upd.exe, which deleted shadow copies and the backup catalog, then renamed ~1,840 files to .lockd locally and on \\fs01\engineering. Ransom note dropped.
- **Actions:** Isolated ENG-LT-091. Disabled kmorgan's sessions and SMB access to fs01. Called IR on-call at 15:04. No reboot; evidence preserved.
- **Next step:** Escalated as Critical (P1) to IR; file-server team to check snapshots for restore.

## References
- [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)

[← Back to casebook](README.md)
