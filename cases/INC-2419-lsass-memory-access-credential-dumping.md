# INC-2419 — LSASS memory access (credential dumping)

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2419)

| Field | Value |
|---|---|
| Category | Endpoint / Credential access |
| Priority | Critical |
| Detection source | Defender for Endpoint |
| Affected entity | SRV-FILE-03 |
| Opened | 2026-10-09 03:12 UTC |

**Summary:** A renamed tool opened LSASS memory and wrote a dump file on a file server.

## 1. Evidence
### Alert
```text
Alert   : Suspicious access to LSASS service memory
Process : C:\Windows\Temp\pd64.exe  -accepteula -ma lsass.exe C:\Windows\Temp\ls.dmp
Signer  : Sysinternals ProcDump (renamed)
User    : HARBOURLINE\svc_backup2
```

### File events
```text
03:10:44  FileCreated  C:\Windows\Temp\ls.dmp   (48 MB)
03:11:30  ls.dmp copied to \\10.20.30.77\c$\Users\Public\
```

### Related
```text
svc_backup2 was added to Domain Admins at 23:41 the previous night (INC-2418).
```

## 2. Hunting query (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("-ma", "MiniDump", "comsvcs")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| File | `C:\Windows\Temp\pd64[.]exe` |  |
| File | `C:\Windows\Temp\ls[.]dmp` |  |
| Host | `10.20.30[.]77 (JUMP-02)` |  |

## 4. MITRE ATT&CK mapping
- [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — OS Credential Dumping: LSASS Memory *(Credential Access)*
- [T1036.003](https://attack.mitre.org/techniques/T1036/003/) — Masquerading: Rename Legitimate Utilities *(Defense Evasion)*
- [T1570](https://attack.mitre.org/techniques/T1570/) — Lateral Tool Transfer *(Lateral Movement)*

## 5. L1 runbook (internal KB SOC-EDR-008 — Credential dumping)
1. Any LSASS dump outside an approved diagnostic task = credential theft.
2. Link to related alerts on the same account/host.
3. Isolate the server only if your runbook allows it for servers; otherwise call IR on-call immediately.
4. Escalate as Critical.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

Credential dumping by the same account that was just made Domain Admin — this is an active intrusion moving through the network.

## 7. Model ticket notes
- **Short description:** LSASS dump by svc_backup2 on SRV-FILE-03 — linked to INC-2418 — Critical
- **Investigation:** Renamed ProcDump (pd64.exe) dumped LSASS to ls.dmp (48 MB) and copied it to JUMP-02. Account svc_backup2 was added to Domain Admins 3.5 hours earlier.
- **Actions:** Called IR on-call at 03:14. Linked incidents. Server isolation requested via IR (server runbook).
- **Next step:** Escalated as Critical (P1); all credentials on SRV-FILE-03 considered exposed.

## References
- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)

[← Back to casebook](README.md)
