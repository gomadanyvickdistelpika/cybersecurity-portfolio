# INC-2413 — DNS beaconing to random domains

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2413)

| Field | Value |
|---|---|
| Category | Network / Command and control |
| Priority | High |
| Detection source | DNS logs / Sentinel |
| Affected entity | LT-ACC-031 · Grace Nolan |
| Opened | 2026-10-07 10:15 UTC |

**Summary:** A laptop is querying hundreds of random-looking domains, and one resolves and is contacted every 60 seconds.

## 1. Evidence
### DNS log
```text
10:01:00  LT-ACC-031  qwkzjxhp1v[.]example   NXDOMAIN
10:01:00  LT-ACC-031  bfh2ljv8tq[.]example   NXDOMAIN
10:01:01  LT-ACC-031  mz0rq7cdt3[.]example   NXDOMAIN
10:01:01  LT-ACC-031  xk3pa9wltz[.]example   A 198.51.100.66
... 412 NXDOMAIN in 15 min
```

### Network
```text
10:01:02  LT-ACC-031 -> 198.51.100.66:443  TLS  SNI: xk3pa9wltz.example   312 bytes out
10:02:02  LT-ACC-031 -> 198.51.100.66:443  312 bytes out
10:03:02  LT-ACC-031 -> 198.51.100.66:443  312 bytes out   (every 60s, same size)
```

### Process
```text
Initiating process: C:\ProgramData\Intel\igfxsvc.exe   (unsigned, created 2026-10-06 17:44)
Real Intel driver path is C:\Windows\System32\  — this path is not normal
```

## 2. Hunting query (KQL)
```kql
// Hosts with lots of NXDOMAIN answers (possible DGA)
DnsEvents
| where TimeGenerated > ago(1h)
| where ResultCode == 3   // NXDOMAIN
| summarize NX = count(), Sample = make_set(Name, 5) by ClientIP
| where NX > 100
| order by NX desc
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| Domain | `xk3pa9wltz[.]example` |  |
| IP | `198.51.100[.]66` |  |
| File | `C:\ProgramData\Intel\igfxsvc[.]exe` |  |

## 4. MITRE ATT&CK mapping
- [T1568.002](https://attack.mitre.org/techniques/T1568/002/) — Dynamic Resolution: Domain Generation Algorithms *(Command and Control)*
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/) — Masquerading: Match Legitimate Name or Location *(Defense Evasion)*
- [T1071.001](https://attack.mitre.org/techniques/T1071/001/) — Application Layer Protocol: Web Protocols *(Command and Control)*

## 5. L1 runbook (internal KB SOC-NET-006 — DGA and beaconing)
1. Look for many NXDOMAIN answers with random-looking names (DGA).
2. Find the one that resolved and check for regular, same-size connections (beacon).
3. Find the process behind it.
4. Isolate and escalate — this is active command and control.

## 6. Decision
**Escalated to L2 / IR** · Classification: **True positive**

DGA lookups plus a steady 60-second beacon from an unsigned file pretending to be an Intel driver = malware with active C2.

## 7. Model ticket notes
- **Short description:** DGA + 60s HTTPS beacon from fake Intel binary — escalated
- **Investigation:** 412 NXDOMAIN random domains in 15 min; xk3pa9wltz.example resolved to 198.51.100.66 and is contacted every 60 s with 312-byte packets. Process: unsigned igfxsvc.exe in ProgramData (masquerading), created 06 Oct 17:44.
- **Actions:** Isolated LT-ACC-031. Blocked domain and IP. Collected file hash and investigation package.
- **Next step:** Escalated to L2: find initial infection on 06 Oct ~17:44, hunt for the hash on other devices.

## References
- [MITRE ATT&CK T1568.002](https://attack.mitre.org/techniques/T1568/002/)
- [MITRE ATT&CK T1036.005](https://attack.mitre.org/techniques/T1036/005/)

[← Back to casebook](README.md)
