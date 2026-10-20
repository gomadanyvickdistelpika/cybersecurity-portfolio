# INC-2411 — Internal port scan detected

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2411)

| Field | Value |
|---|---|
| Category | Network / Discovery |
| Priority | Medium |
| Detection source | Firewall / NDR |
| Affected entity | 10.20.5.15 (VULN-SCAN-01) |
| Opened | 2026-10-07 02:05 UTC |

**Summary:** An internal host probed 1,000+ ports across the server subnet in 20 minutes.

## 1. Evidence
### Alert
```text
Rule      : Horizontal + vertical port scan
Source    : 10.20.5.15
Targets   : 10.20.10.0/24  (254 hosts)
Ports     : 1–1024, 3389, 5985, 8080, 8443
Window    : 01:40–02:00 UTC
```

### Firewall log
```text
2026-10-07T01:40:02Z ALLOW TCP 10.20.5.15:51022 -> 10.20.10.4:22   SYN
2026-10-07T01:40:02Z ALLOW TCP 10.20.5.15:51023 -> 10.20.10.4:23   SYN
2026-10-07T01:40:02Z ALLOW TCP 10.20.5.15:51024 -> 10.20.10.4:25   SYN
... 58,210 similar lines
```

### Asset / CMDB
```text
Hostname : VULN-SCAN-01
Owner    : Security Engineering
Role     : Authorised vulnerability scanner (Nessus)
```

### Change calendar
```text
CHG-88412  "Monthly authenticated scan — server VLAN"
Window   : 2026-10-07 01:30–04:00 UTC   Status: Approved
```

## 2. Hunting query (KQL)
```kql
// Hosts touching many ports/targets (needs CommonSecurityLog from the firewall)
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where SourceIP == "10.20.5.15"
| summarize Targets = dcount(DestinationIP), Ports = dcount(DestinationPort)
    by SourceIP, bin(TimeGenerated, 10m)
```

## 3. Indicators of compromise (defanged)
None — no external indicators.

## 4. MITRE ATT&CK mapping
- [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery *(Discovery)*

## 5. L1 runbook (internal KB SOC-NET-003 — Internal scanning alerts)
1. Identify the source host and its owner in the CMDB.
2. Check for an approved change or scan window.
3. If authorised and inside the window: false positive; suggest a suppression for the scanner.
4. Escalate if the host is not a scanner, or the time is outside any approved window.

## 6. Decision
**Resolved at L1** · Classification: **False positive**

The scanner is authorised and running inside an approved change window. Not malicious; tune the rule.

## 7. Model ticket notes
- **Short description:** Port scan from authorised Nessus scanner — CHG-88412 — false positive
- **Investigation:** 10.20.5.15 = VULN-SCAN-01, owned by Security Engineering. Activity 01:40–02:00 is inside approved CHG-88412 (01:30–04:00).
- **Actions:** Requested suppression for VULN-SCAN-01 during approved scan windows only.
- **Next step:** Closed at L1 as false positive.

## References
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)

[← Back to casebook](README.md)
