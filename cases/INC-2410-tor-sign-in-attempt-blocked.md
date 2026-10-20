# INC-2410 — Tor sign-in attempt blocked

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2410)

| Field | Value |
|---|---|
| Category | Identity / Anonymous IP |
| Priority | Low |
| Detection source | Microsoft Entra ID Protection |
| Affected entity | Sean Doyle · Warehouse |
| Opened | 2026-10-06 13:20 UTC |

**Summary:** Sign-in attempt from a Tor exit node. Conditional Access blocked it; the password was wrong anyway.

## 1. Evidence
### Alert
```text
RiskEventType : anonymizedIPAddress
RiskLevel     : low
User          : sean.doyle@harbourline.example
IP            : 192.0.2.250 (Tor exit node)
```

### Sign-in logs
```text
13:18:44  192.0.2.250  Result: 50126 (invalid password)  Conditional Access: Failure — "Block anonymous IPs"
No other attempts from Tor in 30 days.
Last successful sign-in: 2026-10-06 07:02 from warehouse kiosk 192.0.2.40 (MFA passed)
```

### Password check
```text
Entra leaked-credentials check: no match
Password last changed: 2026-09-01
```

## 2. Hunting query (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "sean.doyle@harbourline.example"
| where RiskEventTypes_V2 has "anonymizedIPAddress" or IPAddress == "192.0.2.250"
| project TimeGenerated, IPAddress, ResultType, ConditionalAccessStatus
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| IP | `192.0.2[.]250` | Tor exit |

## 4. MITRE ATT&CK mapping
- [T1090.003](https://attack.mitre.org/techniques/T1090/003/) — Proxy: Multi-hop Proxy *(Command and Control)*

## 5. L1 runbook (internal KB SOC-ID-002 — Anonymous IP sign-ins)
1. Check the result: did the sign-in succeed?
2. Check Conditional Access outcome and whether the password was correct.
3. If blocked, wrong password, single attempt: close, optionally advise the user.
4. Escalate if it succeeded, the password was correct, or attempts repeat.

## 6. Decision
**Resolved at L1** · Classification: **True positive**

One failed, blocked attempt with a wrong password. Controls worked; no compromise.

## 7. Model ticket notes
- **Short description:** Tor sign-in attempt — blocked, wrong password — closed
- **Investigation:** Single attempt from Tor exit 192.0.2.250, error 50126 and CA 'Block anonymous IPs' failure. No other Tor attempts in 30 days; no leaked-credential match.
- **Actions:** Blocked IP in named locations (already blocked by CA). Sent user a short awareness note.
- **Next step:** Closed at L1.

## References
- [MITRE ATT&CK T1090.003](https://attack.mitre.org/techniques/T1090/003/)

[← Back to casebook](README.md)
