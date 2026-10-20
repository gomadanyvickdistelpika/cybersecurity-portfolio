# INC-2412 — SSH brute force on Linux server

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2412)

| Field | Value |
|---|---|
| Category | Network / Brute force |
| Priority | Medium |
| Detection source | Linux auth.log via Syslog |
| Affected entity | web-dmz-02 (public SFTP) |
| Opened | 2026-10-07 06:40 UTC |

**Summary:** Thousands of failed SSH logins from one IP against an internet-facing server. No successful login.

## 1. Evidence
### auth.log
```text
Oct  7 06:31:02 web-dmz-02 sshd[2211]: Failed password for invalid user admin from 203.0.113.9 port 40122 ssh2
Oct  7 06:31:03 web-dmz-02 sshd[2213]: Failed password for root from 203.0.113.9 port 40130 ssh2
Oct  7 06:31:03 web-dmz-02 sshd[2215]: Failed password for invalid user oracle from 203.0.113.9 port 40134 ssh2
...
Oct  7 06:39:58 web-dmz-02 sshd[9911]: Disconnected from invalid user test 203.0.113.9 port 61002 [preauth]
```

### Summary
```text
Failed attempts  : 4,812 (06:31–06:40)
Accepted logins  : 0 from 203.0.113.9
Accepted logins  : 3 today, all 'sftpsvc' with publickey from partner IP 198.51.100.5 (normal)
fail2ban         : 203.0.113.9 banned at 06:40:01 for 24h
sshd_config      : PasswordAuthentication no ; PermitRootLogin no
```

### Threat intel
```text
203.0.113.9 — reported 1,900+ times for SSH brute force in the last 30 days (public scanner/botnet)
```

## 2. Hunting query (KQL)
```kql
Syslog
| where TimeGenerated > ago(1d)
| where Computer == "web-dmz-02" and ProcessName == "sshd"
| extend Result = case(SyslogMessage has "Accepted", "Accepted",
                       SyslogMessage has "Failed password", "Failed", "Other")
| extend SrcIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize count() by SrcIP, Result
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| IP | `203.0.113[.]9` |  |

## 4. MITRE ATT&CK mapping
- [T1110.001](https://attack.mitre.org/techniques/T1110/001/) — Brute Force: Password Guessing *(Credential Access)*

## 5. L1 runbook (internal KB SOC-LNX-001 — SSH brute force on internet-facing hosts)
1. Count failures and check for any 'Accepted' line from the attacking IP.
2. Check hardening: password auth and root login disabled?
3. If zero successes and the IP is banned: block at the perimeter and close.
4. Escalate if any success, or new accounts/keys appear.

## 6. Decision
**Resolved at L1** · Classification: **True positive**

Real attack, but it failed: password auth is off, no success, IP banned. Internet noise handled by controls.

## 7. Model ticket notes
- **Short description:** SSH brute force — 0 successes — blocked
- **Investigation:** 4,812 failed attempts from 203.0.113.9 (known botnet). No Accepted lines from that IP. PasswordAuthentication and root login disabled. Only normal key-based logins from partner IP.
- **Actions:** Confirmed fail2ban ban; added IP to perimeter block list.
- **Next step:** Closed at L1.

## References
- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)

[← Back to casebook](README.md)
