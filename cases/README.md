# Casebook — 20 SOC L1 incident write-ups

Each write-up follows the same structure an L1 analyst would put in a ticket: evidence → hunting query → indicators → ATT&CK mapping → decision → model ticket notes. All data is fictional.

| # | Case | Category | Priority | Decision | ATT&CK |
|---|---|---|---|---|---|
| 1 | [INC-2401 — Reported phishing email](INC-2401-reported-phishing-email.md) | Email / Phishing | Medium | Resolve at L1 | T1566.002 |
| 2 | [INC-2402 — Impossible travel sign-in](INC-2402-impossible-travel-sign-in.md) | Identity / Risky sign-in | Medium | Resolve at L1 | T1078.004 |
| 3 | [INC-2403 — Malware blocked, then PowerShell beacon](INC-2403-malware-blocked-then-powershell-beacon.md) | Endpoint / Malware | High | Escalate | T1204.002, T1059.001, T1027, T1071.001 |
| 4 | [INC-2404 — Password spray with one success](INC-2404-password-spray-with-one-success.md) | Identity / Password spray | High | Escalate | T1110.003, T1078.004 |
| 5 | [INC-2405 — USB write blocked by policy](INC-2405-usb-write-blocked-by-policy.md) | DLP / Removable media | Low | Resolve at L1 | T1052.001 |
| 6 | [INC-2406 — Ransomware behaviour on laptop](INC-2406-ransomware-behaviour-on-laptop.md) | Endpoint / Ransomware | Critical | Escalate | T1486, T1490, T1204.002 |
| 7 | [INC-2407 — MFA fatigue — user approved prompt](INC-2407-mfa-fatigue-user-approved-prompt.md) | Identity / MFA fatigue | High | Escalate | T1621, T1098.005, T1564.008 |
| 8 | [INC-2408 — External mail forwarding rule](INC-2408-external-mail-forwarding-rule.md) | Email / Business email compromise | High | Escalate | T1114.003, T1564.008, T1550.004 |
| 9 | [INC-2409 — Suspicious OAuth app consent](INC-2409-suspicious-oauth-app-consent.md) | Identity / Illicit consent | High | Escalate | T1528, T1566.002 |
| 10 | [INC-2410 — Tor sign-in attempt blocked](INC-2410-tor-sign-in-attempt-blocked.md) | Identity / Anonymous IP | Low | Resolve at L1 | T1090.003 |
| 11 | [INC-2411 — Internal port scan detected](INC-2411-internal-port-scan-detected.md) | Network / Discovery | Medium | Resolve at L1 | T1046 |
| 12 | [INC-2412 — SSH brute force on Linux server](INC-2412-ssh-brute-force-on-linux-server.md) | Network / Brute force | Medium | Resolve at L1 | T1110.001 |
| 13 | [INC-2413 — DNS beaconing to random domains](INC-2413-dns-beaconing-to-random-domains.md) | Network / Command and control | High | Escalate | T1568.002, T1036.005, T1071.001 |
| 14 | [INC-2414 — Office macro launched PowerShell](INC-2414-office-macro-launched-powershell.md) | Endpoint / Malicious document | High | Escalate | T1566.001, T1204.002, T1059.001, T1053.005 |
| 15 | [INC-2415 — Departing employee mass download](INC-2415-departing-employee-mass-download.md) | Insider / Data exfiltration | High | Escalate | T1530, T1560.001, T1567.002 |
| 16 | [INC-2416 — Adware browser extension quarantined](INC-2416-adware-browser-extension-quarantined.md) | Endpoint / Potentially unwanted app | Low | Resolve at L1 | T1176 |
| 17 | [INC-2417 — Expired TLS certificate on intranet](INC-2417-expired-tls-certificate-on-intranet.md) | Vulnerability / Certificate hygiene | Low | Resolve at L1 | — |
| 18 | [INC-2418 — User added to Domain Admins](INC-2418-user-added-to-domain-admins.md) | Identity / Privilege escalation | High | Escalate | T1098, T1136.002, T1078.002 |
| 19 | [INC-2419 — LSASS memory access (credential dumping)](INC-2419-lsass-memory-access-credential-dumping.md) | Endpoint / Credential access | Critical | Escalate | T1003.001, T1036.003, T1570 |
| 20 | [INC-2420 — Lost laptop reported](INC-2420-lost-laptop-reported.md) | Physical / Lost device | Medium | Resolve at L1 | — |

**Balance:** 9 resolve at L1 · 11 escalate — because a good L1 analyst must know when *not* to escalate as well as when to.
