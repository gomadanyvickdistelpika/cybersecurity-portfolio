# Cybersecurity Portfolio — Goma Dany Vick Distel Pika

Technical support engineer with 10+ years in enterprise IT (VMware/Broadcom, DXC/HPE), moving into **Tier-1 SOC and incident response**. Based in Dublin, Ireland. Google Cybersecurity Certificate in progress.

**Live site:** https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/
**Interactive lab:** https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/

## Professional statement

> I am a technical support engineer with over ten years of enterprise IT experience, moving into cybersecurity because I enjoy following the evidence in logs to find out what really happened, and then stopping it from happening again. My strengths are careful log analysis, clear written incident notes and automating repetitive work with Python and PowerShell, and I value protecting people and organisations, keeping honest records, and explaining security in plain language — in both English and French — so that every user can stay safe. I want to use these strengths to help security teams detect, triage and escalate threats quickly, and to keep their systems and data confidential, intact and available.

Outline notes: [professional-statement.md](professional-statement.md)

## Google Cybersecurity Professional Certificate — in progress

- Provider: Google Career Certificates on Coursera ([certificate overview](https://www.coursera.org/professional-certificates/google-cybersecurity), 9 courses)
- Current course: [Course 1 — Foundations of Cybersecurity](https://www.coursera.org/learn/foundations-of-cybersecurity)
- Portfolio activities done: professional statement. More (security audit, incident report, Linux/SQL/Python labs) will be added here as I complete them.

## Project: SOC L1 Case Lab

A browser-based triage queue with **20 fictional incidents**. For each case you:

1. Review the raw evidence (alerts, sign-in logs, process trees, DNS, firewall, auth.log, Windows events).
2. Run through the **KQL hunting query** (Microsoft Sentinel / Defender XDR).
3. Check the **defanged IOCs** and **MITRE ATT&CK** mapping.
4. Follow the L1 runbook, tick the checks you made, choose **Resolve at L1** or **Escalate**, pick a classification and write work notes.
5. Get a score out of 100, compare with the **model ticket**, and download your ticket as Markdown.

| # | Case | Decision |
|---|---|---|
| 01 | Reported phishing email (no click) | Resolve |
| 02 | Impossible travel — corporate VPN | Resolve |
| 03 | Malware blocked, then PowerShell beacon | Escalate |
| 04 | Password spray with one success | Escalate |
| 05 | USB write blocked by policy | Resolve |
| 06 | Ransomware behaviour on laptop | Escalate |
| 07 | MFA fatigue — user approved prompt | Escalate |
| 08 | External mail forwarding rule (BEC) | Escalate |
| 09 | Suspicious OAuth app consent | Escalate |
| 10 | Tor sign-in attempt blocked | Resolve |
| 11 | Internal port scan (authorised scanner) | Resolve |
| 12 | SSH brute force on Linux server | Resolve |
| 13 | DNS beaconing to random (DGA) domains | Escalate |
| 14 | Office macro launched PowerShell | Escalate |
| 15 | Departing employee mass download | Escalate |
| 16 | Adware browser extension quarantined | Resolve |
| 17 | Expired TLS certificate on intranet | Resolve |
| 18 | User added to Domain Admins | Escalate |
| 19 | LSASS memory access (credential dumping) | Escalate |
| 20 | Lost laptop reported (encrypted) | Resolve |

Full write-ups: [cases/](cases/README.md)

### What this shows

- Triage judgement: 9 cases close at L1, 11 escalate — knowing when **not** to escalate matters as much as knowing when to.
- Evidence-led notes in a consistent ticket format (summary → investigation → actions → next step).
- KQL across `EmailEvents`, `UrlClickEvents`, `SigninLogs`, `AuditLogs`, `OfficeActivity`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DnsEvents`, `SecurityEvent`, `Syslog`, `CloudAppEvents`.
- 33 MITRE ATT&CK techniques across Initial Access, Execution, Persistence, Credential Access, Discovery, C2, Exfiltration and Impact.

### Run it locally

No build step. Clone the repo and open `lab/index.html` in a browser, or serve the folder:

```bash
python -m http.server 8000
# then open http://localhost:8000/lab/
```

Progress is saved only in your own browser (localStorage).

## Repository layout

```
index.html                 Portfolio landing page (GitHub Pages)
professional-statement.md  Statement + outline notes (Google Cybersecurity Certificate)
lab/                       Interactive SOC L1 Case Lab
  data/cases-01-10.js      Case data
  data/cases-11-20.js
cases/                     20 Markdown incident write-ups
```

## Safety note

All people, companies, hosts and indicators are **fictional**. Domains use the reserved `.example` TLD and IPs use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Indicators are defanged (`hxxp`, `[.]`). Internal KB numbers are invented; external links point to public Microsoft, MITRE, CISA and NIST guidance.

## Contact

- LinkedIn: https://www.linkedin.com/in/dany-goma-vyck-distel-pika-8b905b17/
- Email: therealdan2015@gmail.com

## Licence

MIT — see [LICENSE](LICENSE).
