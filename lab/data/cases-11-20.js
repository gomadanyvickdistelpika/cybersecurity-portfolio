/* SOC L1 Case Lab — cases 11 to 20. Fictional data; see cases-01-10.js header. */
window.CASES = window.CASES || [];
window.CASES.push(

/* ------------------------------------------------------------------ 11 */
{
  id: "INC-2411", title: "Internal port scan detected", category: "Network", subcategory: "Discovery",
  priority: "Medium", source: "Firewall / NDR", entity: "10.20.5.15 (VULN-SCAN-01)", opened: "2026-10-07 02:05 UTC",
  summary: "An internal host probed 1,000+ ports across the server subnet in 20 minutes.",
  evidence: [
    { tab: "Alert", body:
`Rule      : Horizontal + vertical port scan
Source    : 10.20.5.15
Targets   : 10.20.10.0/24  (254 hosts)
Ports     : 1–1024, 3389, 5985, 8080, 8443
Window    : 01:40–02:00 UTC` },
    { tab: "Firewall log", body:
`2026-10-07T01:40:02Z ALLOW TCP 10.20.5.15:51022 -> 10.20.10.4:22   SYN
2026-10-07T01:40:02Z ALLOW TCP 10.20.5.15:51023 -> 10.20.10.4:23   SYN
2026-10-07T01:40:02Z ALLOW TCP 10.20.5.15:51024 -> 10.20.10.4:25   SYN
... 58,210 similar lines` },
    { tab: "Asset / CMDB", body:
`Hostname : VULN-SCAN-01
Owner    : Security Engineering
Role     : Authorised vulnerability scanner (Nessus)` },
    { tab: "Change calendar", body:
`CHG-88412  "Monthly authenticated scan — server VLAN"
Window   : 2026-10-07 01:30–04:00 UTC   Status: Approved` }
  ],
  iocs: [],
  mitre: [{ id: "T1046", name: "Network Service Discovery", tactic: "Discovery" }],
  kql: `// Hosts touching many ports/targets (needs CommonSecurityLog from the firewall)
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where SourceIP == "10.20.5.15"
| summarize Targets = dcount(DestinationIP), Ports = dcount(DestinationPort)
    by SourceIP, bin(TimeGenerated, 10m)`,
  runbook: [
    "Identify the source host and its owner in the CMDB.",
    "Check for an approved change or scan window.",
    "If authorised and inside the window: false positive; suggest a suppression for the scanner.",
    "Escalate if the host is not a scanner, or the time is outside any approved window."
  ],
  kb: { id: "SOC-NET-003", title: "Internal scanning alerts" },
  refs: [{ label: "MITRE ATT&CK T1046", url: "https://attack.mitre.org/techniques/T1046/" }],
  checklist: [
    "Identified the source host in CMDB",
    "Found the approved change ticket",
    "Confirmed the time is within the window",
    "Requested a tuning/suppression rule"
  ],
  answer: "resolve", classification: "False positive",
  rationale: "The scanner is authorised and running inside an approved change window. Not malicious; tune the rule.",
  model: {
    short: "Port scan from authorised Nessus scanner — CHG-88412 — false positive",
    investigation: "10.20.5.15 = VULN-SCAN-01, owned by Security Engineering. Activity 01:40–02:00 is inside approved CHG-88412 (01:30–04:00).",
    actions: "Requested suppression for VULN-SCAN-01 during approved scan windows only.",
    next: "Closed at L1 as false positive."
  }
},

/* ------------------------------------------------------------------ 12 */
{
  id: "INC-2412", title: "SSH brute force on Linux server", category: "Network", subcategory: "Brute force",
  priority: "Medium", source: "Linux auth.log via Syslog", entity: "web-dmz-02 (public SFTP)", opened: "2026-10-07 06:40 UTC",
  summary: "Thousands of failed SSH logins from one IP against an internet-facing server. No successful login.",
  evidence: [
    { tab: "auth.log", body:
`Oct  7 06:31:02 web-dmz-02 sshd[2211]: Failed password for invalid user admin from 203.0.113.9 port 40122 ssh2
Oct  7 06:31:03 web-dmz-02 sshd[2213]: Failed password for root from 203.0.113.9 port 40130 ssh2
Oct  7 06:31:03 web-dmz-02 sshd[2215]: Failed password for invalid user oracle from 203.0.113.9 port 40134 ssh2
...
Oct  7 06:39:58 web-dmz-02 sshd[9911]: Disconnected from invalid user test 203.0.113.9 port 61002 [preauth]` },
    { tab: "Summary", body:
`Failed attempts  : 4,812 (06:31–06:40)
Accepted logins  : 0 from 203.0.113.9
Accepted logins  : 3 today, all 'sftpsvc' with publickey from partner IP 198.51.100.5 (normal)
fail2ban         : 203.0.113.9 banned at 06:40:01 for 24h
sshd_config      : PasswordAuthentication no ; PermitRootLogin no` },
    { tab: "Threat intel", body:
`203.0.113.9 — reported 1,900+ times for SSH brute force in the last 30 days (public scanner/botnet)` }
  ],
  iocs: [{ type: "IP", value: "203.0.113[.]9" }],
  mitre: [{ id: "T1110.001", name: "Brute Force: Password Guessing", tactic: "Credential Access" }],
  kql: `Syslog
| where TimeGenerated > ago(1d)
| where Computer == "web-dmz-02" and ProcessName == "sshd"
| extend Result = case(SyslogMessage has "Accepted", "Accepted",
                       SyslogMessage has "Failed password", "Failed", "Other")
| extend SrcIP = extract(@"from (\\d+\\.\\d+\\.\\d+\\.\\d+)", 1, SyslogMessage)
| summarize count() by SrcIP, Result`,
  runbook: [
    "Count failures and check for any 'Accepted' line from the attacking IP.",
    "Check hardening: password auth and root login disabled?",
    "If zero successes and the IP is banned: block at the perimeter and close.",
    "Escalate if any success, or new accounts/keys appear."
  ],
  kb: { id: "SOC-LNX-001", title: "SSH brute force on internet-facing hosts" },
  refs: [{ label: "MITRE ATT&CK T1110.001", url: "https://attack.mitre.org/techniques/T1110/001/" }],
  checklist: [
    "Confirmed zero accepted logins from the IP",
    "Checked sshd hardening settings",
    "Confirmed fail2ban ban",
    "Blocked IP at the perimeter firewall",
    "Checked threat intel reputation"
  ],
  answer: "resolve", classification: "True positive",
  rationale: "Real attack, but it failed: password auth is off, no success, IP banned. Internet noise handled by controls.",
  model: {
    short: "SSH brute force — 0 successes — blocked",
    investigation: "4,812 failed attempts from 203.0.113.9 (known botnet). No Accepted lines from that IP. PasswordAuthentication and root login disabled. Only normal key-based logins from partner IP.",
    actions: "Confirmed fail2ban ban; added IP to perimeter block list.",
    next: "Closed at L1."
  }
},

/* ------------------------------------------------------------------ 13 */
{
  id: "INC-2413", title: "DNS beaconing to random domains", category: "Network", subcategory: "Command and control",
  priority: "High", source: "DNS logs / Sentinel", entity: "LT-ACC-031 · Grace Nolan", opened: "2026-10-07 10:15 UTC",
  summary: "A laptop is querying hundreds of random-looking domains, and one resolves and is contacted every 60 seconds.",
  evidence: [
    { tab: "DNS log", body:
`10:01:00  LT-ACC-031  qwkzjxhp1v[.]example   NXDOMAIN
10:01:00  LT-ACC-031  bfh2ljv8tq[.]example   NXDOMAIN
10:01:01  LT-ACC-031  mz0rq7cdt3[.]example   NXDOMAIN
10:01:01  LT-ACC-031  xk3pa9wltz[.]example   A 198.51.100.66
... 412 NXDOMAIN in 15 min` },
    { tab: "Network", body:
`10:01:02  LT-ACC-031 -> 198.51.100.66:443  TLS  SNI: xk3pa9wltz.example   312 bytes out
10:02:02  LT-ACC-031 -> 198.51.100.66:443  312 bytes out
10:03:02  LT-ACC-031 -> 198.51.100.66:443  312 bytes out   (every 60s, same size)` },
    { tab: "Process", body:
`Initiating process: C:\\ProgramData\\Intel\\igfxsvc.exe   (unsigned, created 2026-10-06 17:44)
Real Intel driver path is C:\\Windows\\System32\\  — this path is not normal` }
  ],
  iocs: [
    { type: "Domain", value: "xk3pa9wltz[.]example" },
    { type: "IP", value: "198.51.100[.]66" },
    { type: "File", value: "C:\\ProgramData\\Intel\\igfxsvc[.]exe" }
  ],
  mitre: [
    { id: "T1568.002", name: "Dynamic Resolution: Domain Generation Algorithms", tactic: "Command and Control" },
    { id: "T1036.005", name: "Masquerading: Match Legitimate Name or Location", tactic: "Defense Evasion" },
    { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" }
  ],
  kql: `// Hosts with lots of NXDOMAIN answers (possible DGA)
DnsEvents
| where TimeGenerated > ago(1h)
| where ResultCode == 3   // NXDOMAIN
| summarize NX = count(), Sample = make_set(Name, 5) by ClientIP
| where NX > 100
| order by NX desc`,
  runbook: [
    "Look for many NXDOMAIN answers with random-looking names (DGA).",
    "Find the one that resolved and check for regular, same-size connections (beacon).",
    "Find the process behind it.",
    "Isolate and escalate — this is active command and control."
  ],
  kb: { id: "SOC-NET-006", title: "DGA and beaconing" },
  refs: [
    { label: "MITRE ATT&CK T1568.002", url: "https://attack.mitre.org/techniques/T1568/002/" },
    { label: "MITRE ATT&CK T1036.005", url: "https://attack.mitre.org/techniques/T1036/005/" }
  ],
  checklist: [
    "Spotted the high NXDOMAIN count",
    "Found the resolving C2 domain and IP",
    "Identified the 60-second beacon",
    "Found the masquerading process",
    "Isolated the device",
    "Escalated to L2"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "DGA lookups plus a steady 60-second beacon from an unsigned file pretending to be an Intel driver = malware with active C2.",
  model: {
    short: "DGA + 60s HTTPS beacon from fake Intel binary — escalated",
    investigation: "412 NXDOMAIN random domains in 15 min; xk3pa9wltz.example resolved to 198.51.100.66 and is contacted every 60 s with 312-byte packets. Process: unsigned igfxsvc.exe in ProgramData (masquerading), created 06 Oct 17:44.",
    actions: "Isolated LT-ACC-031. Blocked domain and IP. Collected file hash and investigation package.",
    next: "Escalated to L2: find initial infection on 06 Oct ~17:44, hunt for the hash on other devices."
  }
},

/* ------------------------------------------------------------------ 14 */
{
  id: "INC-2414", title: "Office macro launched PowerShell", category: "Endpoint", subcategory: "Malicious document",
  priority: "High", source: "Defender for Endpoint", entity: "LT-PRC-007 · Ciarán Hughes", opened: "2026-10-07 13:40 UTC",
  summary: "Excel opened an attachment and immediately started encoded PowerShell, which wrote a scheduled task.",
  evidence: [
    { tab: "Process tree", body:
`outlook.exe
 └─ excel.exe  "C:\\Users\\chughes\\AppData\\Local\\...\\PO_44871.xlsm"
     └─ powershell.exe -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...
         └─ schtasks.exe /create /sc minute /mo 30 /tn "OneDriveSyncCheck" /tr "C:\\Users\\Public\\odsync.exe"` },
    { tab: "Email", body:
`From    : purchasing@supplier-orders[.]example
Subject : PO 44871 — urgent revision
Attachment: PO_44871.xlsm  (macro-enabled)  — user clicked "Enable Content"` },
    { tab: "File events", body:
`13:38:10  FileCreated  C:\\Users\\Public\\odsync.exe   (SHA256 a1b2...ef90, unsigned)
13:38:12  ScheduledTaskCreated  OneDriveSyncCheck` }
  ],
  iocs: [
    { type: "Sender", value: "purchasing@supplier-orders[.]example" },
    { type: "File", value: "PO_44871.xlsm" },
    { type: "File", value: "C:\\Users\\Public\\odsync[.]exe" },
    { type: "Task", value: "OneDriveSyncCheck" }
  ],
  mitre: [
    { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "Initial Access" },
    { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution" },
    { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution" },
    { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence" }
  ],
  kql: `// Office apps spawning script interpreters
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
  runbook: [
    "Office app → script interpreter is almost never legitimate.",
    "Check for dropped files and persistence (scheduled tasks, run keys, services).",
    "Isolate, collect evidence, purge the email from all mailboxes.",
    "Escalate."
  ],
  kb: { id: "SOC-EDR-005", title: "Malicious Office document" },
  refs: [
    { label: "MITRE ATT&CK T1566.001", url: "https://attack.mitre.org/techniques/T1566/001/" },
    { label: "MITRE ATT&CK T1053.005", url: "https://attack.mitre.org/techniques/T1053/005/" }
  ],
  checklist: [
    "Identified Excel → PowerShell parent/child",
    "Found the dropped executable",
    "Found the scheduled task persistence",
    "Purged the email from all mailboxes",
    "Isolated the device",
    "Escalated to L2"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "Code ran and set up persistence. That is a compromised endpoint, not a blocked attempt.",
  model: {
    short: "Macro → PowerShell → persistence on LT-PRC-007 — escalated",
    investigation: "User enabled macros in PO_44871.xlsm. Excel spawned hidden encoded PowerShell, which dropped unsigned odsync.exe and created scheduled task 'OneDriveSyncCheck' every 30 minutes.",
    actions: "Isolated device, purged email from all mailboxes, blocked sender domain and file hash.",
    next: "Escalated to L2; recommend blocking macros from internet files via policy."
  }
},

/* ------------------------------------------------------------------ 15 */
{
  id: "INC-2415", title: "Departing employee mass download", category: "Insider", subcategory: "Data exfiltration",
  priority: "High", source: "Defender for Cloud Apps / Insider Risk", entity: "Paul Quinn · Sales (leaving Friday)", opened: "2026-10-08 16:10 UTC",
  summary: "A user who resigned downloaded 3,400 SharePoint files and uploaded a large archive to a personal cloud drive.",
  evidence: [
    { tab: "Alert", body:
`Policy : Mass download by a single user
User   : paul.quinn@harbourline.example
Files  : 3,412 from "Sales — Customer Accounts" (Confidential)
Window : 15:20–15:55 UTC` },
    { tab: "HR context", body:
`HR flag: resignation submitted 2026-09-30, last day 2026-10-09.
Joining a competitor (per HR, do not contact the user directly).` },
    { tab: "Endpoint / proxy", body:
`16:02  LT-SAL-019  7z.exe a C:\\Temp\\backup.7z  (2.1 GB)
16:05  chrome.exe upload -> personal-drive-cloud[.]example   2.1 GB   Allowed (category: Personal storage)` }
  ],
  iocs: [{ type: "Domain", value: "personal-drive-cloud[.]example" }],
  mitre: [
    { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" },
    { id: "T1560.001", name: "Archive Collected Data: Archive via Utility", tactic: "Collection" },
    { id: "T1567.002", name: "Exfiltration Over Web Service: Exfiltration to Cloud Storage", tactic: "Exfiltration" }
  ],
  kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where AccountDisplayName == "Paul Quinn"
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Files = count(), Sites = make_set(tostring(RawEventData.SiteUrl)) by bin(Timestamp, 15m)`,
  runbook: [
    "Confirm volume and sensitivity of the data.",
    "Check HR context (leaver / notice period).",
    "Do NOT contact the user. Preserve evidence.",
    "Escalate to L2 and the insider-risk / HR / legal process."
  ],
  kb: { id: "SOC-INS-001", title: "Insider data theft — leaver" },
  refs: [{ label: "MITRE ATT&CK T1567.002", url: "https://attack.mitre.org/techniques/T1567/002/" }],
  checklist: [
    "Confirmed volume and Confidential label",
    "Linked the 7-Zip archive to the upload",
    "Checked HR leaver status",
    "Did not contact the user",
    "Preserved evidence",
    "Escalated to L2 / Insider Risk"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "Confidential customer data was archived and uploaded to personal storage by a leaver joining a competitor. This needs HR/legal, not an L1 closure.",
  model: {
    short: "Leaver exfiltrated Confidential customer data to personal cloud — escalated",
    investigation: "3,412 Confidential files downloaded 15:20–15:55, archived to backup.7z (2.1 GB) at 16:02 and uploaded to personal-drive-cloud.example at 16:05. HR confirms resignation, last day 09 Oct, joining competitor.",
    actions: "Evidence preserved. No contact with user. Requested blocking personal storage category for this user via policy.",
    next: "Escalated to L2 and Insider Risk/HR/Legal per KB SOC-INS-001."
  }
},

/* ------------------------------------------------------------------ 16 */
{
  id: "INC-2416", title: "Adware browser extension quarantined", category: "Endpoint", subcategory: "Potentially unwanted app",
  priority: "Low", source: "Defender Antivirus", entity: "LT-RCP-002 · Front desk", opened: "2026-10-08 09:05 UTC",
  summary: "Antivirus detected and removed a coupon-style browser extension after a free PDF tool install.",
  evidence: [
    { tab: "Alert", body:
`Threat     : PUA:Win32/CouponAdware
Action     : Quarantined + Removed  (Remediation: Success)
Path       : C:\\Users\\reception\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\kpd...` },
    { tab: "Timeline", body:
`08:55  Downloaded FreePDFMerge_setup.exe from a search ad
08:57  Installer added Chrome extension "SmartCoupons"
09:04  Defender quarantined extension (PUA)
After 09:04: no suspicious processes, no new network destinations, full scan clean` }
  ],
  iocs: [{ type: "File", value: "FreePDFMerge_setup[.]exe" }],
  mitre: [{ id: "T1176", name: "Software Extensions (Browser Extensions)", tactic: "Persistence" }],
  kql: `DeviceEvents
| where DeviceName == "lt-rcp-002" and Timestamp > ago(1d)
| where ActionType has "Antivirus"
| project Timestamp, ActionType, FileName, FolderPath, AdditionalFields`,
  runbook: [
    "Confirm remediation succeeded and a full scan is clean.",
    "Check for anything after the detection (new processes/connections).",
    "Remove the bundled installer; remind the user to use the company software portal.",
    "Escalate only if remediation failed or other suspicious activity exists."
  ],
  kb: { id: "SOC-EDR-001", title: "Potentially unwanted applications" },
  refs: [{ label: "MITRE ATT&CK T1176", url: "https://attack.mitre.org/techniques/T1176/" }],
  checklist: [
    "Confirmed remediation success",
    "Confirmed full scan clean",
    "Checked activity after detection",
    "Removed the installer",
    "Advised the user on the software portal"
  ],
  answer: "resolve", classification: "True positive",
  rationale: "Low-risk PUA, fully removed, nothing after it. L1 closes with user advice.",
  model: {
    short: "Adware extension from bundled installer — removed — closed",
    investigation: "SmartCoupons extension installed by FreePDFMerge_setup.exe; quarantined and removed at 09:04. Full scan clean; no new processes or destinations afterwards.",
    actions: "Deleted installer; pointed user to the Company Portal for PDF tools.",
    next: "Closed at L1."
  }
},

/* ------------------------------------------------------------------ 17 */
{
  id: "INC-2417", title: "Expired TLS certificate on intranet", category: "Vulnerability", subcategory: "Certificate hygiene",
  priority: "Low", source: "Vulnerability scanner", entity: "intranet.harbourline.example (10.20.10.30)", opened: "2026-10-08 11:00 UTC",
  summary: "Scanner reports the intranet HTTPS certificate expired yesterday. Users see browser warnings.",
  evidence: [
    { tab: "Scanner", body:
`Plugin   : SSL Certificate Expiry
Host     : 10.20.10.30:443
Subject  : CN=intranet.harbourline.example
Issuer   : CN=Harbourline Internal Issuing CA 02
NotAfter : 2026-10-07 23:59:59 UTC   (EXPIRED)` },
    { tab: "openssl", body:
`$ openssl s_client -connect intranet.harbourline.example:443 -servername intranet.harbourline.example </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
subject=CN = intranet.harbourline.example
issuer=CN = Harbourline Internal Issuing CA 02
notBefore=Oct  7 00:00:00 2025 GMT
notAfter=Oct  7 23:59:59 2026 GMT
SHA256 Fingerprint=3A:9F:...:C1   (matches the cert issued by our CA in 2025 — not swapped)` },
    { tab: "Service desk", body:
`6 tickets today: "Your connection is not private" on intranet.
CMDB owner: Web Platform team. Renewal task was assigned to a leaver.` }
  ],
  iocs: [],
  mitre: [],
  kql: `// No KQL needed — this is configuration hygiene. Example check from scanner data:
// SecurityRecommendation / or your scanner's table
// | where Title has "certificate" and Status == "Expired"`,
  runbook: [
    "Confirm the certificate details with openssl.",
    "Check it is the expected certificate (fingerprint / issuer) — rule out interception.",
    "If it is our own cert simply expired: raise a P3 change to the owner team, tell users not to click through warnings.",
    "Escalate to security only if the certificate or issuer is unexpected."
  ],
  kb: { id: "SOC-VUL-004", title: "Certificate expiry findings" },
  refs: [
    { label: "NIST SP 1800-16 — TLS Server Certificate Management", url: "https://csrc.nist.gov/pubs/sp/1800/16/final" }
  ],
  checklist: [
    "Verified the expiry date with openssl",
    "Confirmed issuer and fingerprint are expected",
    "Raised a change/request to the owner team",
    "Told users not to bypass browser warnings",
    "Suggested certificate expiry monitoring"
  ],
  answer: "resolve", classification: "True positive",
  rationale: "Real finding, but operational: our own certificate expired and was not replaced by an attacker. Route to the owner team and close the security ticket.",
  model: {
    short: "Intranet TLS cert expired — own cert, not tampered — routed to Web Platform",
    investigation: "openssl confirms CN=intranet.harbourline.example, issuer Internal Issuing CA 02, notAfter 07 Oct 2026; fingerprint matches the cert issued in 2025, so no interception. Renewal owner had left the company.",
    actions: "Raised CHG request to Web Platform to renew and bind a new cert. Service desk message: do not click through certificate warnings. Suggested 30/14/7-day expiry alerts.",
    next: "Closed at L1 (handed to IT operations)."
  }
},

/* ------------------------------------------------------------------ 18 */
{
  id: "INC-2418", title: "User added to Domain Admins", category: "Identity", subcategory: "Privilege escalation",
  priority: "High", source: "Windows Security log (DC01)", entity: "svc_backup2 → Domain Admins", opened: "2026-10-08 23:47 UTC",
  summary: "A service account was added to Domain Admins at night, with no change ticket.",
  evidence: [
    { tab: "Event 4728", body:
`EventID   : 4728  A member was added to a security-enabled global group
Time      : 2026-10-08 23:41:07 UTC
Computer  : DC01.harbourline.local
Subject   : HARBOURLINE\\helpdesk.tmp   (Logon ID 0x3E7A1F)
Member    : CN=svc_backup2,OU=Service Accounts,DC=harbourline,DC=local
Group     : Domain Admins` },
    { tab: "Logons", body:
`23:38:55  4624  helpdesk.tmp  LogonType 10 (RDP)  from 10.20.30.77 (JUMP-02)
helpdesk.tmp was created 2026-10-08 22:10 — not in HR or the access request system` },
    { tab: "Change calendar", body:
`No approved change for Domain Admins membership this week.
Domain Admins owner: Infrastructure (only 3 named admins expected)` }
  ],
  iocs: [
    { type: "Account", value: "HARBOURLINE\\helpdesk.tmp" },
    { type: "Account", value: "svc_backup2" },
    { type: "Host", value: "JUMP-02 (10.20.30[.]77)" }
  ],
  mitre: [
    { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
    { id: "T1136.002", name: "Create Account: Domain Account", tactic: "Persistence" },
    { id: "T1078.002", name: "Valid Accounts: Domain Accounts", tactic: "Privilege Escalation" }
  ],
  kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)       // added to global / local / universal group
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Administrators")
| project TimeGenerated, Computer, SubjectAccount, MemberName, TargetUserName`,
  runbook: [
    "Check who made the change and whether a change ticket exists.",
    "Check the account that made the change — is it known and expected?",
    "No ticket and an unknown actor: treat as privilege escalation; escalate immediately (L1 does not edit AD).",
    "Preserve the events."
  ],
  kb: { id: "SOC-AD-002", title: "Privileged group changes" },
  refs: [
    { label: "Microsoft — Monitoring AD for signs of compromise", url: "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise" },
    { label: "MITRE ATT&CK T1098", url: "https://attack.mitre.org/techniques/T1098/" }
  ],
  checklist: [
    "Read event 4728 (who, what, when)",
    "Checked for an approved change",
    "Found the unknown account helpdesk.tmp",
    "Traced its RDP logon source (JUMP-02)",
    "Escalated to L2 as high priority"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "An unknown account created two hours earlier added a service account to Domain Admins at night with no change. Possible domain compromise.",
  model: {
    short: "Unauthorised Domain Admins addition by unknown account — escalated",
    investigation: "Event 4728 on DC01 at 23:41: helpdesk.tmp added svc_backup2 to Domain Admins. helpdesk.tmp was created at 22:10, not in HR/IAM, and logged on via RDP from JUMP-02. No change ticket.",
    actions: "Preserved event logs. Paged Infrastructure on-call. No AD changes made by L1.",
    next: "Escalated to L2/IR as P1 — possible domain compromise starting from JUMP-02."
  }
},

/* ------------------------------------------------------------------ 19 */
{
  id: "INC-2419", title: "LSASS memory access (credential dumping)", category: "Endpoint", subcategory: "Credential access",
  priority: "Critical", source: "Defender for Endpoint", entity: "SRV-FILE-03", opened: "2026-10-09 03:12 UTC",
  summary: "A renamed tool opened LSASS memory and wrote a dump file on a file server.",
  evidence: [
    { tab: "Alert", body:
`Alert   : Suspicious access to LSASS service memory
Process : C:\\Windows\\Temp\\pd64.exe  -accepteula -ma lsass.exe C:\\Windows\\Temp\\ls.dmp
Signer  : Sysinternals ProcDump (renamed)
User    : HARBOURLINE\\svc_backup2` },
    { tab: "File events", body:
`03:10:44  FileCreated  C:\\Windows\\Temp\\ls.dmp   (48 MB)
03:11:30  ls.dmp copied to \\\\10.20.30.77\\c$\\Users\\Public\\` },
    { tab: "Related", body:
`svc_backup2 was added to Domain Admins at 23:41 the previous night (INC-2418).` }
  ],
  iocs: [
    { type: "File", value: "C:\\Windows\\Temp\\pd64[.]exe" },
    { type: "File", value: "C:\\Windows\\Temp\\ls[.]dmp" },
    { type: "Host", value: "10.20.30[.]77 (JUMP-02)" }
  ],
  mitre: [
    { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access" },
    { id: "T1036.003", name: "Masquerading: Rename Legitimate Utilities", tactic: "Defense Evasion" },
    { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement" }
  ],
  kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("-ma", "MiniDump", "comsvcs")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
  runbook: [
    "Any LSASS dump outside an approved diagnostic task = credential theft.",
    "Link to related alerts on the same account/host.",
    "Isolate the server only if your runbook allows it for servers; otherwise call IR on-call immediately.",
    "Escalate as Critical."
  ],
  kb: { id: "SOC-EDR-008", title: "Credential dumping" },
  refs: [{ label: "MITRE ATT&CK T1003.001", url: "https://attack.mitre.org/techniques/T1003/001/" }],
  checklist: [
    "Recognised renamed ProcDump against LSASS",
    "Found the dump copied to JUMP-02",
    "Linked to INC-2418 (same account)",
    "Called IR on-call",
    "Escalated as Critical"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "Credential dumping by the same account that was just made Domain Admin — this is an active intrusion moving through the network.",
  model: {
    short: "LSASS dump by svc_backup2 on SRV-FILE-03 — linked to INC-2418 — Critical",
    investigation: "Renamed ProcDump (pd64.exe) dumped LSASS to ls.dmp (48 MB) and copied it to JUMP-02. Account svc_backup2 was added to Domain Admins 3.5 hours earlier.",
    actions: "Called IR on-call at 03:14. Linked incidents. Server isolation requested via IR (server runbook).",
    next: "Escalated as Critical (P1); all credentials on SRV-FILE-03 considered exposed."
  }
},

/* ------------------------------------------------------------------ 20 */
{
  id: "INC-2420", title: "Lost laptop reported", category: "Physical", subcategory: "Lost device",
  priority: "Medium", source: "Service desk", entity: "LT-MKT-011 · Zara Ahmed", opened: "2026-10-09 08:30 UTC",
  summary: "User left her laptop on a train. It is encrypted and managed.",
  evidence: [
    { tab: "Report", body:
`08:20  User reports laptop LT-MKT-011 left on the Dublin–Cork train at ~07:45.
Garda/lost property contacted by user.` },
    { tab: "Intune", body:
`Device       : LT-MKT-011   Windows 11   Compliant
BitLocker    : On (TPM + PIN)  Recovery key escrowed in Entra ID
Last check-in: 07:41 UTC
Remote wipe  : Available` },
    { tab: "Sign-ins", body:
`No sign-ins from LT-MKT-011 after 07:41.
User signed in from a loaner laptop at 08:25 (MFA passed).` }
  ],
  iocs: [],
  mitre: [],
  kql: `SigninLogs
| where TimeGenerated > ago(1d)
| where DeviceDetail.displayName == "LT-MKT-011"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType`,
  runbook: [
    "Check encryption and compliance status.",
    "Check for any sign-ins from the device after it was lost.",
    "Revoke the user's refresh tokens; send remote lock/wipe per policy.",
    "If encrypted and no activity, close. Escalate if unencrypted, sensitive data was stored locally, or the device is used after loss (possible GDPR breach review)."
  ],
  kb: { id: "SOC-PHY-001", title: "Lost or stolen device" },
  refs: [{ label: "Microsoft Intune — Remote wipe", url: "https://learn.microsoft.com/en-us/intune/intune-service/remote-actions/devices-wipe" }],
  checklist: [
    "Confirmed BitLocker with PIN",
    "Checked for sign-ins after the loss",
    "Revoked the user's sessions",
    "Sent remote wipe/lock",
    "Recorded the Garda/lost-property reference"
  ],
  answer: "resolve", classification: "True positive",
  rationale: "Device is encrypted with TPM + PIN, there is no activity after loss, and remote wipe is sent. Risk is low; L1 closes.",
  model: {
    short: "Lost encrypted laptop — sessions revoked, wipe sent — closed",
    investigation: "LT-MKT-011 compliant, BitLocker TPM+PIN, last check-in 07:41. No sign-ins from the device after the loss.",
    actions: "Revoked user refresh tokens, issued remote wipe, marked device lost in Intune, recorded lost-property reference.",
    next: "Closed at L1; reopen if the device checks in."
  }
}
);
