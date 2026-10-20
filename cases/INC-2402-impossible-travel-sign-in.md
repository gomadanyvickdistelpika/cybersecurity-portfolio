# INC-2402 — Impossible travel sign-in

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2402)

| Field | Value |
|---|---|
| Category | Identity / Risky sign-in |
| Priority | Medium |
| Detection source | Microsoft Entra ID Protection |
| Affected entity | Liam Byrne · Sales |
| Opened | 2026-10-05 10:02 UTC |

**Summary:** Atypical travel risk: sign-ins from Dublin and Frankfurt 40 minutes apart. Both passed MFA.

## 1. Evidence
### Alert
```text
RiskEventType : unlikelyTravel
RiskLevel     : medium
User          : liam.byrne@harbourline.example
Sign-in A     : 2026-10-05T09:11Z  Dublin, IE     192.0.2.10     Outlook desktop
Sign-in B     : 2026-10-05T09:51Z  Frankfurt, DE  203.0.113.80   Teams desktop
```

### Sign-in logs
```text
Time       IP             Location   App      MFA      Device         Compliant
09:11:03   192.0.2.10     Dublin     Outlook  Passed   LT-SALES-022   Yes
09:51:40   203.0.113.80   Frankfurt  Teams    Passed   LT-SALES-022   Yes
09:52:10   203.0.113.80   Frankfurt  SharePoint Passed LT-SALES-022   Yes
```

### IP lookup
```text
203.0.113.80  -> ASN 64500 "Harbourline Corporate VPN — FRA-01 egress"
Listed in Named Locations: "Corporate VPN egress" (trusted)
```

### User interview
```text
Liam is in the Dublin office. He connected to the corporate VPN at ~09:50
because the CRM only works over VPN. He did not share his password.
```

## 2. Hunting query (KQL)
```kql
// Compare devices and IPs for the user over 7 days
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "liam.byrne@harbourline.example"
| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by IPAddress, Location = tostring(LocationDetails.city),
       DeviceId = tostring(DeviceDetail.deviceId), AppDisplayName
| order by LastSeen desc
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| IP | `203.0.113[.]80` | Corporate VPN egress — benign |

## 4. MITRE ATT&CK mapping
- [T1078.004](https://attack.mitre.org/techniques/T1078/004/) — Valid Accounts: Cloud Accounts *(Initial Access)*

## 5. L1 runbook (internal KB SOC-ID-004 — Atypical travel / impossible travel triage)
1. Compare both sign-ins: same device? MFA passed? Compliant device?
2. Look up the 'far away' IP — is it a known VPN, proxy or cloud egress?
3. Confirm with the user if needed.
4. If explained by corporate VPN on the same managed device, mark as benign and dismiss the risk.
5. Escalate if the device is unknown, MFA was skipped, or the IP is unfamiliar.

## 6. Decision
**Resolved at L1** · Classification: **Benign true positive**

The detection worked as designed, but the 'travel' is the corporate VPN on the same compliant laptop with MFA. Nothing to escalate.

## 7. Model ticket notes
- **Short description:** Impossible travel — corporate VPN egress — benign
- **Investigation:** Both sign-ins from device LT-SALES-022 (compliant) with MFA passed. 203.0.113.80 is the Harbourline VPN Frankfurt egress and is a trusted named location. User confirms VPN use at 09:50.
- **Actions:** Dismissed user risk in Entra ID Protection with comment. Suggested to the identity team that the VPN egress be excluded from travel detections.
- **Next step:** Closed at L1 as benign true positive.

## References
- [Microsoft Entra — Investigate risk](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)

[← Back to casebook](README.md)
