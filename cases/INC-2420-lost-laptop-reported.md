# INC-2420 — Lost laptop reported

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2420)

| Field | Value |
|---|---|
| Category | Physical / Lost device |
| Priority | Medium |
| Detection source | Service desk |
| Affected entity | LT-MKT-011 · Zara Ahmed |
| Opened | 2026-10-09 08:30 UTC |

**Summary:** User left her laptop on a train. It is encrypted and managed.

## 1. Evidence
### Report
```text
08:20  User reports laptop LT-MKT-011 left on the Dublin–Cork train at ~07:45.
Garda/lost property contacted by user.
```

### Intune
```text
Device       : LT-MKT-011   Windows 11   Compliant
BitLocker    : On (TPM + PIN)  Recovery key escrowed in Entra ID
Last check-in: 07:41 UTC
Remote wipe  : Available
```

### Sign-ins
```text
No sign-ins from LT-MKT-011 after 07:41.
User signed in from a loaner laptop at 08:25 (MFA passed).
```

## 2. Hunting query (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where DeviceDetail.displayName == "LT-MKT-011"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType
```

## 3. Indicators of compromise (defanged)
None — no external indicators.

## 4. MITRE ATT&CK mapping
Not an attack technique — operational / hygiene finding.

## 5. L1 runbook (internal KB SOC-PHY-001 — Lost or stolen device)
1. Check encryption and compliance status.
2. Check for any sign-ins from the device after it was lost.
3. Revoke the user's refresh tokens; send remote lock/wipe per policy.
4. If encrypted and no activity, close. Escalate if unencrypted, sensitive data was stored locally, or the device is used after loss (possible GDPR breach review).

## 6. Decision
**Resolved at L1** · Classification: **True positive**

Device is encrypted with TPM + PIN, there is no activity after loss, and remote wipe is sent. Risk is low; L1 closes.

## 7. Model ticket notes
- **Short description:** Lost encrypted laptop — sessions revoked, wipe sent — closed
- **Investigation:** LT-MKT-011 compliant, BitLocker TPM+PIN, last check-in 07:41. No sign-ins from the device after the loss.
- **Actions:** Revoked user refresh tokens, issued remote wipe, marked device lost in Intune, recorded lost-property reference.
- **Next step:** Closed at L1; reopen if the device checks in.

## References
- [Microsoft Intune — Remote wipe](https://learn.microsoft.com/en-us/intune/intune-service/remote-actions/devices-wipe)

[← Back to casebook](README.md)
