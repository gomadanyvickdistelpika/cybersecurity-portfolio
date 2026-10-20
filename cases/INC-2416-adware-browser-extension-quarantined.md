# INC-2416 — Adware browser extension quarantined

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2416)

| Field | Value |
|---|---|
| Category | Endpoint / Potentially unwanted app |
| Priority | Low |
| Detection source | Defender Antivirus |
| Affected entity | LT-RCP-002 · Front desk |
| Opened | 2026-10-08 09:05 UTC |

**Summary:** Antivirus detected and removed a coupon-style browser extension after a free PDF tool install.

## 1. Evidence
### Alert
```text
Threat     : PUA:Win32/CouponAdware
Action     : Quarantined + Removed  (Remediation: Success)
Path       : C:\Users\reception\AppData\Local\Google\Chrome\User Data\Default\Extensions\kpd...
```

### Timeline
```text
08:55  Downloaded FreePDFMerge_setup.exe from a search ad
08:57  Installer added Chrome extension "SmartCoupons"
09:04  Defender quarantined extension (PUA)
After 09:04: no suspicious processes, no new network destinations, full scan clean
```

## 2. Hunting query (KQL)
```kql
DeviceEvents
| where DeviceName == "lt-rcp-002" and Timestamp > ago(1d)
| where ActionType has "Antivirus"
| project Timestamp, ActionType, FileName, FolderPath, AdditionalFields
```

## 3. Indicators of compromise (defanged)
| Type | Value | Note |
|---|---|---|
| File | `FreePDFMerge_setup[.]exe` |  |

## 4. MITRE ATT&CK mapping
- [T1176](https://attack.mitre.org/techniques/T1176/) — Software Extensions (Browser Extensions) *(Persistence)*

## 5. L1 runbook (internal KB SOC-EDR-001 — Potentially unwanted applications)
1. Confirm remediation succeeded and a full scan is clean.
2. Check for anything after the detection (new processes/connections).
3. Remove the bundled installer; remind the user to use the company software portal.
4. Escalate only if remediation failed or other suspicious activity exists.

## 6. Decision
**Resolved at L1** · Classification: **True positive**

Low-risk PUA, fully removed, nothing after it. L1 closes with user advice.

## 7. Model ticket notes
- **Short description:** Adware extension from bundled installer — removed — closed
- **Investigation:** SmartCoupons extension installed by FreePDFMerge_setup.exe; quarantined and removed at 09:04. Full scan clean; no new processes or destinations afterwards.
- **Actions:** Deleted installer; pointed user to the Company Portal for PDF tools.
- **Next step:** Closed at L1.

## References
- [MITRE ATT&CK T1176](https://attack.mitre.org/techniques/T1176/)

[← Back to casebook](README.md)
