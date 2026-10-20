# INC-2405 — USB write blocked by policy

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2405)

| Field | Value |
|---|---|
| Category | DLP / Removable media |
| Priority | Low |
| Detection source | Endpoint DLP |
| Affected entity | Nora Patel · Design |
| Opened | 2026-10-05 14:38 UTC |

**Summary:** Endpoint control blocked a copy to an unapproved USB stick. No data left the device.

## 1. Evidence
### Alert
```text
Policy        : Block write to unapproved removable storage
Action        : Blocked
Device        : LT-DES-014
File          : Brand_Guidelines_v4.pdf  (Classification: Internal)
USB           : SanDisk Ultra  VID_0781 PID_5581  Serial 4C53...  (not on approved list)
```

### Device events
```text
14:37:55  UsbDriveMounted        E:\
14:38:02  RemovableStorageFileEvent  Write  Blocked  Brand_Guidelines_v4.pdf
14:38:10  No further write attempts
```

### User interview
```text
Nora wanted to bring the brand guide to a printer shop. She did not know USB was blocked.
Manager confirms the file is Internal (not Confidential) and the request was legitimate.
```

## 2. Hunting query (KQL)
```kql
DeviceEvents
| where DeviceName == "lt-des-014" and Timestamp > ago(1d)
| where ActionType in ("UsbDriveMounted", "RemovableStoragePolicyTriggered", "RemovableStorageFileEvent")
| project Timestamp, ActionType, AdditionalFields
```

## 3. Indicators of compromise (defanged)
None — no external indicators.

## 4. MITRE ATT&CK mapping
- [T1052.001](https://attack.mitre.org/techniques/T1052/001/) — Exfiltration Over Physical Medium: USB *(Exfiltration)*

## 5. L1 runbook (internal KB SOC-DLP-001 — Removable media policy events)
1. Confirm the action was Blocked and no file was written.
2. Check file classification and any repeat attempts.
3. Speak to the user/manager to confirm the business reason.
4. If blocked, low sensitivity and explained: educate the user, point to the approved sharing method, close.
5. Escalate if data was copied, files are Confidential, or there are repeated attempts.

## 6. Decision
**Resolved at L1** · Classification: **Benign true positive**

The control worked, nothing was copied, the file is Internal and the reason is legitimate. User education is enough.

## 7. Model ticket notes
- **Short description:** USB write blocked — Internal file — user educated
- **Investigation:** Single write attempt of Brand_Guidelines_v4.pdf (Internal) to an unapproved SanDisk USB; action Blocked, no further attempts. Manager confirms legitimate reason.
- **Actions:** Explained policy to user; shared the approved method (OneDrive share link with expiry).
- **Next step:** Closed at L1.

## References
- [MITRE ATT&CK T1052.001](https://attack.mitre.org/techniques/T1052/001/)

[← Back to casebook](README.md)
