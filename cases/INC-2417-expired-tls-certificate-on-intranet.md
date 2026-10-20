# INC-2417 — Expired TLS certificate on intranet

> Fictional training case · [Open it in the interactive lab](https://gomadanyvickdistelpika.github.io/cybersecurity-portfolio/lab/#INC-2417)

| Field | Value |
|---|---|
| Category | Vulnerability / Certificate hygiene |
| Priority | Low |
| Detection source | Vulnerability scanner |
| Affected entity | intranet.harbourline.example (10.20.10.30) |
| Opened | 2026-10-08 11:00 UTC |

**Summary:** Scanner reports the intranet HTTPS certificate expired yesterday. Users see browser warnings.

## 1. Evidence
### Scanner
```text
Plugin   : SSL Certificate Expiry
Host     : 10.20.10.30:443
Subject  : CN=intranet.harbourline.example
Issuer   : CN=Harbourline Internal Issuing CA 02
NotAfter : 2026-10-07 23:59:59 UTC   (EXPIRED)
```

### openssl
```text
$ openssl s_client -connect intranet.harbourline.example:443 -servername intranet.harbourline.example </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
subject=CN = intranet.harbourline.example
issuer=CN = Harbourline Internal Issuing CA 02
notBefore=Oct  7 00:00:00 2025 GMT
notAfter=Oct  7 23:59:59 2026 GMT
SHA256 Fingerprint=3A:9F:...:C1   (matches the cert issued by our CA in 2025 — not swapped)
```

### Service desk
```text
6 tickets today: "Your connection is not private" on intranet.
CMDB owner: Web Platform team. Renewal task was assigned to a leaver.
```

## 2. Hunting query (KQL)
```kql
// No KQL needed — this is configuration hygiene. Example check from scanner data:
// SecurityRecommendation / or your scanner's table
// | where Title has "certificate" and Status == "Expired"
```

## 3. Indicators of compromise (defanged)
None — no external indicators.

## 4. MITRE ATT&CK mapping
Not an attack technique — operational / hygiene finding.

## 5. L1 runbook (internal KB SOC-VUL-004 — Certificate expiry findings)
1. Confirm the certificate details with openssl.
2. Check it is the expected certificate (fingerprint / issuer) — rule out interception.
3. If it is our own cert simply expired: raise a P3 change to the owner team, tell users not to click through warnings.
4. Escalate to security only if the certificate or issuer is unexpected.

## 6. Decision
**Resolved at L1** · Classification: **True positive**

Real finding, but operational: our own certificate expired and was not replaced by an attacker. Route to the owner team and close the security ticket.

## 7. Model ticket notes
- **Short description:** Intranet TLS cert expired — own cert, not tampered — routed to Web Platform
- **Investigation:** openssl confirms CN=intranet.harbourline.example, issuer Internal Issuing CA 02, notAfter 07 Oct 2026; fingerprint matches the cert issued in 2025, so no interception. Renewal owner had left the company.
- **Actions:** Raised CHG request to Web Platform to renew and bind a new cert. Service desk message: do not click through certificate warnings. Suggested 30/14/7-day expiry alerts.
- **Next step:** Closed at L1 (handed to IT operations).

## References
- [NIST SP 1800-16 — TLS Server Certificate Management](https://csrc.nist.gov/pubs/sp/1800/16/final)

[← Back to casebook](README.md)
