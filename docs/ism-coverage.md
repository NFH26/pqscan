# ISM coverage

PQScan scores against the ASD Information Security Manual. This page says exactly which
controls it measures, which it cannot, and why.

**Rule profile:** `asd_ism`, rules version `2026.09.1`
**Control identifiers verified against:** ASD OSCAL catalog `2026.09.4` (published 2026-09-03)

`pqc selftest --offline` re-verifies every cited control number against the catalog. The ISM is
reissued quarterly and control numbers are retired, so a citation that was right last quarter
can quietly stop being right. `python tools/refresh_ism_controls.py` updates the local copy when
a new ISM lands.

## Measured

### Transport Layer Security

| Control | Requirement | How it is measured |
|---|---|---|
| ISM-1139 | Only the latest version of TLS is used | Negotiated version |
| ISM-1369 | AES-GCM is used for encryption | Negotiated cipher suite |
| ISM-1372 | Ephemeral DH or ECDH for key establishment | Cipher suite; static RSA key transport detected with `--deep` |
| ISM-1373 | Anonymous DH is not used | Cipher suite |
| ISM-1374 | SHA-2 based certificates | Certificate signature algorithm |
| ISM-1453 | Perfect Forward Secrecy | Cipher suite and key exchange |
| ISM-1553 | TLS compression disabled | Handshake |

### Secure Shell

| Control | Requirement | How it is measured |
|---|---|---|
| ISM-1506 | SSH version 1 is disabled | Identification string |
| ISM-0471 | Only approved algorithms are used | Every algorithm in the KEXINIT name-lists. A server advertises what it will accept, so offering a weak algorithm is itself the finding — the client chooses, and an attacker is a client |

### Internet Protocol Security

Answered from one unauthenticated, plaintext `IKE_SA_INIT` exchange.

| Control | Requirement | How it is measured |
|---|---|---|
| ISM-1233 | IKE version 2 is used | The responder answered IKEv2 |
| ISM-1771 | AES, preferably ENCR_AES_GCM_16 | Chosen ENCR transform and key length |
| ISM-1772 | PRF_HMAC_SHA2_256/384/512, preferably 512 | Chosen PRF transform |
| ISM-0998 | AUTH_HMAC_SHA2_*, preferably NONE with AES-GCM | Chosen INTEG transform, checked against the cipher — NONE without an AEAD cipher means no integrity at all |
| ISM-0999 | DH or ECDH, preferably 384-bit ECP or 3072/4096 MODP | Chosen D-H group |
| ISM-0494 | Tunnel mode, or transport mode inside an IP tunnel | Chosen mode in the responder's proposal |
| ISM-0496 | ESP is used for authentication and encryption | Protocol ID in the accepted proposal |
| ISM-0498 | Security association lifetime under four hours | Lifetime attribute in the chosen proposal, where the responder sends one |
| ISM-1000 | Perfect forward secrecy | A D-H group is present in the proposal, so keys are not derived from a long-term secret |

### Email and web transport

| Control | Requirement | How it is measured |
|---|---|---|
| ISM-0572 | Opportunistic TLS on email servers | STARTTLS probe |
| ISM-0574 | SPF specifies authorised email servers | Apex TXT record |
| ISM-1183 | A **hard fail** SPF record is used | The record ends in `-all`. `~all` only soft-fails, so forged mail is still delivered |
| ISM-1540 | DMARC configured to **reject** | `_dmarc` TXT. `p=none` and `p=quarantine` both still deliver |
| ISM-1589 | MTA-STS is enabled | `_mta-sts` TXT plus the policy file, which must be served with a 200 and be in `enforce` mode |
| ISM-1424 | HSTS in response headers | One HTTPS request |
| ISM-0861 | DKIM signing is enabled | `_domainkey` TXT records for the common selectors |
| ISM-2017 | DNS traffic encrypted | DNS over TLS on port 853 |
| ISM-0548 | Secure session initiation protocol | SIP over TLS on port 5061 |

### Algorithms and certificates

| Control | Requirement |
|---|---|
| ISM-0469, 0481 | Approved protocol for data in transit |
| ISM-0471 | Only approved algorithms |
| ISM-0472, 1759 | DH modulus size |
| ISM-0474, 1761, 1762 | ECDH curves |
| ISM-0475, 1763, 1764 | ECDSA curves |
| ISM-0476, 1765 | RSA modulus size |
| ISM-1446 | NIST SP 800-186 curves |
| ISM-1766 | SHA-2 output size |
| ISM-1917 | Support for ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512, AES-256 by 2030 |
| ISM-1991 | ML-DSA-65 or ML-DSA-87, preferably 87 |
| ISM-1995 | ML-KEM-768 or ML-KEM-1024, preferably 1024 |
| ISM-1996 | A hybrid has at least one approved half |
| ISM-2073 | A post-quantum transition plan exists |
| ISM-2082, 2083 | Cryptographic bill of materials — see [Output formats](outputs.md#cbom) |

Certificate classification also applies the `classification_curve_rules` for the level you set
per host (`NC`, `OS`, `P`, `S`, `TS`), because ASD sets different minimum curve strengths by
classification.

## Not observable, and stated as such

A scanner that quietly omits a control it cannot see is more dangerous than one that says so.
These are named in the rule profile and, for IPsec, printed in the report.

| Control | Why not |
|---|---|
| ISM-0494, 0496 | IPsec mode and ESP/AH are settled in `IKE_AUTH`, which needs credentials |
| ISM-0498 | IKEv2 does not carry the SA lifetime in the SA payload; it is local policy |
| ISM-1000 | Child SA Perfect Forward Secrecy appears only in `CREATE_CHILD_SA` |
| ISM-0459, 1059, 2109 | Full disk encryption is a property of a volume, not a connection |
| ISM-1796, 1797, 2050 | Code signing needs the artefact |
| ISM-0490 | S/MIME version is a message-format property |
| ISM-1449, 0484, 0487, 0488, 0489 | SSH host configuration lives in `sshd_config`, not on the wire |
| ISM-1332 and neighbours | Wi-Fi needs a radio in monitor mode — a different product |
| ISM-2163–2167 | MACsec runs at layer 2 on the local segment; a routed scanner cannot see it |
| ISM-1321 | 802.1X requires being a supplicant on the wire |

DKIM (ISM-0861) is reported as **inconclusive**, never as a failure. A DKIM record lives at a
selector name that only appears in a signed message header, so it cannot be enumerated: absence
of a hit is absence of evidence.

**DNSSEC and RDP have zero ISM controls.** They are not measured, and not for want of trying.

## The 2030 deadline, precisely

Three things worth stating carefully, because they are often summarised wrongly:

1. **The date is "by no later than 2030" / end of 2030**, and ASD's own verb is *recommends*.
   There is no gazetted day.
2. **ISM-1917 is scoped to new development and procurement**, not to all existing systems. The
   blanket effect arrives indirectly, because RSA, DH, ECDH, ECDSA, ML-KEM-768, ML-DSA-65,
   SHA-256, AES-128 and AES-192 all lose approval beyond 2030.
3. **ML-KEM-1024 and ML-DSA-87 are *preferred*, not the only approved sets today.** They become
   the only approved sets after 2030.

## Sources

- [ASD ISM OSCAL catalog](https://github.com/AustralianCyberSecurityCentre/ism-oscal) — CC BY 4.0
- [Guidelines for cryptography](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/cyber-security-guidelines/guidelines-for-cryptography)
- [Planning for post-quantum cryptography](https://www.cyber.gov.au/business-government/secure-design/quantum/planning-for-post-quantum-cryptography)

This project is not affiliated with or endorsed by the Australian Signals Directorate.
