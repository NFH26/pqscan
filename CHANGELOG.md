# Changelog

Notable changes to PQScan. Format based on [Keep a Changelog](https://keepachangelog.com/),
versioning follows [Semantic Versioning](https://semver.org/).

Rule-profile changes are called out separately, because a new rules version can change a score
without any code changing.

## [0.4.0] - 2026-09-21

First public release.

### Added

- **Service-specific recommendations.** Every recommendation names the endpoints it applies to
  and the service each one runs (`vpn-a.example:500 (ipsec)`), in the terminal, the Markdown
  export and the HTML report, where each endpoint links to its own measurements. An estate with
  several VPNs or a dozen SSH hosts needs to know which box to change, not how many.
- **IPsec / IKEv2 probe.** One unauthenticated, plaintext `IKE_SA_INIT` answers ISM-1233, 1771,
  1772, 0998 and 0999. Handles the RFC 7296 cookie challenge, which any gateway under load
  issues — and which a probe that ignores it measures nothing against.
- **Domain controls.** SPF (ISM-0574), hard-fail SPF (ISM-1183), DMARC reject (ISM-1540),
  MTA-STS enforcing (ISM-1589) and HSTS (ISM-1424), via a hand-rolled DNS resolver so the
  install stays one command.
- **Service discovery** (`--discover`). Given a hostname, finds which of 24 ISM-relevant ports
  are live, identifies each from its greeting, and measures them all.
- **Cipher suite enumeration** (`--deep`). Reading one ServerHello only reveals a server's
  favourite suite. `badssl.com` leads with AES-GCM and still accepts 3DES and static RSA key
  transport — the suite a downgrade attack asks for.
- **CBOM export.** CycloneDX 1.6, built from observed negotiation rather than declared
  dependencies, citing ISM-2082 and ISM-2083.
- **SARIF and Markdown exports**, alongside HTML, CSV and JSON. One `-o` directory, `-f` to
  narrow. Each run lands in its own dated folder.
- **`pqc selftest`.** A real scan of every protocol against endpoints with a known answer, plus
  offline checks of the rule profile, the scoring invariants and every output format — including
  that every cited ISM control number still exists in ASD's catalog.
- **Readiness band, 0-5.** Band 3, *PQ capable but not negotiating*, is the one that matters: an
  endpoint that cannot do post-quantum and one that can but does not are both classical, and
  only the second is a configuration line from compliant.
- DNS over TLS (ISM-2017) and SIP over TLS (ISM-0548) via the port map.
- `--protocol` for a single target, `--flat`, and a per-host time budget.

### Fixed

- **Ed25519 and Ed448 certificates no longer raise.** Both key types carry no `key_size`
  attribute, so reading one raised `AttributeError` on any endpoint presenting an EdDSA
  certificate. Both curves are fixed size and are now reported as such.
- **mypy now actually runs.** It was aborting on a module-path collision before checking a
  single file, so the type gate had never caught anything. The findings it surfaced once it ran
  are fixed in this release.
- **The scanner crashed on a machine with no OpenSSL binary** — the configuration the README
  promises and `doctor` reports as fine.
- **A file descriptor leaked on every exception path** in the main TLS connection, which is the
  weak-crypto path, so scanning a legacy estate exhausted descriptors.
- **Hosts that only speak 3DES, RC4 or NULL were unmeasurable.** OpenSSL 3.5 removed those
  suites entirely; PQScan now builds its own ClientHello and measures them.
- **Network failures were reported as ISM breaches.** A DNS timeout on `_dmarc` was
  indistinguishable from a domain publishing no DMARC.
- **IKEv2 transforms were read from a fixed offset**, ignoring the declared SPI size, producing
  plausible but wrong algorithm names.
- **A YAML null silently disabled the NULL-cipher check**, letting an unencrypted endpoint score
  better than a 3DES one.
- TLS below 1.3 reported as UNKNOWN rather than definitively classical.
- Ports treated as contracts rather than guesses — SSH on 443 is now detected and measured.
- Teardown could hang forever against a peer that went silent mid-handshake.
- `--require-hybrid-kex` failed on every domain row.
- An SSH server's `SSH_MSG_DISCONNECT` reason is quoted instead of reported as a parse error.

### Changed

- **`pqc report` uses the same writers as `pqc scan --out`.** It carried its own thinner JSON
  and CBOM writers, so `report --format cbom` and `scan -f cbom` produced different documents.
  It now takes the same format names as `scan` and writes the same files. The `rich` and
  `jsonl` format names are gone; `rich` was the terminal output, which prints anyway.
- **The status legend lists only the bands on screen.** A six-band legend under a table holding
  one band is definitions for something the reader is not looking at.
- **A one-host scan drops the fleet summary.** "Hosts scanned 1" and "PQ readiness HYBRID 1"
  both restated the single row underneath them.
- **`pqc scan` no longer warns about an old OpenSSL.** Scanning never uses the binary, so the
  notice was a warning that trains people to ignore warnings. `pqc doctor` reports the
  capability and `pqc verify` enforces the version.
- **`pqc doctor` ends by showing how to start a scan** rather than with a scoring legend that
  belongs next to a score.
- **The summary counts endpoints, not hosts.** After `--discover` finds seven services on one
  host, "Hosts scanned 7" was simply wrong; it now reads "Endpoints 7 on 1 host(s)" and adds a
  breakdown by service when more than one kind was measured.
- **Every row names its service.** Four SSH listeners on one host differ only by port, and a
  table showing the port alone read as the same row four times.
- **Recommendations list every affected endpoint.** "+2 more" hid exactly the VPN or SSH host
  the reader was looking for.
- **Removed the PQCMM claim.** Checked against the published model: the PKI Consortium's PQC
  Maturity Model rates a named product as shipped, on evidence a handshake cannot see. PQScan
  reports its own band and says plainly why a scan can contribute evidence to a PQCMM assessment
  but cannot be one.
- **Python 3.11 and newer**, down from 3.13.
- The summary says only what is true at the scale scanned; a distribution over one host repeated
  the row below it.
- One `Status` column instead of separate Ready and Band columns, which said the same thing
  twice.
- Three export flags became `-o` and `-f`. The old flags still work.

### Rules

- `asd_ism` rules version `2026.09.1`, control identifiers verified against ASD OSCAL catalog
  `2026.09.4`.
- SSH tables now classify ML-KEM hybrids over NIST curves and ML-DSA host keys. ML-DSA-44 is
  classified unapproved: ISM-1991 lists only ML-DSA-65 and ML-DSA-87.
- NULL and EXPORT ciphers scored separately from weak-but-real ciphers, at the cap.

[0.4.0]: https://github.com/nayefalharbi/pqscan/releases/tag/v0.4.0
