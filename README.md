# PQScan

**Post-quantum readiness scanning for TLS, SSH, IPsec and email, scored against the Australian
ASD Information Security Manual.**

[![CI](https://github.com/nayefalharbi/pqscan/actions/workflows/ci.yml/badge.svg)](https://github.com/nayefalharbi/pqscan/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

The Australian Signals Directorate (ASD) expects Australian organisations to complete their
post-quantum transition by the end of 2030. Its
[Information Security Manual](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism)
(ISM) is the standard that sets it, and it is the standard PQScan measures against: every
classification in the rule profile cites the ISM control it comes from, and the control numbers
are checked on every run against ASD's
[OSCAL catalog](https://github.com/AustralianCyberSecurityCentre/ism-oscal).

PQScan tells you where you actually stand: it connects to your endpoints, reads what they
negotiate, and reports each one against the ISM controls that govern it — with the control
numbers, a risk score, and what to change.

PQScan is an independent project. It is not affiliated with, endorsed by, or produced by ASD.

```console
$ pqc scan www.ato.gov.au -y

 Host                 Version   Key exchange                   Status          Conf risk   Auth risk
 ────────────────────────────────────────────────────────────────────────────────────────────────────
 www.ato.gov.au:443   TLSv1.3   x25519 (can: X25519MLKEM768)   3 PQ capable           62          38

Recommendations
  #   Effort        Do this                                               Applies to
  1   config        Reorder the server's group preference so the ...      www.ato.gov.au:443 (tls)
  2   certificate   At next renewal, move to the P-384 curve.             www.ato.gov.au:443 (tls)
```

That endpoint **supports** a post-quantum key exchange and **negotiates** a classical one. It is
one configuration line from compliant, and no other scanner will tell you that.

---

## Why this exists

Every other scanner answers "is this TLS configuration good?". PQScan answers a different
question: **"does this endpoint meet the ISM, and what do I change?"**

- **It maps to ASD ISM control numbers.** 46 controls across TLS, SSH, IPsec, email and
  certificates, verified against ASD's published OSCAL catalog on every run. No other scanner
  maps to the ISM at all.
- **It measures what OpenSSL refuses to.** OpenSSL 3.5 removed 3DES, RC4, NULL and EXPORT from
  its cipher list, so a host that only speaks those is unreachable through the `ssl` module.
  PQScan builds its own ClientHello and measures them anyway — those are the hosts a readiness
  report most needs to name.
- **It separates *can't* from *doesn't*.** A server that supports ML-KEM but negotiates x25519
  scores as classical everywhere else. Here it is band 3, and that is the difference between a
  morning's work and a procurement cycle.
- **It knows Australia is different.** ASD does **not** recommend hybrid schemes, while NIST,
  NCSC and the EU do. Under the ISM, both halves of the world's default `X25519MLKEM768` lose
  approval after 2030, so adopting the global default commits you to a second migration.

## Install

Requires Python 3.11 or newer. Nothing else — not even OpenSSL.

```bash
git clone https://github.com/nayefalharbi/pqscan.git
cd pqscan
./pqc setup
```

`./pqc setup` creates an isolated environment and runs a preflight check. On Windows, or
without the launcher:

```bash
pip install -e .
pqc doctor
```

## Use it

```bash
# one endpoint
pqc scan example.com -y

# find what a host is running, then measure every service on it
pqc scan example.com -y --discover

# a whole estate, with every report format
pqc scan --input hosts.csv -y -o reports/

# a specific protocol, without writing a host file
pqc scan example.com -y --protocol domain
pqc scan vpn.example.com:500 -y

# check the tool itself against endpoints with a known answer
pqc selftest
```

`-y` is short for `--confirm-authorised`. It is deliberately required: **only scan what you are
authorised to scan.**

## What it measures

| Protocol | How | ISM controls |
|---|---|---|
| **TLS** (all versions) | Own ClientHello; negotiated group, capability probe, certificate chain | ISM-1139, 1369, 1372, 1373, 1374, 1453, 1553 |
| **SSH** | Unauthenticated KEXINIT read — every algorithm the server accepts | ISM-1506, 0471 |
| **IPsec / IKEv2** | One plaintext `IKE_SA_INIT` datagram; the responder's chosen transforms | ISM-1233, 1771, 1772, 0998, 0999 |
| **STARTTLS** | SMTP, IMAP, POP3, FTP, LDAP, PostgreSQL | as TLS |
| **Domain** | SPF, DMARC, MTA-STS, HSTS via DNS and one HTTPS request | ISM-0574, 1183, 1540, 1589, 1424 |
| **Certificates** | Signature and hash algorithms, key sizes, curves, chain validation | ISM-0472, 0474, 0475, 0476, 1446, 1759, 1761-1766 |

DNS over TLS (ISM-2017) and SIP over TLS (ISM-0548) need no extra code — they are TLS on
another port, and the port map already knows them.

## Documentation

| Guide | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Install, first scan, reading the output |
| [Scanning](docs/scanning.md) | Host files, protocols, discovery, every flag |
| [Scores and bands](docs/scoring.md) | How the numbers are built and what they mean |
| [ISM coverage](docs/ism-coverage.md) | Every control, what is measured, what cannot be |
| [Output formats](docs/outputs.md) | HTML, CSV, JSON, CBOM, SARIF, Markdown |
| [CI and automation](docs/ci.md) | Exit codes, policy gates, GitHub Actions |
| [Architecture](docs/architecture.md) | How it works, and how to add a protocol |

## Verifying the tool

A compliance tool that quietly gets something wrong is worse than no tool. Two commands:

```bash
pqc test        # unit tests, no network, about ten seconds
pqc selftest    # a real scan of every protocol against endpoints with a known answer
```

`selftest` also checks the tool against itself: the scoring invariants, the output formats, and
**every ISM control number cited, against ASD's catalog** — the ISM is reissued quarterly and
control numbers are retired. [CI and automation](docs/ci.md#verifying-the-tool-in-ci) has the
full list and the offline variant for pre-commit hooks.

## Scope and honesty

Some ISM controls are not observable from a network, and PQScan says so rather than guessing:
full disk encryption (ISM-0459, 1059), code signing (ISM-1796, 1797), S/MIME version
(ISM-0490), IPsec mode and SA lifetime (ISM-0494, 0496, 0498, 1000), and most SSH host
configuration. Wi-Fi needs a radio in monitor mode and MACsec is link-local, so neither is
reachable from a routed scanner.

An endpoint that could not be measured is reported as **not measured**, never as a pass.

## Licence and attribution

Apache-2.0. Copyright 2026 Nayef Alharbi. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

ISM control identifiers in `pqc_scan/rules/ism_controls.txt` are extracted from the Australian
Signals Directorate's [OSCAL catalog](https://github.com/AustralianCyberSecurityCentre/ism-oscal),
published under CC BY 4.0. This project is not affiliated with or endorsed by ASD.
