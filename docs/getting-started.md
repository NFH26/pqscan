# Getting started

## Install

PQScan needs Python 3.11 or newer and nothing else. It does **not** need OpenSSL: it speaks TLS,
SSH and IKEv2 itself, which is deliberate — see [Architecture](architecture.md#why-not-openssl).

```bash
git clone https://github.com/NFH26/pqscan.git
cd pqscan
./pqc setup
```

`./pqc setup` creates an isolated environment with [uv](https://docs.astral.sh/uv/), installing
uv and a suitable Python first if they are missing, then runs a preflight check.

Without the launcher, or on Windows:

```bash
python -m pip install -e .
pqc doctor
```

`pqc doctor` reports what this installation can do. It exits `0` even when OpenSSL is old or
absent, because scanning never uses it — only `pqc verify` does.

## Your first scan

```bash
pqc cloudflare.com
```

```
Only scan systems you own or have permission to test.
Scan cloudflare.com? [y/N]: y

 Site             Result         What to do
 ──────────────────────────────────────────────────────────────────────────────
 cloudflare.com   Almost ready   Plan the move to pure ML-KEM-1024.

Almost ready = uses post-quantum, but the ISM wants ML-KEM-1024 by 2030

Full report: reports/cloudflare.com-20261121-093000.html
More detail: add --details. All formats: add -o FOLDER.
```

PQScan asks before it scans, every time. Scanning infrastructure you do not own or have written
permission to test is, depending on where you are, a criminal offence, so consent is an explicit
act rather than a default. In a script or CI job there is no one to ask, so pass `-y` (or
`--confirm-authorised`) to say that you are authorised for every target.

## Reading the output

Each endpoint gets one verdict:

| Verdict | Meaning |
|---|---|
| **Ready** | Meets the ISM profile for key exchange |
| **Almost ready** | Uses post-quantum today, but the ISM wants ML-KEM-1024 by 2030 |
| **Quick fix** | Supports post-quantum but does not use it, usually one setting |
| **Not ready** | Classical cryptography only |
| **Unsafe today** | Weak or no encryption now, before any quantum computer |
| **Not measured** | Could not connect. Never counted as a pass |

A domain row (`example.com (email/web)`) shows the SPF, DMARC, MTA-STS and HSTS result instead,
because those controls say nothing about post-quantum.

**What to do** is the single most useful change for that endpoint. The HTML report has every
recommendation, the ISM control behind it, and each endpoint's measurements.

## The detailed view

`--details` prints the full table behind those verdicts:

```
 Endpoint             Version   Key exchange     Status        Conf risk   Auth risk   Findings
 ──────────────────────────────────────────────────────────────────────────────────────────────────
 cloudflare.com:443   TLSv1.3   X25519MLKEM768   4 PQ in use          20          65   curve < preferred
```

**Status** combines post-quantum readiness and the health of the classical configuration into a
single 0–5 band: **5** is pure post-quantum and ASD-approved beyond 2030 (Ready), **4** is
post-quantum in use today (Almost ready), **3** supports post-quantum but negotiates something
classical (Quick fix), **2** is sound classical and **1** is dated (both Not ready), **0** is
unprotected (Unsafe today), and **UNKNOWN** could not be measured.
[Scoring](scoring.md#the-readiness-band) defines each band and what moves an endpoint between them.

**Conf risk** and **Auth risk** are the confidentiality and authentication scores, the same
numbers `--fail-on-score` gates on and the same ones the JSON export calls
`confidentiality_score` and `authentication_score`. Both run 0–100, where **0 means the endpoint
already meets the profile** and 100 is the worst case. Confidentiality is about the key exchange and cipher —
what protects the data. Authentication is about the certificate chain or host key — what proves
you are talking to the right server. They are separate because they usually fail separately and
are fixed by different people.

**Findings** are the specific rules that fired, shortened for the table. `--explain` prints the
full breakdown with ISM control numbers and points.

## Next steps

```bash
# find what a host runs and check all of it
pqc example.com --discover

# a whole estate, with every report format in a dated folder
pqc --input examples/hosts.csv -y -o reports/

# show me why that score
pqc example.com --explain
```

Then read [Scanning](scanning.md) for host files and flags, or [Scores and bands](scoring.md)
for how the numbers are built.
