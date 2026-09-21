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
pqc scan cloudflare.com -y
```

```
 Endpoint             Version   Key exchange     Status        Conf risk   Auth risk   Findings
 ──────────────────────────────────────────────────────────────────────────────────────────────────
 cloudflare.com:443   TLSv1.3   X25519MLKEM768   4 PQ in use          20          65   curve < preferred

Status: 5 pure post-quantum, ASD-approved beyond 2030  4 post-quantum in use
        3 supports it but does not use it  2 sound classical  1 dated  0 unprotected
Risk 0 = already meets the profile, 100 = worst. Lower is better.

Recommendations
  #   Effort        Do this                                        Applies to
  1   design        Plan the move to pure ML-KEM-1024. Keep ...     cloudflare.com:443 (tls)
  2   certificate   At next renewal, move to the P-384 curve.      cloudflare.com:443 (tls)
```

`-y` is `--confirm-authorised`, and it is required. Scanning infrastructure you do not own or
have written permission to test is, depending on where you are, a criminal offence. The flag is
there so that consent is an explicit act rather than a default.

Every recommendation names the endpoints it applies to, and every endpoint names the service it
runs. An estate can hold three VPN concentrators and a dozen SSH hosts, so "12 endpoints need a
config change" is not something anyone can act on. The HTML report lists every affected endpoint
per recommendation and links each one to its own measurements.

## Reading the output

**Status** is the one column to read first. It combines post-quantum readiness and the health of
the classical configuration into a single 0–5 band:

**5** is pure post-quantum and ASD-approved beyond 2030, **4** is post-quantum in use today,
**3** supports post-quantum but negotiates something classical, **2** is sound classical, **1**
is dated, **0** is unprotected, and **UNKNOWN** could not be measured and never counts as a
pass. [Scoring](scoring.md#the-readiness-band) defines each band and what moves an endpoint
between them.

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
# find what a host runs and measure all of it
pqc scan example.com -y --discover

# a whole estate, with every report format in a dated folder
pqc scan --input examples/hosts.csv -y -o reports/

# show me why that score
pqc scan example.com -y --explain
```

Then read [Scanning](scanning.md) for host files and flags, or [Scores and bands](scoring.md)
for how the numbers are built.
