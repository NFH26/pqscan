# Scores and bands

## Two axes, not one

Every endpoint gets two scores, each 0–100, where **0 means it already meets the profile** and
100 is the worst case.

**Confidentiality** is about what protects the data: the key exchange, the cipher, the protocol
version, and how long the data must stay secret.

**Authentication** is about what proves you are talking to the right server: the certificate
chain, the signature and hash algorithms, key sizes and curves, and validation failures.

They are separate because they fail separately and are fixed by different people. A site can
negotiate ML-KEM and still serve a certificate signed with RSA — post-quantum on the wire,
classical in the chain. One number would hide that.

> Higher is worse. This is a risk score, not a grade. It was chosen so that "0" is the goal and
> an unmeasured endpoint can be `n/a` rather than an ambiguous zero.

## The readiness band

Alongside the scores, one 0–5 band per endpoint:

| Band | Name | Condition |
|---|---|---|
| 5 | PQ approved | Negotiates a post-quantum key exchange ASD approves beyond 2030 |
| 4 | PQ in use | Negotiates post-quantum today, on a transitional parameter set |
| 3 | PQ capable | Supports a post-quantum key exchange but negotiates a classical one |
| 2 | Sound classical | No post-quantum, but current protocols and approved algorithms |
| 1 | Dated | Encrypted, but behind on protocol version or algorithms |
| 0 | Unprotected | No encryption, an obsolete protocol, or a service that will not encrypt |

**Band 3 is the one that earns the column.** An endpoint that *cannot* do post-quantum and one
that *can but does not* both score as classical. Only the second is a preference line away from
compliant. Finding those is what the capability probe exists for, and nothing else surfaces it.

Readiness sets the ceiling and the score sets the floor, so a post-quantum endpoint is never
banded below a classical one with the same weaknesses. Anything with no encryption or an
obsolete protocol is banded 0 regardless of score — that is absent security, not low maturity.
An endpoint that could not be measured gets no band at all, because "unmeasured" is not a
posture and a 0 would read as a finding.

### This is not the PQCMM

PQScan's band deliberately does **not** claim to implement the
[PKI Consortium's PQC Maturity Model](https://pkic.org/wg/pqc/pqcmm/). The PQCMM rates a named
*product or service as released and shipped*, and its levels 2 and above require evidence no
scanner can observe: CAVP conformance results, an SBOM and CBOM, crypto-agility across
algorithms, an HNDL exposure register, zero-legacy configurability including firmware signing,
and independent FIPS 140 or Common Criteria validation.

A scan can contribute evidence towards a PQCMM assessment. It cannot be one, and presenting a
handshake as a PQCMM level would be exactly the unsupported claim their own guidelines warn
about.

## How a score is built

Use `--explain` to see it:

```
cloudflare.com:443
Confidentiality:
key exchange X25519MLKEM768 -> TRANSITIONAL (+20)
    data_lifetime > 5y (+10)
    subtotal 30 x criticality low 0.7 = 21

Authentication:
weakest signature in chain: ecdsa-with-SHA256 on cloudflare.com -> NOT_APPROVED_AFTER_2030 (+50)
    worst hash in chain: NOT_APPROVED_AFTER_2030 (+10)
    curve_below_preferred (informational) (+5)
    subtotal 65 x criticality low 0.7 = 45 (capped at 100)
```

Every line names a rule, its ISM control where one applies, and its points. **The lines add up
to the subtotal.** The subtotal is multiplied by criticality and capped at 100.

### Classifications

Each algorithm is classified against the rule profile:

| Classification | Meaning |
|---|---|
| `APPROVED` | Meets the ISM, including beyond 2030 |
| `TRANSITIONAL` | Approved now, not beyond 2030 — every post-quantum hybrid is here |
| `NOT_APPROVED_AFTER_2030` | Classical algorithms ASD approves today and not past 2030 |
| `REVIEW` | Not named in the ISM; judge it yourself |
| `NOT_APPROVED` | Not an ASD-approved algorithm |

### Mandatory versus preferred

The ISM's wording decides the weight. A control phrased *"is used"* is mandatory and carries a
real penalty. A control phrased *"preferably"* is a preference: those findings are marked
`(informational)` and share a cap, so preferences cannot add up to look like a breach.

## Criticality and data lifetime

`criticality` multiplies both scores: `low` ×0.7, `medium` ×1.0, `high` ×1.3. The same
cryptography is a different risk on a system that matters more.

`data_lifetime_years` raises confidentiality risk past 5 years and again past 10. This is the
harvest-now-decrypt-later dimension, and it is the reason a "fine today" endpoint can still be a
finding: traffic recorded in 2026 and decrypted in 2035 is a breach in 2035, and the only thing
that prevents it is the key exchange used in 2026.

## Why hybrids are TRANSITIONAL, not APPROVED

This is the position most likely to surprise someone used to NIST or NCSC guidance, so it is
worth stating plainly.

ASD's guidance says *"post-quantum traditional hybrid schemes are not recommended; however, it
is not prohibited"*, and that *"all organisations should expect to move to purely post-quantum
algorithms."* ISM-1996 requires only that one half of a hybrid be an approved algorithm.

The world's default is `X25519MLKEM768`. Under the ISM **both halves lose approval after 2030**:
X25519 as a traditional algorithm, ML-KEM-768 because ISM-1995 prefers ML-KEM-1024 and retires
768. So adopting the global default now commits an Australian organisation to a second migration
before 2030.

That is why the tool bands a working hybrid at 4 rather than 5, and why its advice says *plan
the move to pure ML-KEM-1024*.

## Changing the rules

Everything above is data, not code. `pqc_scan/rules/asd_ism.yaml` holds every classification
with the ISM control that sets it; `pqc_scan/rules/scoring.yaml` holds the weights and the band
definitions. Adjusting a position is a YAML edit.

Two positions are judgement calls, both marked `verify:` in the profile:

- **Hybrids are TRANSITIONAL**, for the reason above.
- **`sntrup761x25519` is not ML-KEM.** It is Streamlined NTRU Prime, which the ISM does not
  approve, so it is classified on the strength of its classical half. It is quantum-resistant in
  practice; it is not ISM-approved. GitHub still leads with it.
