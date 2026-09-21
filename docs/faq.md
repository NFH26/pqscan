# FAQ

### Does this need OpenSSL?

No. Scanning speaks TLS, SSH and IKEv2 directly. Only `pqc verify` — the optional cross-check —
uses the `openssl` binary, and it needs 3.5 or newer. `pqc doctor` tells you what your machine
can do and exits `0` either way.

### Is it safe to run against production?

It never completes a handshake it does not need, never authenticates, and never sends
application data. The heaviest mode is `--deep`, which opens one connection per cipher suite;
use `--rate-limit` on shared infrastructure. `--scope-file` restricts an engagement to the
domains in the statement of work.

Scanning infrastructure you are not authorised to test may be a criminal offence. `-y` exists so
that consent is an explicit act.

### Why is a working post-quantum endpoint not scored 0?

Because ASD does not approve today's default hybrid beyond 2030. `X25519MLKEM768` has two halves
and **both** lose approval: X25519 as a traditional algorithm, ML-KEM-768 because ISM-1995
prefers ML-KEM-1024. The endpoint is genuinely better off than a classical one — that is why it
bands 4 — but it is not finished. See [Scores and bands](scoring.md#why-hybrids-are-transitional-not-approved).

### GitHub uses `sntrup761x25519`. Why is that classical?

Streamlined NTRU Prime is quantum-resistant in practice and is **not** an ASD-approved algorithm,
so the hybrid is classified on the strength of its classical half. This is a strict reading, it
is marked `verify:` in the rule profile, and it is worth confirming before you put it in front of
a client.

### What does band 3 mean, and why do I care?

The endpoint supports a post-quantum key exchange and negotiates a classical one. Every other
scanner calls it classical. It is a server preference line away from compliant — usually one
config change, no procurement, no downtime. On a real estate it is often the cheapest win
available, and finding it is what the capability probe is for.

### An endpoint shows UNKNOWN. Is that a failure?

It means the tool could not measure it, and it is never counted as a pass. Check the Issues
table for the reason. Common causes are a firewall in between, a rate-limited host, or a service
that is not what the port suggested. Try it alone before treating it as a defect.

### Can it scan an internal network?

Yes. It needs no internet access, and the rule profile and control list ship with it. DNS-based
checks need a resolver, which it reads from `/etc/resolv.conf`.

### Does it support frameworks other than the ISM?

Not yet. The rule profile is data — `--profile NAME` selects one — so adding NIST or BSI
TR-02102 is a YAML file rather than a code change. Contributions welcome.

### Why two scores instead of one grade?

Confidentiality and authentication fail separately and are fixed by different people. A site can
negotiate ML-KEM and serve an RSA-signed certificate: post-quantum on the wire, classical in the
chain. A single grade hides that, and the hiding is the part that costs you.

### How do I check the tool is right?

`pqc selftest`. It scans a reference endpoint for every protocol, checks the answers against
known-correct values, verifies the scoring invariants, and confirms every ISM control number
still exists in ASD's catalog. See [CI and automation](ci.md#verifying-the-tool-in-ci).

### Is this endorsed by ASD?

No. It is an independent implementation that maps to published ISM controls. Control identifiers
come from ASD's OSCAL catalog, published under CC BY 4.0. Nothing here is legal or compliance
advice — an ISM assessment is made by your assessor, not by a scanner.
