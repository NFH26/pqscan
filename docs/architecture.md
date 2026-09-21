# Architecture

The whole tool is one pipeline, and everything else is data.

```
host file  ->  Target  ->  PROBES[protocol]  ->  HostFinding  ->  Scorer  ->  FORMATS[name]
                              |                       |             |
                        port_map.yaml          asd_ism.yaml   scoring.yaml
```

A **probe** observes an endpoint and describes what it found in the shared `HostFinding` shape.
It never scores, never formats, and never knows about reports. A **scorer** turns a
`HostFinding` into numbers using the rule profile. An **exporter** turns findings into a file.
Each stage knows only the shape between it and the next.

## Why not OpenSSL

PQScan builds its own TLS ClientHello, SSH KEXINIT reader, IKEv2 `IKE_SA_INIT` and DNS TXT
resolver. That is a deliberate choice, and it was not free.

OpenSSL is better than this code at everything OpenSSL will do. The problem is that OpenSSL is
a *security product with opinions*, and a scanner needs a *measuring instrument without any*.

- **It will not offer a codepoint it does not implement.** OpenSSL's default client group list
  contains no pure ML-KEM, so a scanner that reads the negotiated group can never see
  ML-KEM-1024 support — the algorithm the ISM actually prefers.
- **It removed weak ciphers entirely.** OpenSSL 3.5 dropped 3DES, RC4, NULL and EXPORT from its
  TLS cipher list, so `ssl.SSLContext` cannot negotiate with a server that only speaks them at
  any security level. Those are the hosts a readiness report most needs to name, and the tool
  went silent on exactly them.
- **It cannot run everywhere.** Scanning must work on a machine with an old OpenSSL or none.

So measurement falls back through three layers: a strict `ssl.SSLContext`, then a permissive
one, then a raw ClientHello that has no opinions about what it will negotiate. The rule behind
it: **a measurement failure is a bug in the instrument, not a result.** Any time the tool says
"unknown", that is a gap until proven otherwise.

`pqc verify` cross-checks results against the `openssl` binary when one is present, and
independently recomputes the scores. That is the right use of OpenSSL here — a second opinion,
not a dependency.

## Adding a protocol

Three steps, one of them optional.

**1. Write the probe.** It takes a `Target` and a `ProbeContext` and returns a `HostFinding`.

```python
async def probe_mqtt(target: Target, context: ProbeContext) -> HostFinding:
    observation = await read_mqtt_connack(target.hostname, target.port, context.timeout)
    return HostFinding(
        target=target,
        service="mqtt",
        algorithms={"cipher": [{"name": observation.cipher,
                                "classification": context.engine.classify_mqtt(observation.cipher).value,
                                "in_use": True}]},
        not_testable_reason=observation.not_testable_reason,
        handshake_errors=observation.errors,
    )
```

**2. Register it and give it a port.**

```python
PROBES["mqtt"] = probe_mqtt          # pqc_scan/probes.py
```
```yaml
ports:
  8883: "mqtt"                       # pqc_scan/rules/port_map.yaml
```

`pqc selftest --offline` checks these two agree — the port map once advertised a protocol
nothing implemented, and every target on that port was silently unmeasured.

**3. Add its classifications to the rule profile**, with the ISM control that sets each one.

Then add a case to `pqc_scan/rules/selftest.yaml` so the live self-test covers it.

## Rules are data

`pqc_scan/rules/asd_ism.yaml` holds every algorithm classification with the ISM control behind
it. `scoring.yaml` holds the weights and the band definitions. `port_map.yaml` maps ports to
protocols. `selftest.yaml` holds the live test cases. Changing a position is a YAML edit and a
test run, not a code change — which matters because the ISM is reissued quarterly.

## Design rules that are load-bearing

These came from bugs, and each one has a test pinning it.

**A measurement failure is a bug, not a result.** If the tool says "unknown", the instrument
failed until proven otherwise. Several of the defects in the changelog were found by taking
this seriously rather than accepting an "unknown".

**Unmeasured is never compliant.** An endpoint that could not be reached gets no score, no band
and no pass. It must never satisfy a policy gate.

**Absence of evidence is not evidence of absence.** A DNS timeout on `_dmarc` is not "this
domain publishes no DMARC". Each lookup records whether it completed, and a control that could
not be observed is listed as not observed rather than charged as a breach.

**Say only what is true at the scale measured.** A distribution and an average are statements
about a population; printed over one host they repeat the row below them.

**Broad exception handlers hide real bugs.** A bare `except Exception` around a DNS lookup once
swallowed a `NameError` from a missing import and reported it as a DNS failure — the tool looked
like it was working and was not. Handlers name the failures they expect.

**The rules file is parsed, not trusted.** A bare `null` in a YAML list parses as a null value,
not the string `"null"`, which silently disabled the NULL-cipher check and let an unencrypted
endpoint score better than a 3DES one. `pqc selftest --offline` now checks for it.

## Hostile input

Every parser reads bytes from a server that may be hostile. All five are fuzzed, and a local
server that misbehaves on purpose — accepts and never speaks, hangs up mid-handshake, floods a
banner, declares a length far larger than its payload, fakes an SSH banner then talks nonsense —
runs in the test suite. Nothing may hang, crash, allocate on a declared length, or produce a
confident wrong answer.

Each host also has an overall time budget, because per-phase timeouts compose: an IKE cookie
retry nested inside an `INVALID_KE` retry could otherwise hold a scan slot for minutes.

## Layout

```
pqc_scan/
  cli.py            commands and flags
  probes.py         the probe registry and per-protocol probes
  collectors.py     TLS collection, STARTTLS preludes, certificate validation
  tls_probe.py      raw ClientHello, group and cipher enumeration
  ssh_probe.py      KEXINIT
  ike_probe.py      IKE_SA_INIT, including the cookie challenge
  domain_probe.py   DNS resolver, MTA-STS, HSTS
  discovery.py      which services a host is running
  scoring.py        scores and the readiness band
  parsers.py        certificate parsing and classification
  reporters.py      terminal and HTML
  exporters.py      the format registry
  cbom.py           CycloneDX
  checks.py         offline invariants
  selftest.py       live protocol cases
  rules/            the profile, weights, port map, control list, test cases
```
