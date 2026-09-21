# Security policy

## Reporting a vulnerability

Please report privately through
[GitHub Security Advisories](https://github.com/nayefalharbi/pqscan/security/advisories/new)
rather than opening a public issue.

Please include what an attacker could do, how to reproduce it, and the version from
`pqc doctor`. You will get an acknowledgement within a few days and an assessment within two
weeks. If a fix is warranted you will be credited in the advisory and the changelog unless you
prefer otherwise.

## Supported versions

The latest released version. This is a young project; there is no long-term support branch yet.

## What counts as a vulnerability here

This tool connects to endpoints and reads what they send, so the interesting attack surface is
a **malicious or compromised server attacking the scanner**:

- A crafted response that crashes, hangs or exhausts memory in the TLS, SSH, IKEv2 or DNS
  parsers.
- Anything that causes the tool to write outside its output directory, or to execute or
  interpret data it received from the network.
- A response that makes the tool report a **confidently wrong result** — for instance a
  non-compliant endpoint scoring as compliant. In a compliance tool this is a security issue,
  not a correctness nit.

All five parsers — TLS, SSH, IKEv2, DNS and X.509 certificates — are fuzzed and there is a deliberately hostile server in the test suite, but
neither is proof of absence.

## What is not a vulnerability

- Scanning a host you are not authorised to scan. The `--confirm-authorised` flag exists
  precisely so that this is your decision and your responsibility.
- A finding you disagree with because of how the ISM is read. Please open a
  [rule correction](https://github.com/nayefalharbi/pqscan/issues/new?template=rule_correction.yml)
  instead — those are welcome and useful.
- Weaknesses in the endpoints you scan. Reporting those is the point of the tool.

## Handling of scan data

PQScan sends nothing anywhere. It has no telemetry, no update check and no network access beyond
the endpoints you name. Reports are written only where you point `--out`.

Reports contain hostnames, certificate details and configuration weaknesses, which makes them
sensitive. The HTML report is self-contained and requests nothing external, so opening one does
not tell anyone that you read it.
