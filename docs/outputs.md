# Output formats

```bash
pqc scan --input hosts.csv -y -o reports/              # every format
pqc scan --input hosts.csv -y -o reports/ -f sarif,md  # just these
```

Each run writes into its own dated subfolder — `reports/20260921-011457-ACME-2026/` — because a
compliance report is evidence, and evidence that a later run silently replaced is not evidence.
`--flat` writes straight into the directory instead.

| Format | File | For |
|---|---|---|
| `html` | `report.html` | A person. Self-contained, light and dark, per-host remediation |
| `csv` | `findings.csv` | A spreadsheet |
| `json` | `findings.json` | Another tool |
| `cbom` | `cbom.json` | CycloneDX cryptographic bill of materials |
| `sarif` | `findings.sarif` | CI and code-scanning dashboards |
| `md` | `summary.md` | A ticket, an email, a pull request comment |

## HTML

Self-contained: no external requests, so opening a report does not tell anyone that you read it,
so it opens safely on an isolated network. Renders in light and dark. Carries the full remediation
advice per host, the certificate inventory, and the scan's provenance — operator, engagement,
timestamp, rule version, and which probe produced each result.

## JSON

Everything the scan observed, including the fields the terminal has no room for: every
algorithm with its classification, the full score explanations, certificate details, the
capability probe results, and per-host errors.

```bash
jq '.findings[] | select(.readiness_band <= 1) | .target.hostname' findings.json
```

## CBOM

A [CycloneDX 1.6](https://cyclonedx.org/) **Cryptographic Bill of Materials** — an inventory of
the cryptography in use, the way an SBOM is an inventory of software. It lists algorithms,
protocols and certificates as components, with key sizes, NIST security categories and the
endpoints each certificate serves.

ASD names the CBOM in **ISM-2082** and **ISM-2083**, and the June 2026 US executive order
directed CISA to define its minimum elements. Both matter if you sell software or sell into US
federal.

Two things make this document different from a CBOM produced by a source-code scanner, and both
are stated in its metadata rather than implied:

- **It is built from observed negotiation, not declared dependencies.** Every algorithm records
  whether it was `negotiated` or merely `offered`. A source scan cannot make that distinction:
  it can tell you a library supports ML-KEM, not whether your server ever uses it.
- **Each certificate lists every endpoint that served it.** That is what makes the document
  actionable — it answers *what breaks when this key has to be replaced*.

The scoping caveat, stated plainly because overclaiming here is easy: ISM-2082 and ISM-2083 sit
in the *Guidelines for software development*. They bind an organisation as a software
**producer**. This document makes an adjacent claim — an inventory of deployed endpoints — and
says so in `metadata.properties`.

## SARIF

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/), so findings appear natively in CI and code-scanning dashboards. Each distinct finding becomes a SARIF rule carrying its ISM control
number, and severity maps from the confidentiality score: `error` at 75 and above, `warning` at
40, otherwise `note`.

```yaml
- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/findings.sarif
```

## Markdown

A table with endpoint, service, key exchange, readiness, band, both scores and the findings,
ordered worst first. Written to be pasted rather than read as a file.

## Adding a format

`pqc_scan/exporters.py` is a registry: findings in, one file out.

```python
def write_yaml(path, findings, certificates, engine, metadata, reporter=None):
    path.write_text(yaml.safe_dump(_payload(findings, certificates, metadata)))

FORMATS["yaml"] = Format("findings.yaml", write_yaml, "YAML, for people who prefer it")
```

A function and a dict entry. Nothing else in the tool changes, and
`pqc selftest --offline` will check the new format produces a well-formed file.
