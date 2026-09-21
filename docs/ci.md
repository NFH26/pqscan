# CI and automation

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no policy gate failed |
| `1` | A policy gate failed, or authorisation was not confirmed |
| `2` | Bad input — no targets, an unknown format, a scope file that excluded everything |
| `70` | Internal error. This is a bug; please [report it](https://github.com/NFH26/pqscan/issues) |

## Policy gates

Gates turn a scan into a build step. Each one exits `1` and names the endpoint that failed.

```bash
# fail if anything scores worse than 50
pqc scan --input hosts.csv -y --fail-on-score 50

# fail if any certificate chain is unapproved
pqc scan --input hosts.csv -y --fail-on-class NOT_APPROVED

# fail unless every measurable endpoint negotiates post-quantum
pqc scan --input hosts.csv -y --require-hybrid-kex
```

Despite the name, `--require-hybrid-kex` gates on a post-quantum key exchange of any kind,
hybrid or pure. It exempts `domain` rows, which have no key exchange to judge, and endpoints
that could not be measured — an unreachable host must not pass a gate, and must not fail one
either. Use `--fail-on-score` if you want unreachable hosts to be loud.

## GitHub Actions

```yaml
name: post-quantum readiness
on:
  schedule: [{cron: "0 19 * * 0"}]   # Monday 05:00 Brisbane
  workflow_dispatch:

permissions:
  contents: read
  security-events: write             # for the SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.13"}
      - run: pip install .
      - name: Scan
        run: |
          pqc scan --input hosts.csv \
            --operator "${{ github.actor }}" \
            --engagement "${{ github.run_id }}" \
            --confirm-authorised \
            --out reports/ --flat \
            --fail-on-score 75
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/findings.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pqscan-reports
          path: reports/
```

`if: always()` matters: when the gate fails you want the reports most.

## Scheduling

Weekly is the right cadence for an estate. The thing you are watching for is drift — a
certificate renewed onto a weaker algorithm, a load balancer replaced with different defaults, a
new host that nobody added to the inventory. `--discover` is worth running monthly against your
main domains for the same reason.

## Verifying the tool in CI

```bash
pqc selftest --offline   # no network, about a second
pqc selftest             # live, every protocol
pqc selftest --strict    # unreachable endpoints count as failures
```

`--offline` belongs in a pre-commit hook and in any pipeline that changes the rule profile: it
checks the profile is coherent, the scoring invariants hold, every output format is well formed,
and every ISM control number cited still exists in ASD's catalog.

Use plain `selftest` on a runner with open egress. Without `--strict`, endpoints this network
cannot reach are reported as skipped rather than failed — outbound UDP 500 and port 21 are
commonly filtered, and a rate-limited public test server is not a defect in your scanner.

## Machine-readable output

```bash
pqc scan --input hosts.csv -y -o out/ --flat -f json

# every endpoint that is capable but not using it
jq -r '.findings[] | select(.readiness_band == 3) | .target.hostname' out/findings.json

# worst first
jq -r '.findings | sort_by(-.confidentiality_score)[] |
       [.target.hostname, .confidentiality_score] | @tsv' out/findings.json
```
