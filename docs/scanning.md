# Scanning

## Targets

Three ways to say what to scan.

```bash
pqc scan example.com -y                 # one host, protocol from the port
pqc scan example.com:22 -y              # explicit port
pqc scan --input hosts.csv -y           # a host file
```

The protocol is chosen from the port when you do not name one. A port is a convention rather
than a contract, so a wrong guess recovers: if the TLS probe fails at the record layer, PQScan
reads the server's greeting and retries with the protocol it actually speaks. `ssh.github.com:443`
is measured as SSH with no annotation from you.

To force it:

```bash
pqc scan example.com -y --protocol domain
pqc scan example.com -y -p starttls:smtp
```

Valid protocols: `tls`, `ssh`, `ipsec`, `domain`, and `starttls:` plus `smtp`, `imap`, `pop3`,
`ftp`, `ldap` or `postgres`.

## Discovery

```bash
pqc scan example.com -y --discover
```

Given a hostname, PQScan asks the host which of the 24 ISM-relevant ports are live, identifies
each service from its greeting, and measures them all — plus the domain's email and web
transport controls. The ports an operator forgets to list are the ones still running TLS 1.0 or
an SSH daemon nobody owns, so asking the host beats asking the person.

It is **not** a port scanner. It tries a short list of ports the ISM has something to say about,
one connection each, and never sweeps a range.

A public host you can try it on is `sdf.org`, a free shell provider that has run for decades:

```bash
pqc scan sdf.org -y --discover
```

`sdf.org` answers SSH on port 22, and on 110, 143 and 993 as well - ports a port map would have
read as POP3 and IMAP. PQScan identifies each service from its greeting rather than from its port number,
so all four come back as SSH and are measured as SSH. That is the case a scan driven by a
port list gets wrong.

## Host files

CSV with a header row. Only `hostname` is required. Copy
[`examples/hosts.csv`](../examples/hosts.csv) for your own estate, or run
[`examples/testbed.csv`](../examples/testbed.csv) to see the tool work against public endpoints
with a known answer.

```csv
hostname,port,protocol,owner,system_name,criticality,data_lifetime_years,classification
www.example.com,443,tls,Web team,Public website,medium,3,OS
mail.example.com,587,starttls:smtp,IT,Mail submission,high,7,OS
vpn.example.com,500,ipsec,Network,Remote access,high,10,OS
example.com,0,domain,IT,Email controls,medium,5,OS
```

| Column | Effect |
|---|---|
| `hostname` | Required |
| `port` | Chooses the protocol when `protocol` is blank. `0` means "no port", used by `domain` |
| `protocol` | Overrides the port map |
| `owner`, `system_name` | Carried into the report, so a finding has a name and a team |
| `criticality` | `low` (×0.7), `medium` (×1.0), `high` (×1.3) — multiplies the score |
| `data_lifetime_years` | Raises confidentiality risk past 5 and again past 10 years. This is the harvest-now-decrypt-later dimension: data that must stay secret until 2040 is at risk from a machine built in 2035 |
| `classification` | `NC`, `OS`, `P`, `S`, `TS` — selects the curve rules ASD sets for that level |

Lines beginning with `#` are comments.

## Flags

### Selecting and shaping

| Flag | Effect |
|---|---|
| `--input FILE` | CSV or plain list of hosts |
| `--protocol`, `-p` | Force the protocol for the target |
| `--discover` | Find and measure every service on each host |
| `--profile NAME` | Rule profile to score against (default `asd_ism`) |
| `--scope-file FILE` | Hostnames or domain suffixes you are authorised to scan; anything else is skipped |

### Measurement

| Flag | Effect |
|---|---|
| `--deep` | Also test which cipher suites each host *accepts*, not just the one it prefers. One connection per suite — slower, and the only way to find a server that leads with AES-GCM and still accepts 3DES |
| `--no-pq-probe` | Skip the capability probe. Faster, but you lose band 3 |
| `--timeout SECONDS` | Per operation, default 10 |
| `--concurrency N` | Hosts in parallel, default 10 |
| `--rate-limit N` | Maximum connections per second per host |

### Output

| Flag | Effect |
|---|---|
| `--out DIR`, `-o` | Write reports into a dated subfolder of `DIR` |
| `--format LIST`, `-f` | `all` (default) or a subset of `html,csv,json,cbom,sarif,md` |
| `--flat` | Write straight into `--out` instead of a dated subfolder |
| `--wide` | Show every column |
| `--explain` | Print the full score breakdown per host |

### Policy gates

See [CI and automation](ci.md).

| Flag | Effect |
|---|---|
| `--fail-on-score N` | Exit 1 if any score exceeds N |
| `--fail-on-class CLASS` | Exit 1 if any certificate chain has this classification |
| `--require-hybrid-kex` | Exit 1 unless every measurable endpoint negotiates post-quantum. The name is historical; the gate accepts hybrid or pure |

## Scanning responsibly

- `-y` is required, and it is an assertion about authorisation, not a formality.
- `--scope-file` is the guard rail for an engagement: list the domains in the statement of work
  and anything outside it is skipped rather than scanned.
- `--rate-limit` matters on shared infrastructure. Several public test services rate-limit, and
  PQScan reports that as *not reachable* rather than as a finding.
- Every scan records the operator, the engagement reference and the timestamp in every report,
  so a report carries its own provenance.
