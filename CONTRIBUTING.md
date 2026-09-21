# Contributing

Thank you for looking. This is a compliance tool, which shapes what a good contribution looks
like: a wrong measurement presented confidently is worse than no measurement at all, so the bar
is less about style and more about not being quietly wrong.

## Getting set up

```bash
git clone https://github.com/NFH26/pqscan.git
cd pqscan
./pqc setup
pqc test
```

Python 3.11 or newer. No other system dependency.

## Before you open a pull request

```bash
pqc test                  # unit tests, no network, about ten seconds
pqc selftest --offline    # rules, scoring invariants, output formats
pqc selftest              # live, every protocol (needs network)
./pqc lint
```

## The rules this project is strict about

Each came from a real bug and each has a test pinning it. The full list, with the defect behind
each rule, is in [docs/architecture.md](docs/architecture.md#design-rules-that-are-load-bearing).
Read it before your first change. The two that reviewers raise most often:

**Unmeasured is never compliant.** An endpoint that could not be reached gets no score, no band
and no pass, and must never satisfy a policy gate.

**Rules are data.** Classifications live in `pqc_scan/rules/*.yaml` next to the ISM control that
sets them. A classification change is a YAML edit and should cite its control.

**Comments explain why.** The code shows what it does. A comment earns its place by explaining
the reasoning, the constraint, or the bug that made the code look like this. Commit messages
follow the same rule.

## Adding a protocol

See [docs/architecture.md](docs/architecture.md#adding-a-protocol). Briefly: write a probe that
returns a `HostFinding`, register it in `PROBES`, give it a port in `port_map.yaml`, add its
classifications to the rule profile with their control numbers, and add a case to
`selftest.yaml`.

## Changing a rule or a classification

Please include the ISM wording you are relying on. The profile is a *reading* of the ISM and
readings can be wrong; two positions are already marked `verify:` for exactly that reason.

If a new ISM has been published, run `python tools/refresh_ism_controls.py` and include the
updated control list in the same pull request.

## Tests

- Unit tests live in `tests/` and must not touch the network.
- A live protocol case belongs in `pqc_scan/rules/selftest.yaml`, not in a unit test.
- Every parser reads attacker-controlled bytes. New parsing code needs a case in
  `tests/test_hostile_input.py`, and new connection handling needs one in
  `tests/test_hostile_server.py`.

## Reporting a security issue

Please do not open a public issue — see [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under Apache-2.0, the licence of this project.
