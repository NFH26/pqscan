## What this changes

<!-- One or two sentences. If it fixes an issue, "Fixes #123". -->

## Why

<!-- The reasoning belongs here and, for anything non-obvious, in a comment in the code.
     This project's commits explain *why*; a diff already shows *what*. -->

## Checklist

- [ ] `pqc test` passes
- [ ] `pqc selftest --offline` passes
- [ ] New behaviour has a test that would fail without the change
- [ ] A rule or classification change cites the ISM control it is based on
- [ ] A new protocol is registered in `PROBES`, given a port in `port_map.yaml`, and has a
      case in `selftest.yaml`
- [ ] No measurement can now fail silently — a failure is reported, never assumed compliant
