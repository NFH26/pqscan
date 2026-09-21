# Release checklist

Not part of the published documentation. Delete this file, or keep it out of the repo, once
the first release is out.

## Before the first push to GitHub

**1. History is clean.** The repository was re-initialised, so the ISM PDF that was once
committed under `Ref/` is gone with the old history. `Ref/` is in `.gitignore`. Confirm before
pushing, and confirm nothing local slipped in:

```bash
git rev-list --all --objects | grep -c "Ref/"   # must be 0
git ls-files | grep -Ei "ref/|linkedin|test-plan|reports/"   # must be empty
```

If you ever restore an older clone, the PDF is back in its history; delete that clone rather
than pushing it.

**2. Set the repository URL.** The docs assume
`https://github.com/nayefalharbi/pqscan`. If your username or repository name differs:

```bash
grep -rl "nayefalharbi/pqscan" --include="*.md" --include="*.yml" --include="*.py" --include="*.toml" . \
  | xargs sed -i.bak 's|nayefalharbi/pqscan|YOUR-USER/YOUR-REPO|g' && find . -name '*.bak' -delete
```

**3. Check the author name and email on every commit** if you are publishing history:

```bash
git log --format='%an <%ae>' | sort -u
```

## Repository settings after the first push

- Description: *Post-quantum readiness scanning for TLS, SSH, IPsec and email, scored against
  the ASD ISM.*
- Topics: `post-quantum`, `pqc`, `ml-kem`, `tls`, `ssh`, `ipsec`, `security-scanner`,
  `compliance`, `asd-ism`, `cbom`, `australia`
- Enable Issues and Discussions. Disable Wiki and Projects until you need them.
- Settings > Security: enable private vulnerability reporting, so `SECURITY.md` has somewhere
  to point.
- Branches: protect `main`, require the `ci` check to pass.
- Actions: allow only actions from GitHub and verified creators.

## First release

```bash
./pqc test && ./pqc selftest && ./pqc lint
git tag -a v0.4.0 -m "PQScan 0.4.0"
git push origin main --tags
```

The release workflow builds, refuses to release if the tag and the packaged version disagree,
and creates the GitHub release with the wheel and sdist attached.

**No PyPI.** Installation is a clone and `./pqc setup`, so the GitHub page is the one place
people land. If you want `pip install pqc-scan` later, register a trusted publisher at
<https://pypi.org/manage/account/publishing/> for project `pqc-scan`, repository `pqscan`,
workflow `release.yml`, environment `pypi`, create that environment under Settings >
Environments, and add a job to `release.yml` running `pypa/gh-action-pypi-publish` against the
existing build.

## Worth doing soon, not before launch

- A short asciinema recording of `pqc selftest` in the README. Thirty seconds of real output is more
  convincing than any description of it.
- Drift tracking between scans. Every scan is currently a
  fresh snapshot with nothing to compare against.
- A published quarterly `.au` readiness benchmark. Nobody publishes one, and it would make this
  the reference dataset.
