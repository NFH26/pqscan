# Release checklist

Not part of the published documentation. Delete this file, or keep it out of the repo, once
the first release is out.

## Before the first push to GitHub

**1. The ISM PDF is still in git history.**

It is no longer tracked, but it exists in 2 past commits and would be published with the
repository. It is Commonwealth copyright and not yours to redistribute. Pick one:

```bash
# Option A - start clean. Simplest, and 92 commits of history are not what gets you hired.
rm -rf .git
git init -b main
git add -A
git commit -m "PQScan 0.4.0"

# Option B - keep the history, strip the file.
pipx install git-filter-repo
git filter-repo --path Ref --invert-paths
```

Verify either way:

```bash
git rev-list --all --objects | grep -c "Ref/"   # must be 0
```

**2. Set the repository URL.** The docs assume
`https://github.com/nayefalharbi/pqscan`. If your username or repository name differs:

```bash
grep -rl "nayefalharbi/pqscan" --include="*.md" --include="*.yml" --include="*.py" --include="*.toml" . \
  | xargs sed -i '' 's|nayefalharbi/pqscan|YOUR-USER/YOUR-REPO|g'
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

The release workflow builds, refuses to publish if the tag and the packaged version disagree,
creates the GitHub release, and publishes to PyPI.

**PyPI needs one manual step first.** Trusted publishing means no token is stored anywhere, but
the publisher has to be registered before the first upload. At
<https://pypi.org/manage/account/publishing/>, add a pending publisher:

| Field | Value |
|---|---|
| PyPI project name | `pqc-scan` |
| Owner | your GitHub username |
| Repository | `pqscan` |
| Workflow | `release.yml` |
| Environment | `pypi` |

Then create the `pypi` environment under Settings > Environments in the repository.

## Worth doing soon, not before launch

- A short asciinema recording of `pqc selftest` in the README. It is the most convincing
  thirty seconds this project has.
- Drift tracking between scans. The 2030 deadline is the pitch, and right now every scan is a
  fresh snapshot with nothing to compare against.
- A published quarterly `.au` readiness benchmark. Nobody publishes one, and it would make this
  the reference dataset.
