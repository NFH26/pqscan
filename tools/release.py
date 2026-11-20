#!/usr/bin/env python3
"""Release PQScan in one step: checks, changelog, commit, tag, push, then wait for PyPI.

    ./pqc release            # next patch version, e.g. 0.5.1 -> 0.5.2
    ./pqc release minor      # 0.5.1 -> 0.6.0
    ./pqc release 0.6.0      # an exact version
    ./pqc release --dry-run  # show what would happen, change nothing

Pushing a v* tag is what publishes: the release workflow builds the package, uploads it to
PyPI and creates the GitHub release. The version comes from that tag, so there is no version
number to edit anywhere. What used to go wrong was everything around the tag: a forgotten
changelog entry, a tag pushed without main, a version typed by hand. This script does those
steps in order and refuses to start when something is off.

Before anything changes it checks: on main, nothing uncommitted, not behind GitHub, the tag
is new, the changelog says what changed, and the tests, lint and offline self-test pass.
Then it moves the [Unreleased] notes under the new version, commits, tags, and pushes main
and the tag together (atomic: both or neither). Finally it waits until PyPI serves the new
version, so "done" means installable, not just pushed.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
UNRELEASED = "## [Unreleased]"
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


class Stop(Exception):
    """A precondition failed. The message says what to do about it."""


# --- pure helpers (tested in tests/test_release.py) ------------------------------------------

def next_version(current: str | None, bump: str) -> str:
    """The version to release. `bump` is patch, minor, major or an exact X.Y.Z."""
    if VERSION.match(bump):
        if current and _key(bump) <= _key(current):
            raise Stop(f"{bump} is not newer than the last release, {current}.")
        return bump
    if bump not in ("patch", "minor", "major"):
        raise Stop(f"Unknown version '{bump}'. Use patch, minor, major or a number like 0.6.0.")
    if current is None:
        raise Stop("No earlier release tag found. Give the first version, e.g. ./pqc release 0.1.0.")
    major, minor, patch = _key(current)
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def unreleased_notes(changelog: str) -> str:
    """The text under ## [Unreleased], up to the next release heading."""
    if UNRELEASED not in changelog:
        return ""
    body = changelog.split(UNRELEASED, 1)[1]
    return re.split(r"^## \[", body, maxsplit=1, flags=re.MULTILINE)[0].strip()


def stamp_changelog(changelog: str, version: str, date: str) -> str:
    """Move the [Unreleased] notes under a heading for `version`, and leave an empty
    [Unreleased] on top for the next round."""
    return changelog.replace(UNRELEASED + "\n", f"{UNRELEASED}\n\n## [{version}] - {date}\n", 1)


def github_slug(remote_url: str) -> str | None:
    """owner/repo from an https or ssh GitHub remote."""
    found = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", remote_url.strip())
    return found.group(1) if found else None


# --- git and the outside world -----------------------------------------------------------

def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise Stop(f"git {' '.join(args)} failed:\n{(result.stderr or result.stdout).strip()}")
    return result.stdout.strip()


def last_release_tag() -> str | None:
    try:
        return git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*")
    except Stop:
        return None


def on_pypi(package: str, version: str) -> bool:
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            return json.load(response).get("info", {}).get("version") == version
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def run_checks() -> None:
    steps = [
        ("tests", [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]),
        ("lint", [sys.executable, "-m", "ruff", "check", "."]),
        ("types", [sys.executable, "-m", "mypy", "pqc_scan/"]),
        ("offline self-test", [sys.executable, "-m", "pqc_scan.cli", "selftest", "--offline"]),
    ]
    for name, command in steps:
        print(f"  {name} ...", end=" ", flush=True)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            print("FAILED")
            tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-25:])
            raise Stop(f"The {name} failed, so nothing was released.\n\n{tail}")
        print("ok")


# --- the release ------------------------------------------------------------------------------

def release(bump: str, assume_yes: bool, skip_checks: bool, wait: bool, dry_run: bool) -> int:
    package = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["name"]
    slug = github_slug(git("remote", "get-url", "origin")) or "NFH26/pqscan"

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch != "main":
        raise Stop(f"You are on '{branch}'. Releases are made from main: git switch main")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise Stop("There are uncommitted changes. Commit or stash them first, then run this again.")
    git("fetch", "--quiet", "--tags", "origin")
    behind = int(git("rev-list", "--count", "HEAD..origin/main"))
    if behind:
        raise Stop(f"main is {behind} commit(s) behind GitHub. Run git pull first.")

    previous = last_release_tag()
    version = next_version(previous.removeprefix("v") if previous else None, bump)
    tag = f"v{version}"
    if subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
                      cwd=ROOT, capture_output=True).returncode == 0:
        raise Stop(f"The tag {tag} already exists here. Pick another version.")
    if git("ls-remote", "--tags", "origin", tag):
        raise Stop(f"The tag {tag} already exists on GitHub. Pick another version.")

    changelog = CHANGELOG.read_text(encoding="utf-8")
    notes = unreleased_notes(changelog)
    if not notes:
        raise Stop(
            "CHANGELOG.md has nothing under '## [Unreleased]'. Write what changed there first:\n"
            "that text becomes the release notes."
        )
    commits = git("log", "--oneline", f"{previous}..HEAD") if previous else git("log", "--oneline", "-10")

    print(f"\nRelease {package} {version}  (last release: {previous or 'none'})\n")
    print("Commits since then:")
    print("\n".join(f"  {line}" for line in commits.splitlines()) or "  none")
    print("\nRelease notes (from CHANGELOG.md):")
    print("\n".join(f"  {line}" for line in notes.splitlines()))
    print()

    if not skip_checks:
        print("Checking before anything changes:")
        run_checks()
        print()

    if dry_run:
        print(f"Dry run: would commit the changelog, tag {tag}, push main and {tag}, "
              f"then wait for {package} {version} on PyPI. Nothing was changed.")
        return 0

    if not assume_yes:
        if not sys.stdin.isatty():
            raise Stop("No terminal to confirm on. Add --yes to release without asking.")
        answer = input(f"Publish {package} {version} to GitHub and PyPI? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Nothing was changed.")
            return 1

    today = datetime.datetime.now(tz=datetime.UTC).astimezone().date().isoformat()
    CHANGELOG.write_text(stamp_changelog(changelog, version, today), encoding="utf-8")
    git("add", "CHANGELOG.md")
    git("commit", "--quiet", "-m", f"PQScan {version}")
    git("tag", "-a", tag, "-m", f"PQScan {version}")

    # Both or neither. A tag on GitHub whose commit is not on main, or main without its tag,
    # is the half-finished state this script exists to prevent.
    pushed = subprocess.run(["git", "push", "--atomic", "origin", "HEAD:main", f"refs/tags/{tag}"],
                            cwd=ROOT, capture_output=True, text=True)
    if pushed.returncode != 0:
        # Put things back as they were: the tree was clean before, and only the changelog
        # commit and the tag were added.
        subprocess.run(["git", "tag", "-d", tag], cwd=ROOT, capture_output=True)
        subprocess.run(["git", "reset", "--quiet", "--hard", "HEAD~1"], cwd=ROOT, capture_output=True)
        raise Stop(
            "The push was refused, so nothing was published. The local changelog commit and tag\n"
            f"have been undone.\n\n{(pushed.stderr or pushed.stdout).strip()}"
        )

    actions = f"https://github.com/{slug}/actions/workflows/release.yml"
    print(f"Pushed main and {tag}. The release workflow is building it now:\n  {actions}\n")
    if not wait:
        print(f"Not waiting for PyPI. Check https://pypi.org/project/{package}/{version}/ in a few minutes.")
        return 0

    print(f"Waiting for {package} {version} on PyPI (usually 1 to 3 minutes)", end="", flush=True)
    deadline = time.monotonic() + 15 * 60
    while time.monotonic() < deadline:
        if on_pypi(package, version):
            print(" live.\n")
            print(f"{package} {version} is on PyPI and GitHub.")
            print(f"  https://pypi.org/project/{package}/{version}/")
            print(f"  https://github.com/{slug}/releases/tag/{tag}")
            print(f"Upgrade with: pipx upgrade {package}")
            return 0
        print(".", end="", flush=True)
        time.sleep(15)
    print(" not yet.\n")
    print(f"{version} is not on PyPI after 15 minutes. The workflow run says why:\n  {actions}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="./pqc release",
        description="Check, tag and publish a new PQScan release to GitHub and PyPI.",
    )
    parser.add_argument("version", nargs="?", default="patch",
                        help="patch (default), minor, major, or an exact version like 0.6.0")
    parser.add_argument("-y", "--yes", action="store_true", help="do not ask before publishing")
    parser.add_argument("--dry-run", action="store_true", help="run the checks and show the plan only")
    parser.add_argument("--skip-checks", action="store_true", help="skip tests, lint and the self-test")
    parser.add_argument("--no-wait", action="store_true", help="do not wait for PyPI after pushing")
    args = parser.parse_args()
    try:
        return release(args.version, args.yes, args.skip_checks, not args.no_wait, args.dry_run)
    except Stop as stop:
        print(f"\n{stop}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
