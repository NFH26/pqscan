"""tools/release.py: the pure parts. The git and network steps are exercised by --dry-run."""
import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parent.parent / "tools" / "release.py"
_spec = importlib.util.spec_from_file_location("release", _PATH)
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)


@pytest.mark.parametrize(("current", "bump", "expected"), [
    ("0.5.1", "patch", "0.5.2"),
    ("0.5.1", "minor", "0.6.0"),
    ("0.5.1", "major", "1.0.0"),
    ("0.5.9", "patch", "0.5.10"),
    ("0.5.1", "0.7.0", "0.7.0"),
    (None, "0.1.0", "0.1.0"),
])
def test_next_version(current, bump, expected):
    assert release.next_version(current, bump) == expected


@pytest.mark.parametrize(("current", "bump"), [
    ("0.5.1", "0.5.1"),     # already released
    ("0.5.1", "0.4.9"),     # going backwards
    ("0.5.1", "v0.6.0"),    # the tag, not the version
    ("0.5.1", "big"),
    (None, "patch"),        # nothing to bump from
])
def test_next_version_refuses_what_cannot_be_right(current, bump):
    with pytest.raises(release.Stop):
        release.next_version(current, bump)


CHANGELOG = """# Changelog

## [Unreleased]

### Fixed

- AES-128 is flagged on TLS 1.3.

## [0.5.1] - 2026-11-21

- Earlier.
"""


def test_unreleased_notes_stop_at_the_previous_release():
    notes = release.unreleased_notes(CHANGELOG)
    assert notes.startswith("### Fixed")
    assert "AES-128" in notes
    assert "Earlier" not in notes


def test_an_empty_unreleased_section_has_no_notes():
    assert release.unreleased_notes("# Changelog\n\n## [Unreleased]\n\n## [0.5.1] - x\n- a\n") == ""
    assert release.unreleased_notes("# Changelog\n\n## [0.5.1] - x\n- a\n") == ""


def test_stamping_moves_the_notes_under_the_new_version():
    stamped = release.stamp_changelog(CHANGELOG, "0.5.2", "2026-11-22")
    assert "## [Unreleased]\n\n## [0.5.2] - 2026-11-22\n\n### Fixed" in stamped
    # The next round starts empty, and the release itself must now carry the entry the
    # offline self-test looks for.
    assert release.unreleased_notes(stamped) == ""
    assert "0.5.2" in stamped
    assert stamped.count("## [0.5.1]") == 1


@pytest.mark.parametrize("url", [
    "https://github.com/NFH26/pqscan.git",
    "https://github.com/NFH26/pqscan",
    "git@github.com:NFH26/pqscan.git",
])
def test_github_slug(url):
    assert release.github_slug(url) == "NFH26/pqscan"
