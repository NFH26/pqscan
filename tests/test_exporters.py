"""Export formats: one registry, one writer each."""
import json

import pytest

from pqc_scan.checks import _sample
from pqc_scan.exporters import FORMATS, export, resolve
from pqc_scan.parsers import RuleEngine
from pqc_scan.reporters import Reporter

METADATA = {
    "operator": "tester", "engagement": "unit", "authorised": True, "probe_method": "native",
    "profile": "asd_ism", "rules_version": "test", "tool_version": "test", "scan_time": "now",
}


def _reporter(findings, certificates):
    engine = RuleEngine()
    return engine, Reporter(findings, certificates, engine.profile_name, engine=engine, metadata=METADATA)


def test_resolve_defaults_to_every_format():
    assert resolve(None) == list(FORMATS)
    assert resolve("all") == list(FORMATS)


def test_resolve_accepts_a_subset_and_ignores_spacing():
    assert resolve("json, sarif") == ["json", "sarif"]


def test_an_unknown_format_names_itself_and_the_alternatives():
    # A typo must not silently produce nothing; the message has to say what is available.
    with pytest.raises(ValueError) as error:
        resolve("jsonn")
    assert "jsonn" in str(error.value) and "cbom" in str(error.value)


def test_every_format_writes_a_non_empty_file(tmp_path):
    findings, certificates = _sample()
    engine, reporter = _reporter(findings, certificates)
    written = export(str(tmp_path), None, findings, certificates, engine, METADATA, reporter)
    assert len(written) == len(FORMATS)
    for path in written:
        assert path.exists() and path.stat().st_size > 0, path


def test_the_output_directory_is_created(tmp_path):
    findings, certificates = _sample()
    engine, reporter = _reporter(findings, certificates)
    nested = tmp_path / "a" / "b"
    export(str(nested), "json", findings, certificates, engine, METADATA, reporter)
    assert (nested / "findings.json").exists()


def test_json_round_trips_every_finding(tmp_path):
    findings, certificates = _sample()
    engine, reporter = _reporter(findings, certificates)
    export(str(tmp_path), "json", findings, certificates, engine, METADATA, reporter)
    payload = json.loads((tmp_path / "findings.json").read_text())
    assert len(payload["findings"]) == len(findings)
    assert payload["metadata"]["operator"] == "tester"


def test_sarif_is_structurally_valid(tmp_path):
    findings, certificates = _sample()
    engine, reporter = _reporter(findings, certificates)
    export(str(tmp_path), "sarif", findings, certificates, engine, METADATA, reporter)
    document = json.loads((tmp_path / "findings.sarif").read_text())
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    # Every result must reference a declared rule, or a dashboard drops it silently.
    assert {result["ruleId"] for result in run["results"]} <= declared
    assert all(result["level"] in {"error", "warning", "note"} for result in run["results"])


def test_markdown_has_a_row_for_every_finding(tmp_path):
    findings, certificates = _sample()
    engine, reporter = _reporter(findings, certificates)
    export(str(tmp_path), "md", findings, certificates, engine, METADATA, reporter)
    text = (tmp_path / "summary.md").read_text()
    for finding in findings:
        assert finding.target.hostname in text


def test_markdown_recommendations_name_their_endpoints(tmp_path):
    """The Markdown export is what gets pasted into a ticket, so it has to say which
    endpoint the change applies to and which service that endpoint runs."""
    findings, certificates = _sample()
    engine, reporter = _reporter(findings, certificates)
    export(str(tmp_path), "md", findings, certificates, engine, METADATA, reporter)
    text = (tmp_path / "summary.md").read_text()
    assert "## Recommendations" in text
    assert "Applies to:" in text
    actionable = [f for f in findings if not f.not_testable_reason]
    assert any(f"{f.target.hostname}:{f.target.port} ({f.service})" in text for f in actionable)


def test_every_registered_format_is_documented():
    for name, fmt in FORMATS.items():
        assert fmt.description and fmt.extension, name
        assert callable(fmt.writer), name
