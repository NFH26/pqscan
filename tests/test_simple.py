"""The plain default: `pqc example.com`, a permission question, one verdict per endpoint."""
import contextlib
import sys

import pytest

from pqc_scan import cli, collectors, probes
from pqc_scan.models import HostFinding, Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.reporters import Reporter


@pytest.mark.parametrize(("argv", "expected"), [
    (["pqc", "example.com"], ["pqc", "scan", "example.com"]),
    (["pqc", "--input", "hosts.csv", "-y"], ["pqc", "scan", "--input", "hosts.csv", "-y"]),
    (["pqc", "-y", "example.com"], ["pqc", "scan", "-y", "example.com"]),
    (["pqc", "scan", "example.com"], ["pqc", "scan", "example.com"]),
    (["pqc", "doctor"], ["pqc", "doctor"]),
    (["pqc", "--help"], ["pqc", "--help"]),
    (["pqc"], ["pqc"]),
])
def test_scan_is_the_default_command(monkeypatch, argv, expected):
    seen = {}
    monkeypatch.setattr(sys, "argv", list(argv))
    monkeypatch.setattr(cli, "app", lambda **kwargs: seen.setdefault("argv", list(sys.argv)))
    cli.main()
    assert seen["argv"] == expected


def _targets(n):
    return [Target(hostname=f"host{i}.example") for i in range(n)]


def test_without_a_terminal_consent_still_needs_y(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as exit_info:
        cli._ask_permission(_targets(1), None)
    assert exit_info.value.code == 1
    assert "-y" in capsys.readouterr().out


def test_answering_no_scans_nothing(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    asked = {}
    monkeypatch.setattr(cli.typer, "confirm", lambda text, default: asked.setdefault("q", text) and False)
    with pytest.raises(SystemExit) as exit_info:
        cli._ask_permission(_targets(3), "hosts.csv")
    assert exit_info.value.code == 1
    assert asked["q"] == "Scan 3 hosts from hosts.csv?"
    assert "Nothing was scanned" in capsys.readouterr().out


def test_answering_yes_allows_the_scan(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda text, default: True)
    assert cli._ask_permission(_targets(1), None) is True


def _finding(host, band, readiness="classical_only", rules=(), port=443, protocol="tls", **extra):
    finding = HostFinding(target=Target(hostname=host, port=port, protocol=protocol))
    finding.readiness_band = band
    finding.pq_readiness = readiness
    finding.rule_findings = list(rules)
    for key, value in extra.items():
        setattr(finding, key, value)
    return finding


def _simple_output(findings, capsys):
    Reporter(findings, {}, "asd_ism", engine=RuleEngine(), simple=True).write_terminal()
    return " ".join(capsys.readouterr().out.split())


def test_simple_view_gives_one_plain_verdict_and_fix(capsys):
    out = _simple_output([
        _finding("capable.example", 3, rules=["capability_exceeds_default_negotiation"]),
        _finding("hybrid.example", 4, readiness="hybrid_transitional"),
        _finding("weak.example", 0, rules=["obsolete_tls"]),
        _finding("gone.example", None, readiness="unknown", not_testable_reason="dns_failure"),
    ], capsys)

    # Band 3 is the point of the tool: the server can already do it, so the fix is the
    # preference order, not "enable post-quantum".
    assert "Quick fix" in out and "Reorder the server's group preference" in out
    assert "Almost ready" in out and "ML-KEM-1024" in out
    # Weak today is fixed before post-quantum is even possible.
    assert "Unsafe today" in out and "Disable TLS 1.0 and 1.1" in out
    assert "Not measured" in out and "Could not find this host" in out
    assert "4 endpoints checked" in out
    # The expert vocabulary stays behind --details.
    assert "Conf risk" not in out and "Recommendations" not in out


def test_simple_view_names_a_website_the_way_a_person_types_it(capsys):
    out = _simple_output([
        _finding("www.example.com", 2),
        _finding("example.com", None, readiness="not_applicable", port=0, protocol="domain"),
    ], capsys)
    assert "www.example.com:443" not in out
    assert "example.com (email/web)" in out


def test_scan_writes_one_html_report_by_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    class FakeCollector:
        def __init__(self, **kwargs):
            pass

        async def collect_tls(self, target):
            return collectors.HostObservation(
                tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", negotiated_group="X25519",
            )

        async def probe_pq_groups(self, target, tls_version, negotiated_group, supported_groups=None):
            return [], "not_supported", []

    monkeypatch.setattr(probes, "NativeTLSCollector", FakeCollector)
    monkeypatch.setattr(cli.Reporter, "write_terminal", lambda self: None)

    # The fake collector yields no scores, so the scan ends "nothing measured" and exits.
    # The report is written before that check, which is the behaviour under test.
    with contextlib.suppress(SystemExit):
        cli.scan(
            target="good.example", input_file=None, protocol=None, discover_services=False,
            operator="t", engagement="t", profile="asd_ism", rate_limit=100.0,
            verbose=False, explain=False, wide=False, deep=False, fail_on_score=None,
            fail_on_class=None, require_hybrid_kex=False, cache_dir=str(tmp_path / "cache"),
            scope_file=None, confirm_authorised=True, report_dir=None, json_out=None,
            cbom_out=None, out_dir=None, formats=None, flat=False,
        )

    reports = list((tmp_path / "reports").glob("good.example-*.html"))
    assert len(reports) == 1
    assert "good.example" in reports[0].read_text()
