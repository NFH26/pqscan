import json

from pqc_scan.models import Classification, HostFinding, Target
from pqc_scan.reporters import Reporter


def test_reporters_generate_files(tmp_path):
    f = HostFinding(target=Target(hostname="test.local", port=443, criticality="low"))
    r = Reporter([f], {}, "test_profile")
    r.write_csv(tmp_path / "out.csv")
    r.write_html(tmp_path / "out.html")
    assert (tmp_path / "out.csv").exists()
    assert (tmp_path / "out.html").exists()


def test_write_terminal_contains_host_name(capsys):
    finding = HostFinding(
        target=Target(hostname="scored.example", port=443, criticality="low"),
        negotiated_group="X25519",
        confidentiality_score=12,
        authentication_score=8,
        chain_classification=Classification.NOT_APPROVED_AFTER_2030,
    )
    finding.pq_readiness = "classical_only"
    unmeasured = HostFinding(target=Target(hostname="unmeasured.example", port=443))

    reporter = Reporter([finding, unmeasured], {}, "asd_ism", explain=True, wide=True)
    reporter.write_terminal()

    output = capsys.readouterr().out
    assert "scored.example" in output
    assert "UNKNOWN" in output          # the readiness legend, not a raw enum in the body

    # Assert on the summary's data rather than its rendering: Rich elides the panel at the
    # narrow width a captured console reports, so a substring check there tests nothing.
    tiles = {left[0]: left[1] for left, _ in reporter._summary_stats["tiles"]}
    tiles.update({right[0]: right[1] for _, right in reporter._summary_stats["tiles"] if right})
    assert tiles["Endpoints"].startswith("2 ")
    assert "Profile" in tiles
    # One of two hosts went unmeasured, which is worth saying. "100% determinable" never was.
    assert tiles["Not measured"] == "[yellow]1 of 2[/yellow]"


def test_a_small_scan_omits_population_statistics():
    # A distribution, an average and a percentage are statements about a population. Printed
    # over one host they repeat the row below them, and noise in a compliance tool trains
    # people to skim past the part that matters.
    finding = HostFinding(
        target=Target(hostname="only.example", port=443),
        negotiated_group="X25519MLKEM768", confidentiality_score=20, authentication_score=45,
    )
    finding.pq_readiness = "hybrid_transitional"
    reporter = Reporter([finding], {}, "asd_ism")
    reporter.write_terminal()
    labels = {left[0] for left, _ in reporter._summary_stats["tiles"]}
    labels |= {right[0] for _, right in reporter._summary_stats["tiles"] if right}
    assert not labels & {"Conf spread", "Auth spread", "Avg conf/auth", "Determinable", "Conf ready"}


def test_a_fleet_scan_keeps_the_distribution():
    findings = []
    for index in range(12):
        item = HostFinding(
            target=Target(hostname=f"h{index}.example", port=443),
            negotiated_group="x25519", confidentiality_score=index * 8, authentication_score=40,
        )
        item.pq_readiness = "classical_only"
        findings.append(item)
    reporter = Reporter(findings, {}, "asd_ism")
    reporter.write_terminal()
    labels = {left[0] for left, _ in reporter._summary_stats["tiles"]}
    labels |= {right[0] for _, right in reporter._summary_stats["tiles"] if right}
    assert {"Conf spread", "Auth spread", "Avg conf/auth"} <= labels


def test_report_formats_include_probe_attestation(tmp_path):
    finding = HostFinding(target=Target(hostname="format.example"), probe_method="native")
    payload = {"probe_method": "native", "findings": [json.loads(finding.model_dump_json())]}
    assert payload["probe_method"] == "native"
    assert payload["findings"][0]["probe_method"] == "native"


def test_terminal_table_never_exceeds_console_width(monkeypatch):
    """The old output hardcoded Console(width=220), so borders interleaved with wrapped text."""
    import io

    from rich.console import Console

    from pqc_scan import reporters
    from pqc_scan.models import HostFinding, Target

    findings = [
        HostFinding(
            target=Target(hostname="a-very-long-hostname-that-would-wrap.example.gov.au", port=443,
                          criticality="high"),
            tls_version="TLSv1.3", negotiated_group="X25519MLKEM768",
            best_supported_group="MLKEM1024", pq_readiness="hybrid_transitional",
            confidentiality_score=52, authentication_score=84,
            rule_findings=["one", "two", "three", "four"],
            handshake_errors=["a long error string " * 8],
        )
    ]
    buffer = io.StringIO()
    monkeypatch.setattr(reporters, "Console", lambda *a, **k: Console(file=buffer, width=100, no_color=True))

    reporters.Reporter(findings, {}, "asd_ism").write_terminal()

    lines = buffer.getvalue().splitlines()
    assert lines, "nothing rendered"
    assert max(len(line) for line in lines) <= 100
    # the hostname is elided on one line, never split across two
    assert not any(line.strip().startswith("example.gov.au") for line in lines)


def test_wide_view_shows_chain_classification_when_there_is_room(monkeypatch):
    import io

    from rich.console import Console

    from pqc_scan import reporters
    from pqc_scan.models import Classification, HostFinding, Target

    finding = HostFinding(
        target=Target(hostname="scored.example", port=443, criticality="medium"),
        tls_version="TLSv1.3", negotiated_group="X25519",
        confidentiality_score=12, authentication_score=8,
        chain_classification=Classification.NOT_APPROVED_AFTER_2030,
    )
    buffer = io.StringIO()
    monkeypatch.setattr(reporters, "Console", lambda *a, **k: Console(file=buffer, width=160, no_color=True))

    reporters.Reporter([finding], {}, "asd_ism", wide=True).write_terminal()

    output = buffer.getvalue()
    assert "Chain" in output
    assert "NOT_APPROVED_AFTER_2030" in output
    assert max(len(line) for line in output.splitlines()) <= 160


def test_html_report_is_self_contained_and_attests_capability(tmp_path):
    from pqc_scan.models import Classification, HostFinding, Target
    from pqc_scan.reporters import Reporter

    findings = [
        HostFinding(
            target=Target(hostname="pq.example", port=443, criticality="high"),
            tls_version="TLSv1.3", negotiated_group="X25519MLKEM768",
            best_supported_group="MLKEM1024", capability_exceeds_default=True,
            pq_readiness="hybrid_transitional", pq_groups_offered=["MLKEM1024", "X25519MLKEM768"],
            confidentiality_score=52, authentication_score=84,
            rule_findings=["capability_exceeds_default_negotiation"],
            chain_classification=Classification.NOT_APPROVED_AFTER_2030,
            confidentiality_explanation="key exchange X25519MLKEM768 -> TRANSITIONAL (+20)",
        ),
        HostFinding(
            target=Target(hostname="dead.example", port=443, criticality="low"),
            not_testable_reason="dns_failure", handshake_errors=["gaierror: not known"],
        ),
    ]
    out = tmp_path / "report.html"
    Reporter(findings, {}, "asd_ism", metadata={
        "operator": "Nayef", "engagement": "ENG-001", "openssl_version": "OpenSSL 3.6.4",
        "probe_method": "native", "authorised": True, "rules_version": "2026.09.1",
    }).write_html(str(out))
    html = out.read_text()

    # no unrendered template, and nothing LOADED from the network. A link in the footer is
    # not a fetch; an external script, stylesheet or image would be.
    assert "{{" not in html and "{%" not in html
    for external in ('src="http', "src='http", '<link', "@import"):
        assert external not in html, f"report pulls in {external}"
    # capability attestation: a "no PQ" verdict must be attributable to the server
    assert "OpenSSL 3.6.4" in html
    assert "native" in html
    assert "MLKEM1024" in html
    # dark mode is declared under both the OS query and the explicit toggle
    assert 'prefers-color-scheme: dark' in html
    assert ':root[data-theme="dark"]' in html
    # a not-testable host is present but carries no score
    assert "dead.example" in html
    assert "Nayef" in html and "ENG-001" in html


def _domain_row(hostname: str, **fields) -> HostFinding:
    finding = HostFinding(target=Target(hostname=hostname, port=0), service="domain",
                          version="domain", negotiated_group="n/a", **fields)
    finding.pq_readiness = "unknown" if finding.not_testable_reason else "not_applicable"
    return finding


def _tls_row(hostname: str, readiness: str) -> HostFinding:
    finding = HostFinding(target=Target(hostname=hostname, port=443), negotiated_group="X25519MLKEM768",
                          confidentiality_score=20, authentication_score=10)
    finding.pq_readiness = readiness
    return finding


def test_a_measured_domain_row_is_not_counted_as_unmeasured(capsys):
    # The defect: every domain row carried "unknown", so a clean SPF/DMARC check printed as
    # "Not measured" and UNKNOWN beside hosts the scanner genuinely could not reach.
    findings = [_tls_row("web.example", "hybrid_transitional"),
                _domain_row("example.gov.au", authentication_score=0)]
    reporter = Reporter(findings, {}, "asd_ism")
    reporter.write_terminal()
    output = capsys.readouterr().out

    assert reporter._summary_stats["unmeasured"] == 0
    tiles = {left[0]: left[1] for left, _ in reporter._summary_stats["tiles"]}
    tiles.update({right[0]: right[1] for _, right in reporter._summary_stats["tiles"] if right})
    assert "Not measured" not in tiles
    assert "UNKNOWN" not in tiles["PQ readiness"]
    assert "UNKNOWN" not in output
    assert "email/web ok" in output


def test_a_domain_row_whose_dns_failed_is_counted_as_unmeasured():
    findings = [_tls_row("web.example", "hybrid_transitional"),
                _domain_row("example.gov.au", not_testable_reason="dns_failure")]
    reporter = Reporter(findings, {}, "asd_ism")
    reporter.write_terminal()

    assert reporter._summary_stats["unmeasured"] == 1
    tiles = {left[0]: left[1] for left, _ in reporter._summary_stats["tiles"]}
    tiles.update({right[0]: right[1] for _, right in reporter._summary_stats["tiles"] if right})
    assert tiles["Not measured"] == "[yellow]1 of 2[/yellow]"


def test_html_readiness_percentages_leave_out_domain_rows():
    # One hybrid host and three domain rows is 100% hybrid, not 25%. Dividing by every row
    # understated exactly the figure a published benchmark would lead with.
    findings = [_tls_row("web.example", "hybrid_transitional")] + [
        _domain_row(f"d{index}.example", authentication_score=0) for index in range(3)
    ]
    context = Reporter(findings, {}, "asd_ism")._html_context()
    rows = {row["key"]: row for row in context["summary"]["readiness_rows"]}

    assert "not_applicable" not in rows
    assert rows["hybrid_transitional"]["pct"] == 100
    assert context["summary"]["pq_total"] == 1
    assert context["summary"]["domain_rows"] == 3
    domain = next(row for row in context["rows"] if row["readiness_key"] == "not_applicable")
    assert domain["readiness_label"] == "email/web ok"
    assert domain["host"] == "d0.example"
