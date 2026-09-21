import pathlib
from typing import ClassVar

import pytest

from pqc_scan import cli, probes
from pqc_scan.models import Classification, HostFinding, Target


def test_parse_target_spec_supports_bracketed_ipv6():
    target = cli._parse_target_spec("[::1]:443", {443: "tls"})

    assert target.hostname == "::1"
    assert target.port == 443


def test_empty_input_exits_with_usage_error(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "check_openssl_version", lambda: None)
    input_file = tmp_path / "empty.txt"
    input_file.write_text("# only a comment\n\n")

    with pytest.raises(SystemExit) as exc_info:
        cli.scan(
            target=None,
            input_file=str(input_file),
            protocol=None,
            discover_services=False,
            operator="test",
            engagement="test",
            profile="asd_ism",
            rate_limit=10.0,
            verbose=False,
            explain=False,
            confirm_authorised=True,
            report_dir=None,
            deep=False,
            json_out=None,
            cbom_out=None,
            out_dir=None,
            formats=None,
            flat=False,
            cache_dir=str(tmp_path / "cache"),
        )

    assert exc_info.value.code == 2


def test_policy_score_gate_reports_only_measured_hosts():
    findings = [
        HostFinding(target=Target(hostname="bad.example"), confidentiality_score=80),
        HostFinding(target=Target(hostname="unmeasured.example"), not_testable_reason="dns_failure"),
    ]

    failures = cli._policy_failures(findings, 50, None, False)

    assert failures == ["bad.example:443: score exceeds 50"]


def test_policy_class_and_hybrid_gates():
    findings = [
        HostFinding(
            target=Target(hostname="bad.example"),
            chain_classification=Classification.NOT_APPROVED,
            pq_status="not_supported",
        )
    ]

    failures = cli._policy_failures(findings, None, "NOT_APPROVED", True)

    assert failures == [
        "bad.example:443: class is NOT_APPROVED",
        "bad.example:443: hybrid KEX is not supported",
    ]


def test_csv_comments_are_ignored(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "check_openssl_version", lambda: None)

    class FakeCollector:
        last_probe_errors: ClassVar[list] = []

        def __init__(self, **kwargs):
            pass

        async def collect_tls(self, target):
            return [], None, None, "unknown", [], [], False, None

        async def probe_pq_groups(self, target, tls_version, negotiated_group):
            return [], "not_determinable"

    monkeypatch.setattr(probes, "NativeTLSCollector", FakeCollector)
    monkeypatch.setattr(cli.Reporter, "write_terminal", lambda self: None)
    input_file = tmp_path / "hosts.csv"
    input_file.write_text("hostname,port\n# ignored comment\nexample.test,443\n")

    with pytest.raises(SystemExit) as exc_info:
        cli.scan(
            target=None,
            input_file=str(input_file),
            protocol=None,
            discover_services=False,
            operator="test",
            engagement="test",
            profile="asd_ism",
            rate_limit=100.0,
            verbose=False,
            explain=False,
            confirm_authorised=True,
            report_dir=None,
            deep=False,
            json_out=None,
            cbom_out=None,
            out_dir=None,
            formats=None,
            flat=False,
            cache_dir=str(tmp_path / "cache"),
        )

    assert exc_info.value.code == 1


def test_cache_metadata_fields_are_defined():
    # Read from package metadata rather than hardcoded, so it cannot drift from
    # pyproject.toml - it already had, within one release, and every report carries it.
    import tomllib

    packaged = tomllib.loads(
        (pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    )["project"]["version"]
    assert packaged == cli.TOOL_VERSION

def test_a_scope_file_that_excludes_everything_says_so(tmp_path, capsys, monkeypatch):
    # "No targets were provided" is wrong here: targets were provided and the scope file
    # removed them all. Naming the file and the hosts is the difference between a
    # two-second fix and a puzzled ten minutes.
    import pytest

    from pqc_scan import cli

    hosts = tmp_path / "hosts.csv"
    hosts.write_text("hostname,port,protocol\nexample.test,443,tls\n")
    scope = tmp_path / "scope.txt"
    scope.write_text("somewhere-else.test\n")

    with pytest.raises(SystemExit) as exit_info:
        cli.scan(
            target=None, input_file=str(hosts), operator="t", engagement="t",
            profile="asd_ism", concurrency=1, timeout=1.0, rate_limit=0.0,
            no_pq_probe=True, verbose=False, explain=False, wide=False, deep=False,
            fail_on_score=None, fail_on_class=None, require_hybrid_kex=False,
            cache_dir=str(tmp_path / "cache"), scope_file=str(scope),
            confirm_authorised=True, report_dir=None, json_out=None, cbom_out=None,
            out_dir=None, formats=None,
        )
    assert exit_info.value.code == 2
    output = capsys.readouterr().out
    assert "scope file" in output and "example.test" in output
