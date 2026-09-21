"""Regressions for hosts the scanner used to report as unmeasurable."""
import asyncio
import struct

import pytest

from pqc_scan.collectors import NativeTLSCollector, _weak_cipher_failures
from pqc_scan.models import Target
from pqc_scan.probes import BANNER_SIGNATURES, ProbeContext, sniff_protocol
from pqc_scan.tls_probe import (
    LEGACY_CIPHER_SUITES,
    _legacy_client_hello,
    _server_hello_choice,
)


def test_legacy_client_hello_offers_the_suites_openssl_dropped():
    # 3DES, RC4 and NULL are gone from OpenSSL 3.5's TLS cipher list, so the raw probe is
    # the only way those hosts stay measurable.
    names = " ".join(LEGACY_CIPHER_SUITES.values())
    assert "3DES" in names and "RC4" in names and "NULL" in names

    hello = _legacy_client_hello("example.com")
    assert hello[0] == 0x16
    body = hello[5:]
    assert body[0] == 1  # ClientHello
    for code in (0x000A, 0x0005, 0x0002):
        assert struct.pack(">H", code) in hello


def test_server_hello_choice_reads_version_and_suite():
    session_id = b"\x11" * 8
    body = (
        struct.pack(">H", 0x0303) + b"\x00" * 32
        + bytes([len(session_id)]) + session_id
        + struct.pack(">H", 0x000A) + bytes([0])
        + struct.pack(">H", 0)
    )
    payload = bytes([2]) + len(body).to_bytes(3, "big") + body
    assert _server_hello_choice(payload) == (0x0303, 0x000A)


@pytest.mark.parametrize(
    "suite,expected",
    [
        ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "obsolete_cipher"),
        ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "broken_stream_cipher"),
        ("TLS_ECDHE_RSA_WITH_NULL_SHA", "null_or_export_cipher"),
        ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "null_or_export_cipher"),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", None),
    ],
)
def test_weak_cipher_failures_names_the_specific_weakness(suite, expected):
    failures = _weak_cipher_failures(suite, "")
    assert failures == ([expected] if expected else [])


def test_weak_dh_is_reported_from_the_error_text():
    assert "weak_dh_parameters" in _weak_cipher_failures(None, "dh key too small")


def test_tls_below_one_three_is_not_supported_rather_than_undetermined():
    # PQ key exchange only exists in TLS 1.3, so a TLS 1.2 host is a certain "no", not a
    # "could not tell" - that distinction is what stopped weak hosts showing as UNKNOWN.
    collector = NativeTLSCollector()
    target = Target(hostname="legacy.example", port=443)
    groups, status, errors = asyncio.run(
        collector.probe_pq_groups(target, "TLSv1.2", "unknown", None)
    )
    assert (groups, status, errors) == ([], "not_supported", [])


def test_missing_version_is_still_undetermined():
    collector = NativeTLSCollector()
    target = Target(hostname="dead.example", port=443)
    _, status, _ = asyncio.run(collector.probe_pq_groups(target, None, "unknown", None))
    assert status == "not_determinable"


def test_ssh_greeting_is_recognised(monkeypatch):
    class FakeReader:
        async def read(self, _n):
            return b"SSH-2.0-OpenSSH_9.6\r\n"

    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open(host, port):
        return FakeReader(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    target = Target(hostname="ssh.github.com", port=443)
    assert asyncio.run(sniff_protocol(target, 2.0)) == "ssh"


def test_banner_signatures_cover_the_speak_first_protocols():
    protocols = {protocol for _, protocol in BANNER_SIGNATURES}
    assert {"ssh", "starttls:smtp", "starttls:imap", "starttls:pop3"} <= protocols


def test_multiline_greeting_ignores_indented_continuation_lines():
    # Rebex's FTP banner indents its continuation lines instead of prefixing them with the
    # reply code, which made the old "fourth byte is a space" check stop on the wrong line.
    from pqc_scan.collectors import _read_greeting

    class FakeReader:
        def __init__(self, lines):
            self.lines = list(lines)

        async def readuntil(self, _sep):
            return self.lines.pop(0)

    reader = FakeReader(
        [
            b"220-Welcome to test.rebex.net!\r\n",
            b"    See https://test.rebex.net/ for more information.\r\n",
            b"220 Ready.\r\n",
        ]
    )
    assert asyncio.run(_read_greeting(reader)) == b"220 Ready.\r\n"


def test_refusing_starttls_is_a_finding_not_an_error():
    from pqc_scan.collectors import NoTLSOffered

    collector = NativeTLSCollector()

    class FakeReader:
        def __init__(self):
            self.lines = [b"220 GNU FTP server ready.\r\n", b"530 Please login.\r\n"]

        async def readuntil(self, _sep):
            return self.lines.pop(0)

    class FakeWriter:
        def write(self, _data):
            pass

        async def drain(self):
            pass

    with pytest.raises(NoTLSOffered):
        asyncio.run(
            collector._perform_starttls(FakeReader(), FakeWriter(), "starttls:ftp")
        )


def test_a_host_cannot_exceed_its_overall_budget(monkeypatch):
    # Each phase has its own timeout and they compose: an IKE cookie retry nested inside an
    # INVALID_KE retry, or fourteen sequential DKIM lookups, could hold a scan slot for
    # minutes. A host that overruns is reported as timed out, which is true.
    from pqc_scan.parsers import RuleEngine
    from pqc_scan.probes import run_probe

    async def never_returns(_target, _context):
        await asyncio.sleep(30)

    monkeypatch.setattr("pqc_scan.probes.probe_for", lambda _p: never_returns)
    context = ProbeContext(engine=RuleEngine(), timeout=0.05, host_budget_multiplier=2.0)
    finding = asyncio.run(run_probe(Target(hostname="slow.example", port=443), context))
    assert finding.not_testable_reason == "timeout"
    assert "budget" in " ".join(finding.handshake_errors)
    assert finding.confidentiality_score is None


def test_the_openssl_version_helper_never_raises(monkeypatch):
    # Scanning does not use the openssl binary, only the report header does. An unguarded
    # subprocess call here crashed the tool outright on a machine with no openssl - exactly
    # the configuration the README promises works.
    from pqc_scan import verify

    def boom(*_a, **_k):
        raise FileNotFoundError("openssl")

    monkeypatch.setattr("subprocess.run", boom)
    assert verify.openssl_display().startswith("not found")
    text, parsed = verify.openssl_version()
    assert parsed is None and text.startswith("not found")


def test_the_openssl_display_trims_the_repeated_library_half():
    """OpenSSL prints itself twice when the binary and the library agree.

    "OpenSSL 3.6.4 ... (Library: OpenSSL 3.6.4 ...)" is the common case and the second half
    says nothing; when they differ it is the only thing that explains a surprising result.
    """
    from pqc_scan import verify

    same = "OpenSSL 3.6.4 25 Aug 2026 (Library: OpenSSL 3.6.4 25 Aug 2026)"
    differs = "OpenSSL 3.6.4 25 Aug 2026 (Library: OpenSSL 3.0.2 15 Mar 2022)"
    assert verify._trim_library_half(same) == "OpenSSL 3.6.4 25 Aug 2026"
    assert verify._trim_library_half(differs) == differs
