import re
import ssl
import struct

import pytest

from pqc_scan.collectors import NativeTLSCollector
from pqc_scan.models import Target
from pqc_scan.tls_probe import _tls12_named_curve, default_client_groups, tls_groups


class FakeReader:
    def __init__(self, responses):
        self.responses = iter(responses)

    async def readuntil(self, separator):
        return next(self.responses)


class FakeWriter:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        pass

def test_probe_parsing_strict():
    # Simulated strict probe matching requirement
    stdout = "Server Temp Key: ECDH, P-256"
    requested = "X25519MLKEM768"

    tmp_m = re.search(r"Server Temp Key:\s+(?:[A-Za-z0-9]+,\s+)?([A-Za-z0-9_-]+)", stdout)
    negotiated = tmp_m.group(1) if tmp_m else None

    assert negotiated == "P-256"
    assert negotiated != requested


def test_native_probe_group_list_includes_pure_mlkem1024():
    assert "MLKEM1024" in tls_groups()


def test_default_client_profile_excludes_pure_mlkem1024():
    assert "MLKEM1024" not in default_client_groups()
    assert default_client_groups()[0] == "X25519MLKEM768"


def test_tls12_server_key_exchange_named_curve():
    body = b"\x03\x00\x17\x00"
    handshake = bytes([12]) + len(body).to_bytes(3, "big") + body

    assert _tls12_named_curve(handshake) == 23


def test_probe_errors_are_deduplicated(monkeypatch):
    from pqc_scan import collectors
    from pqc_scan.tls_probe import ProbeResult

    async def fake_enumerate(*args, **kwargs):
        return [
            ProbeResult(None, "not_testable", "same_error"),
            ProbeResult(None, "not_testable", "same_error"),
        ]

    monkeypatch.setattr(collectors, "enumerate_groups", fake_enumerate)
    collector = NativeTLSCollector()

    import asyncio
    _, _, probe_errors = asyncio.run(
        collector.probe_pq_groups(Target(hostname="example.test"), "TLSv1.3", "X25519")
    )

    assert probe_errors == ["PQ group probe same_error (x2)"]


def test_legacy_context_allows_tls_one(monkeypatch):
    class FakeContext:
        def __init__(self):
            self.ciphers = None

        def set_ciphers(self, value):
            self.ciphers = value

    context = FakeContext()
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)

    legacy = NativeTLSCollector()._legacy_tls_context()

    assert legacy.minimum_version == ssl.TLSVersion.TLSv1
    assert legacy.maximum_version == ssl.TLSVersion.TLSv1_2
    assert legacy.ciphers == "ALL:COMPLEMENTOFALL:@SECLEVEL=0"


@pytest.mark.asyncio
async def test_imap_starttls_sends_command_and_requires_ok():
    writer = FakeWriter()
    await NativeTLSCollector()._perform_starttls(
        FakeReader([b"* OK IMAP4 ready\r\n", b"a1 OK Begin TLS negotiation now\r\n"]),
        writer,
        "starttls:imap",
    )

    assert writer.writes == [b"a1 STARTTLS\r\n"]


@pytest.mark.asyncio
async def test_unsupported_starttls_is_reported_without_connection(monkeypatch):
    async def fail_connection(*args, **kwargs):
        raise AssertionError("unsupported protocol attempted a connection")

    monkeypatch.setattr("asyncio.open_connection", fail_connection)
    result = await NativeTLSCollector().collect_tls(Target(hostname="mysql.local", protocol="starttls:mysql"))

    assert result.errors == ["unsupported_protocol: starttls:mysql"]


@pytest.mark.asyncio
async def test_failed_host_returns_unknown_group(monkeypatch):
    async def fail_connection(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("asyncio.open_connection", fail_connection)
    result = await NativeTLSCollector(timeout=0.1).collect_tls(Target(hostname="failed.local"))

    assert result.negotiated_group == "unknown"
    assert result.errors
    assert result.supported_groups == []


def test_one_host_processing_failure_does_not_abort_scan(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    from pqc_scan import cli, collectors, probes

    class FakeCollector:
        def __init__(self, **kwargs):
            pass

        async def collect_tls(self, target):
            if target.hostname == "failed.local":
                raise RuntimeError("collector exploded")
            return collectors.HostObservation(
                tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", negotiated_group="X25519",
            )

        async def probe_pq_groups(self, target, tls_version, negotiated_group, supported_groups=None):
            return [], "not_supported", []

    monkeypatch.setattr(probes, "NativeTLSCollector", FakeCollector)
    monkeypatch.setattr(cli, "check_openssl_version", lambda: None)
    monkeypatch.setattr(cli.Reporter, "write_terminal", lambda self: None)
    input_file = tmp_path / "hosts.csv"
    input_file.write_text("hostname,port\nfailed.local,443\ngood.local,443\n")

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

    assert exc_info.value.code == 1

@pytest.mark.asyncio
async def test_capabilities_do_not_leak_between_hosts(monkeypatch):
    """One collector serves a whole concurrent batch, so per-host state must not be shared.

    Before this test, collect_tls stored supported groups on the collector. A host that failed
    before that line kept the PREVIOUS host's results, so dead hosts were reported as
    supporting ML-KEM.
    """
    import asyncio

    from pqc_scan import collectors
    from pqc_scan.tls_probe import ProbeResult

    async def fake_enumerate(host, *args, **kwargs):
        return [ProbeResult("MLKEM1024", "supported", "server_hello")]

    async def fake_open_connection(host, port, **kwargs):
        if host == "dead.local":
            raise OSError("no route to host")
        raise OSError("handshake not reached in this test")

    monkeypatch.setattr(collectors, "enumerate_groups", fake_enumerate)
    monkeypatch.setattr("asyncio.open_connection", fake_open_connection)

    collector = NativeTLSCollector(timeout=0.1)
    live = collector.collect_tls(Target(hostname="live.local"))
    dead = collector.collect_tls(Target(hostname="dead.local"))
    live_result, dead_result = await asyncio.gather(live, dead)

    assert dead_result.supported_groups == []
    assert dead_result.negotiated_group == "unknown"
    assert live_result.supported_groups == []


def test_best_supported_group_is_ranked_by_classification():
    from pqc_scan.parsers import RuleEngine
    from pqc_scan.probes import best_supported_group as _best_supported_group

    engine = RuleEngine("asd_ism")

    assert _best_supported_group([], engine) is None
    assert _best_supported_group(["secp256r1", "X25519MLKEM768", "MLKEM1024"], engine) == "MLKEM1024"
    assert _best_supported_group(["secp256r1", "X25519MLKEM768"], engine) == "X25519MLKEM768"
    assert _best_supported_group(["secp256r1", "x25519"], engine) in {"secp256r1", "x25519"}


def test_client_hello_sends_x25519_key_share_but_not_mlkem():
    """A key share is what makes the measurement match real-world negotiation.

    With an empty key_share the server answers with its OWN preference, not what a client
    gets: ato.gov.au reported secp256r1 that way while every real client negotiates x25519.
    An ML-KEM share cannot be faked (FIPS 203 rejects a malformed encapsulation key), so the
    hybrid is offered WITHOUT a share and a server preferring it answers via HelloRetryRequest.
    """
    from pqc_scan.tls_probe import CLIENT_KEY_SHARE_SIZES, _client_hello, tls_groups

    codes = tls_groups()
    assert CLIENT_KEY_SHARE_SIZES == {"x25519": 32}

    hello = _client_hello(
        "example.test",
        [codes["X25519MLKEM768"], codes["x25519"]],
        key_shares=[(codes["x25519"], 32)],
    )
    # key_share extension (51) carries exactly one entry: x25519, 32 bytes
    marker = struct.pack(">HH", 51, 2 + 2 + 2 + 32)
    assert marker in hello
    body = hello[hello.index(marker) + 4:]
    assert struct.unpack(">H", body[0:2])[0] == 2 + 2 + 32
    assert struct.unpack(">H", body[2:4])[0] == codes["x25519"]
    assert struct.unpack(">H", body[4:6])[0] == 32


def test_ssh_kexinit_parser_handles_a_real_server_response():
    """Built from a real OpenSSH KEXINIT so the offsets are exercised end to end."""
    from pqc_scan.ssh_probe import _name_lists

    lists = [
        b"mlkem768x25519-sha256,curve25519-sha256", b"rsa-sha2-512,ssh-ed25519",
        b"aes256-gcm@openssh.com", b"aes256-gcm@openssh.com",
        b"hmac-sha2-512-etm@openssh.com", b"hmac-sha2-256-etm@openssh.com",
        b"none", b"none", b"", b"",
    ]
    payload = bytes([20]) + b"\x00" * 16
    for item in lists:
        payload += struct.pack(">I", len(item)) + item
    payload += b"\x00" + struct.pack(">I", 0)

    parsed = _name_lists(payload)

    assert parsed["kex_algorithms"] == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert parsed["server_host_key_algorithms"] == ["rsa-sha2-512", "ssh-ed25519"]
    assert parsed["mac_server_to_client"] == ["hmac-sha2-256-etm@openssh.com"]
    assert parsed["languages_server_to_client"] == []


def test_ssh_parser_rejects_hostile_lengths():
    """The parser reads lengths off the wire, so every one is bounds-checked."""
    from pqc_scan.ssh_probe import _name_lists

    with pytest.raises(ValueError, match="not_kexinit"):
        _name_lists(bytes([21]) + b"\x00" * 16)
    with pytest.raises(ValueError, match="overruns_payload"):
        _name_lists(bytes([20]) + b"\x00" * 16 + struct.pack(">I", 0xFFFF) + b"short")
    with pytest.raises(ValueError, match="truncated_name_list_length"):
        _name_lists(bytes([20]) + b"\x00" * 16 + b"\x00\x01")
    with pytest.raises(ValueError, match="not_kexinit"):
        _name_lists(b"")
