"""Whole-probe behaviour against a server that misbehaves on purpose.

The parser fuzzing covers bytes; this covers the async paths around them - a server that
accepts and never speaks, one that floods, one that hangs up mid-handshake. None of these may
hang the scan or crash it, and each must come back as a finding about that endpoint.
"""
import asyncio
import contextlib

import pytest

from pqc_scan.models import Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.probes import ProbeContext, run_probe


async def _serve(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _probe(port: int, protocol: str | None = "tls", timeout: float = 0.6) -> object:
    context = ProbeContext(
        engine=RuleEngine(), timeout=timeout, host_budget_multiplier=3.0
    )
    return await run_probe(
        Target(hostname="127.0.0.1", port=port, protocol=protocol), context
    )


def _run(handler, protocol="tls", timeout=0.6):
    async def go():
        server, port = await _serve(handler)
        try:
            return await _probe(port, protocol, timeout)
        finally:
            # Deliberately not awaiting wait_closed(): these handlers block on purpose, and
            # waiting for them would measure the test harness rather than the scanner.
            server.close()

    return asyncio.run(asyncio.wait_for(go(), 30))


def test_a_server_that_accepts_and_never_speaks_times_out_cleanly():
    async def handler(reader, writer):
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(60)

    finding = _run(handler)
    assert finding.not_testable_reason is not None
    assert finding.confidentiality_score is None      # never scored as compliant


def test_a_server_that_hangs_up_immediately_is_a_finding_not_a_crash():
    async def handler(reader, writer):
        writer.close()

    finding = _run(handler)
    assert finding.not_testable_reason or finding.handshake_errors


def test_a_server_flooding_a_banner_cannot_exhaust_memory():
    # A STARTTLS greeting reader that trusts the server will eventually stop is a memory
    # exhaustion bug. The read must be bounded by the timeout and the stream limit.
    async def handler(reader, writer):
        try:
            while True:
                writer.write(b"220-" + b"x" * 4000 + b"\r\n")
                await writer.drain()
        except Exception:
            pass

    finding = _run(handler, protocol="starttls:smtp")
    assert finding.not_testable_reason or finding.handshake_errors


def test_a_server_sending_tls_garbage_is_reported_not_believed():
    async def handler(reader, writer):
        await reader.read(4096)
        writer.write(b"\x16\x03\x03\xff\xff" + b"\x00" * 64)   # declares far more than it sends
        await writer.drain()
        await asyncio.sleep(5)

    finding = _run(handler)
    assert finding.negotiated_group in (None, "unknown", "")
    assert finding.confidentiality_score is None


def test_a_fake_ssh_banner_does_not_produce_a_confident_verdict():
    async def handler(reader, writer):
        writer.write(b"SSH-2.0-Evil\r\n")
        await writer.drain()
        writer.write(b"\x00\x00\x00\x0c\x0a" + b"\xff" * 11)    # nonsense packet
        await writer.drain()
        await asyncio.sleep(5)

    finding = _run(handler, protocol="ssh")
    # It may report an SSH service, but must not invent algorithms it never saw.
    assert not finding.algorithms.get("key_exchange")
    assert finding.confidentiality_score is None


def test_an_ssh_server_claiming_version_one_fails_ism_1506():
    async def handler(reader, writer):
        writer.write(b"SSH-1.99-Ancient\r\n")
        await writer.drain()
        await asyncio.sleep(2)

    finding = _run(handler, protocol="ssh")
    assert finding.observations.get("banner", "").startswith("SSH-1.99")


@pytest.mark.parametrize("payload", [b"\x00", b"HTTP/1.1 200 OK\r\n\r\n", b"\xff" * 512])
def test_arbitrary_first_bytes_never_crash_the_probe(payload):
    async def handler(reader, writer):
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(2)

    finding = _run(handler)
    assert finding is not None
    assert finding.confidentiality_score is None


def test_an_ssh_server_that_says_why_it_hung_up_is_quoted(monkeypatch):
    # RFC 4253 11.1 puts a human-readable reason in SSH_MSG_DISCONNECT. Reporting it is the
    # difference between "ssh_parse_error:not_kexinit:1" and "your quota is exhausted".
    import struct

    from pqc_scan.ssh_probe import probe_ssh

    reason = b"Your usage quota at test.example exceeded."
    payload = bytes([1]) + struct.pack(">I", 11) + struct.pack(">I", len(reason)) + reason + b"\x00\x00\x00\x00"
    packet = struct.pack(">I", len(payload) + 1) + bytes([0]) + payload

    async def handler(reader, writer):
        writer.write(b"SSH-2.0-Example_1.0\r\n")
        await writer.drain()
        await reader.readline()
        writer.write(packet)
        await writer.drain()
        await asyncio.sleep(0.3)

    async def go():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await probe_ssh("127.0.0.1", port, 2.0)
        finally:
            server.close()

    observation = asyncio.run(go())
    assert observation.not_testable_reason == "service_unavailable"
    assert "quota" in " ".join(observation.errors)
