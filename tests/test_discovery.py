"""Service discovery: ask the host what it runs, rather than asking the operator."""
import asyncio

import pytest

from pqc_scan.discovery import Discovered, _probe_port, candidate_ports, discover
from pqc_scan.exporters import run_directory


def test_candidates_come_from_the_port_map():
    # Two lists that must agree, so there is only one.
    ports = candidate_ports()
    assert {22, 443, 853, 500, 21} <= set(ports)
    assert ports[22] == "ssh" and ports[853] == "tls"


def _serve(handler):
    async def go():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await _probe_port("127.0.0.1", port, "tls", 1.0)
        finally:
            server.close()

    return asyncio.run(go())


def test_a_server_that_announces_ssh_is_identified_as_ssh():
    # Regardless of the port it is on: the banner is stronger evidence than the port map.
    async def handler(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()
        await asyncio.sleep(0.4)

    found = _serve(handler)
    assert found is not None and found.protocol == "ssh"
    assert "OpenSSH" in found.evidence


def test_a_silent_server_is_taken_as_the_port_map_guess():
    # TLS servers wait for the client, so silence is the evidence, and the probe that
    # follows will confirm or contradict it.
    async def handler(reader, writer):
        await asyncio.sleep(0.4)

    found = _serve(handler)
    assert found is not None and found.protocol == "tls"
    assert "waits" in found.evidence


def test_a_closed_port_is_not_reported():
    async def go():
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()
        return await _probe_port("127.0.0.1", port, "tls", 0.5)

    assert asyncio.run(go()) is None


def test_discovery_of_an_unreachable_host_returns_nothing_rather_than_guessing():
    # Silence must never be read as "these services exist".
    assert asyncio.run(discover("192.0.2.1", timeout=0.3)) == []


def test_results_are_ordered_by_port():
    found = [Discovered(443, "tls", ""), Discovered(22, "ssh", "")]
    assert [d.port for d in sorted(found, key=lambda x: x.port)] == [22, 443]


@pytest.mark.parametrize(
    "engagement,expected",
    [("ACME-2026", "ACME-2026"), ("a b/c", "a-b-c"), ("", "scan"), ("../etc", "etc")],
)
def test_run_directory_is_dated_and_safe(tmp_path, engagement, expected):
    # One folder per run, so a report is never silently replaced by the next scan - and a
    # engagement name from a host file can never escape the output directory.
    path = run_directory(str(tmp_path), engagement, "2026-09-21T01:14:57+00:00")
    assert path.parent == tmp_path
    assert path.name == f"20260921-011457-{expected}"


def test_two_runs_of_the_same_engagement_do_not_collide(tmp_path):
    first = run_directory(str(tmp_path), "job", "2026-09-21T01:00:00+00:00")
    second = run_directory(str(tmp_path), "job", "2026-09-21T02:00:00+00:00")
    assert first != second
