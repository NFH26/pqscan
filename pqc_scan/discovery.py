"""Find the cryptographic services on a host, then measure each one.

The point is to remove a step that quietly decides how good a scan is. Given only a hostname,
an operator has to know which ports to list - and the ports people forget are exactly the ones
that turn out to be running TLS 1.0 or an SSH daemon nobody owns. Discovery asks the host.

Deliberately NOT a port scanner. It checks a short list of ports the ISM has something to say
about, with one short connection each, and it never sweeps a range: a full sweep is slow, looks
like an attack to anything watching, and finds services this tool could not assess anyway.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import yaml

from pqc_scan.netutil import close_quietly


@dataclass(frozen=True)
class Discovered:
    port: int
    protocol: str
    evidence: str


def candidate_ports() -> dict[int, str]:
    """Ports worth trying, taken from the port map so the two cannot drift."""
    path = Path(__file__).resolve().parent / "rules" / "port_map.yaml"
    with path.open() as handle:
        mapping = yaml.safe_load(handle).get("ports", {})
    return {int(port): str(protocol) for port, protocol in mapping.items()}


async def _probe_port(host: str, port: int, protocol: str, timeout: float) -> Discovered | None:
    """Is something listening, and does its first move match what we expect?"""
    if protocol == "ipsec":
        # UDP has no connection to establish, so the only honest test is the real probe.
        from pqc_scan.ike_probe import probe_ike

        observation = await probe_ike(host, port, timeout)
        return Discovered(port, protocol, "IKE_SA_INIT answered") if observation.responded else None

    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            # A server that speaks first tells us what it is; TLS servers wait, which is
            # itself the evidence. Either way we learn something without sending anything.
            try:
                # Strictly inside the outer budget. Waiting the FULL timeout for a greeting
                # meant the outer timeout could fire first and report the port closed - a
                # race that 3.13 happened to win and 3.12 lost, which is the worst kind.
                greeting = await asyncio.wait_for(reader.read(48), max(timeout * 0.4, 0.2))
            except (TimeoutError, OSError):
                greeting = b""
    except (TimeoutError, OSError):
        return None
    finally:
        await close_quietly(writer, 1.0)

    if greeting.startswith(b"SSH-"):
        return Discovered(port, "ssh", greeting.split(b"\r")[0].decode("utf-8", "replace")[:40])
    if greeting[:1].isdigit() or greeting.startswith((b"* OK", b"+OK")):
        return Discovered(port, protocol, greeting.split(b"\r")[0].decode("utf-8", "replace")[:40])
    if not greeting:
        # Silence on connect is what a TLS server does, so treat the port map's guess as the
        # protocol and let the probe itself confirm or contradict it.
        return Discovered(port, protocol, "open, server waits for the client")
    return Discovered(port, protocol, "open")


async def discover(host: str, timeout: float = 3.0, concurrency: int = 8) -> list[Discovered]:
    """Return the services found on a host, in port order."""
    ports = candidate_ports()
    semaphore = asyncio.Semaphore(concurrency)

    async def one(port: int, protocol: str) -> Discovered | None:
        async with semaphore:
            return await _probe_port(host, port, protocol, timeout)

    results = await asyncio.gather(*(one(port, protocol) for port, protocol in ports.items()))
    return sorted((item for item in results if item), key=lambda found: found.port)
