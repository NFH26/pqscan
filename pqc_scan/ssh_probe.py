"""SSH algorithm discovery, in pure Python.

An SSH server announces every algorithm it will accept in its SSH_MSG_KEXINIT, which it sends
immediately after the version exchange and before any key exchange or authentication. So a
single unauthenticated TCP connection yields the full algorithm inventory: key exchange, host
key, cipher and MAC. Nothing is negotiated, nothing is authenticated, and no credentials are
involved.

The ISM's Secure Shell section says the controls for approved algorithms in the
'Cryptographic algorithms' section "will also need to be consulted", so the same
classifications that score TLS apply here.

Wire format is RFC 4253 section 6 (binary packet) and section 7.1 (SSH_MSG_KEXINIT).
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass, field

SSH_MSG_KEXINIT = 20
CLIENT_IDENTIFIER = b"SSH-2.0-pqc-scan\r\n"
MAX_PACKET = 65536
MAX_PREAMBLE_LINES = 32

NAME_LIST_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


@dataclass
class SSHObservation:
    """What one SSH endpoint announced. Per-host, returned, never stored on a shared object."""

    banner: str | None = None
    protocol_version: str | None = None
    software: str | None = None
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    compression: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    not_testable_reason: str | None = None


SSH_MSG_DISCONNECT = 1


class SSHDisconnected(Exception):
    """The server ended the connection and said why, before any algorithms were exchanged.

    Access denied, too many connections, a banned address, an exhausted quota - a scanner
    meets these constantly, and RFC 4253 section 11.1 puts a human-readable reason in the
    packet. Reporting that reason is the difference between "ssh_parse_error:not_kexinit:1"
    and "the server said your quota is exhausted".
    """


def _disconnect_reason(payload: bytes) -> str:
    """Pull the description out of an SSH_MSG_DISCONNECT packet."""
    if len(payload) < 9:
        return "no reason given"
    (length,) = struct.unpack(">I", payload[5:9])
    text = payload[9:9 + length].decode("utf-8", "replace").strip()
    (code,) = struct.unpack(">I", payload[1:5])
    return text or f"reason code {code}"


def _name_lists(payload: bytes) -> dict[str, list[str]]:
    """Parse the ten name-lists out of a KEXINIT payload.

    Every length is read from the wire, so each one is bounds-checked against the remaining
    buffer before it is used. A hostile or broken server must not be able to walk us past the
    end of the payload.
    """
    if payload and payload[0] == SSH_MSG_DISCONNECT:
        raise SSHDisconnected(_disconnect_reason(payload))
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError(f"not_kexinit:{payload[0] if payload else 'empty'}")
    position = 1 + 16  # message type, then the 16-byte cookie
    result: dict[str, list[str]] = {}
    for name in NAME_LIST_FIELDS:
        if position + 4 > len(payload):
            raise ValueError("truncated_name_list_length")
        (length,) = struct.unpack(">I", payload[position:position + 4])
        position += 4
        if length > len(payload) - position:
            raise ValueError("name_list_overruns_payload")
        raw = payload[position:position + length].decode("ascii", "replace")
        position += length
        result[name] = [item for item in raw.split(",") if item]
    return result


async def _read_identification(reader: asyncio.StreamReader) -> str:
    """Read the server identification string, skipping any preamble lines (RFC 4253 4.2)."""
    for _ in range(MAX_PREAMBLE_LINES):
        line = (await reader.readline()).decode("utf-8", "replace").strip()
        if not line:
            raise ValueError("no_identification_string")
        if line.startswith("SSH-"):
            return line
    raise ValueError("identification_string_not_found")


async def _read_packet(reader: asyncio.StreamReader) -> bytes:
    """Read one unencrypted binary packet and return its payload."""
    header = await reader.readexactly(5)
    (packet_length,) = struct.unpack(">I", header[:4])
    padding_length = header[4]
    if not 1 <= packet_length <= MAX_PACKET:
        raise ValueError(f"implausible_packet_length:{packet_length}")
    payload_length = packet_length - padding_length - 1
    if payload_length < 0:
        raise ValueError("padding_exceeds_packet")
    body = await reader.readexactly(packet_length - 1)
    return body[:payload_length]


async def probe_ssh(host: str, port: int = 22, timeout: float = 10.0) -> SSHObservation:
    observation = SSHObservation()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except TimeoutError:
        observation.errors.append(f"timed out after {timeout}s during TCP connect")
        observation.not_testable_reason = "tcp_connect_timeout"
        return observation
    except OSError as error:
        observation.errors.append(f"{type(error).__name__}: {error}")
        observation.not_testable_reason = "dns_failure" if "getaddrinfo" in str(error) or "gaierror" in type(error).__name__ else "connection_failed"
        return observation

    try:
        identification = await asyncio.wait_for(_read_identification(reader), timeout)
        observation.banner = identification
        parts = identification.split("-", 2)
        observation.protocol_version = parts[1] if len(parts) > 2 else None
        observation.software = parts[2] if len(parts) > 2 else None

        writer.write(CLIENT_IDENTIFIER)
        await writer.drain()

        payload = await asyncio.wait_for(_read_packet(reader), timeout)
        for name, values in _name_lists(payload).items():
            if name == "kex_algorithms":
                observation.kex_algorithms = values
            elif name == "server_host_key_algorithms":
                observation.host_key_algorithms = values
            elif name == "encryption_server_to_client":
                observation.ciphers = values
            elif name == "mac_server_to_client":
                observation.macs = values
            elif name == "compression_server_to_client":
                observation.compression = values
    except TimeoutError:
        observation.errors.append(f"timed out after {timeout}s during SSH key exchange init")
        observation.not_testable_reason = "timeout"
    except asyncio.IncompleteReadError:
        observation.errors.append("connection closed before KEXINIT was complete")
        observation.not_testable_reason = "truncated_response"
    except SSHDisconnected as error:
        # The server told us why it hung up. That is a reachability condition, not a
        # malformed packet, and the operator can act on the reason.
        observation.errors.append(f"service_unavailable: SSH server disconnected: {error}")
        observation.not_testable_reason = "service_unavailable"
    except (ValueError, struct.error) as error:
        observation.errors.append(f"ssh_parse_error:{error}")
        observation.not_testable_reason = "unparsable_response"
    except OSError as error:
        observation.errors.append(f"{type(error).__name__}: {error}")
        observation.not_testable_reason = "connection_failed"
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    return observation
