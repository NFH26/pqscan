"""Async native TLS supported-group probe.

The probe exists because OpenSSL's negotiated default group cannot establish support for
pure ML-KEM groups that are not in its default offer list. The codepoints come from the
ISM profile's tls_groups block; see the profile comments for registry verification notes.
"""
from __future__ import annotations

import asyncio
import os
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from pqc_scan.netutil import close_quietly


@dataclass(frozen=True)
class ProbeResult:
    group: str | None
    status: str
    reason: str | None = None


HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
Prelude = Callable[[asyncio.StreamReader, asyncio.StreamWriter, str], Awaitable[None]]


@lru_cache(maxsize=1)
def _profile() -> dict:
    """The rule profile, parsed once.

    It was re-read and re-parsed from disk on every call, and probe_group calls it per group,
    so enumerating seventeen groups parsed the whole file seventeen times for every host.
    """
    path = Path(__file__).resolve().parent / "rules" / "asd_ism.yaml"
    with path.open() as handle:
        return yaml.safe_load(handle)


def tls_groups() -> dict[str, int]:
    return {str(name): int(code) for name, code in _profile()["tls_groups"].items()}


def default_client_groups() -> list[str]:
    return [str(name) for name in _profile()["default_client_groups"]]


# Byte length of the CLIENT key_share we send for each group.
#
# Sending a key share matters: with an empty key_share the server answers with whatever IT
# prefers from our list, which measures server preference rather than what a real client gets.
# ato.gov.au returned secp256r1 that way while every real client negotiates x25519.
#
# We only send an X25519 share. Any 32 bytes is a valid X25519 public key, so a server that
# prefers x25519 uses it and names it in the ServerHello. An ML-KEM share cannot be faked:
# FIPS 203 requires a well-formed encapsulation key, and random bytes fail that check, which
# made hybrid-preferring servers abort and fall back to TLS 1.2. Instead we list the hybrid in
# supported_groups WITHOUT a share, so a server that prefers it answers with a
# HelloRetryRequest naming the group. Either way we learn the group a real client would get,
# and we never complete the handshake.
CLIENT_KEY_SHARE_SIZES = {
    "x25519": 32,
}


def _extension(extension_type: int, body: bytes) -> bytes:
    return struct.pack(">HH", extension_type, len(body)) + body


def _client_hello(
    host: str,
    codes: list[int],
    tls13: bool = True,
    key_shares: list[tuple[int, int]] | None = None,
) -> bytes:
    server_name = host.encode("idna")
    extensions = [
        _extension(0, struct.pack(">HBH", len(server_name) + 3, 0, len(server_name)) + server_name),
        _extension(10, struct.pack(">H", 2 * len(codes)) + b"".join(struct.pack(">H", code) for code in codes)),
        _extension(13, struct.pack(">H", 6) + struct.pack(">HHH", 0x0403, 0x0804, 0x0401)),
    ]
    if tls13:
        shares = b"".join(
            struct.pack(">HH", code, size) + os.urandom(size)
            for code, size in (key_shares or [])
        )
        extensions.extend(
            (
                _extension(43, bytes([2]) + struct.pack(">H", 0x0304)),
                _extension(51, struct.pack(">H", len(shares)) + shares),
            )
        )
    extensions_blob = b"".join(extensions)
    body = (
        struct.pack(">H", 0x0303) + os.urandom(32) + bytes([32]) + os.urandom(32)
        + struct.pack(">H", 6 if tls13 else 8) + (struct.pack(">HHH", 0x1301, 0x1302, 0x1303) if tls13 else struct.pack(">HHHH", 0xc02f, 0xc02b, 0xc013, 0xc014))
        + bytes([1, 0]) + struct.pack(">H", len(extensions_blob)) + extensions_blob
    )
    handshake = bytes([1]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + struct.pack(">HH", 0x0301, len(handshake)) + handshake


async def _read_record(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await reader.readexactly(5)
    record_type = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    payload = await reader.readexactly(length)
    return record_type, payload


def _selected_group(payload: bytes) -> tuple[int | None, bool]:
    if len(payload) < 4 or payload[0] != 2:
        raise ValueError("malformed_server_hello")
    body = payload[4:]
    if len(body) < 38:
        raise ValueError("truncated_server_hello")
    is_hrr = body[2:34] == HRR_RANDOM
    session_length = body[34]
    position = 35 + session_length + 3
    if position + 2 > len(body):
        raise ValueError("truncated_server_hello_extensions")
    extensions_length = struct.unpack(">H", body[position:position + 2])[0]
    position += 2
    end = min(len(body), position + extensions_length)
    while position + 4 <= end:
        extension_type, extension_length = struct.unpack(">HH", body[position:position + 4])
        position += 4
        if position + extension_length > end:
            raise ValueError("truncated_extension")
        if extension_type == 51:
            if extension_length < 2:
                raise ValueError("malformed_key_share")
            return struct.unpack(">H", body[position:position + 2])[0], is_hrr
        position += extension_length
    return None, is_hrr


def _tls12_named_curve(payload: bytes) -> int | None:
    position = 0
    while position + 4 <= len(payload):
        message_type = payload[position]
        length = int.from_bytes(payload[position + 1:position + 4], "big")
        body = payload[position + 4:position + 4 + length]
        if len(body) < length:
            raise ValueError("truncated_tls12_handshake")
        if message_type == 12 and len(body) >= 3 and body[0] == 3:
            return int.from_bytes(body[1:3], "big")
        position += 4 + length
    return None


async def probe_group(
    host: str,
    port: int,
    group: str,
    timeout: float = 5.0,
    protocol: str | None = None,
    starttls_prelude: Prelude | None = None,
) -> ProbeResult:
    groups = tls_groups()
    if group not in groups:
        return ProbeResult(None, "not_testable", "unknown_group")
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            try:
                if protocol and protocol.startswith("starttls:") and starttls_prelude:
                    await starttls_prelude(reader, writer, protocol or "")
                writer.write(_client_hello(host, [groups[group]]))
                await writer.drain()
                record_type, payload = await _read_record(reader)
                if record_type == 0x15:
                    return ProbeResult(group, "not_supported", "tls_alert")
                if record_type != 0x16:
                    return ProbeResult(None, "not_testable", "unexpected_record")
                selected, _ = _selected_group(payload)
                if selected is None:
                    return ProbeResult(None, "not_supported", "no_key_share")
                return ProbeResult(group, "supported" if selected == groups[group] else "not_supported", f"selected_{selected}")
            finally:
                await close_quietly(writer)
    except TimeoutError:
        return ProbeResult(None, "not_testable", "timeout")
    except (asyncio.IncompleteReadError, ValueError, struct.error) as error:
        return ProbeResult(None, "not_testable", str(error))
    except OSError as error:
        return ProbeResult(None, "not_testable", f"connection:{error}")


async def _probe_tls12(
    host: str,
    port: int,
    groups: dict[str, int],
    timeout: float,
    protocol: str | None,
    starttls_prelude: Prelude | None,
) -> ProbeResult:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        if protocol and protocol.startswith("starttls:") and starttls_prelude:
            await starttls_prelude(reader, writer, protocol)
        writer.write(_client_hello(host, list(groups.values()), tls13=False))
        await writer.drain()
        reverse = {code: name for name, code in groups.items()}
        for _ in range(8):
            record_type, payload = await _read_record(reader)
            if record_type == 0x15:
                return ProbeResult(None, "not_supported", "tls12_alert")
            if record_type != 0x16:
                return ProbeResult(None, "not_testable", "tls12_unexpected_record")
            curve = _tls12_named_curve(payload)
            if curve is not None:
                return ProbeResult(reverse.get(curve), "supported", "tls12_server_key_exchange")
        return ProbeResult(None, "not_supported", "tls12_no_named_curve")
    finally:
        await close_quietly(writer)


async def probe_negotiated(
    host: str,
    port: int,
    timeout: float = 5.0,
    protocol: str | None = None,
    starttls_prelude: Prelude | None = None,
) -> ProbeResult:
    groups = tls_groups()
    default_groups = default_client_groups()
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            try:
                if protocol and protocol.startswith("starttls:") and starttls_prelude:
                    await starttls_prelude(reader, writer, protocol or "")
                writer.write(
                    _client_hello(
                        host,
                        [groups[group] for group in default_groups],
                        key_shares=[
                            (groups[name], size)
                            for name, size in CLIENT_KEY_SHARE_SIZES.items()
                            if name in default_groups and name in groups
                        ],
                    )
                )
                await writer.drain()
                record_type, payload = await _read_record(reader)
                if record_type == 0x15:
                    await close_quietly(writer)
                    return await _probe_tls12(host, port, groups, timeout, protocol, starttls_prelude)
                if record_type != 0x16:
                    return ProbeResult(None, "not_testable", "unexpected_record")
                selected, _ = _selected_group(payload)
                reverse = {code: name for name, code in groups.items()}
                if selected is None:
                    await close_quietly(writer)
                    return await _probe_tls12(host, port, groups, timeout, protocol, starttls_prelude)
                return ProbeResult(reverse.get(selected), "supported", "server_hello")
            finally:
                await close_quietly(writer)
    except TimeoutError:
        return ProbeResult(None, "not_testable", "timeout")
    except (asyncio.IncompleteReadError, ValueError, struct.error) as error:
        return ProbeResult(None, "not_testable", str(error))
    except OSError as error:
        return ProbeResult(None, "not_testable", f"connection:{error}")


async def enumerate_groups(
    host: str,
    port: int,
    timeout: float = 5.0,
    protocol: str | None = None,
    starttls_prelude: Prelude | None = None,
) -> list[ProbeResult]:
    semaphore = asyncio.Semaphore(4)

    async def bounded_probe(group: str) -> ProbeResult:
        async with semaphore:
            return await probe_group(host, port, group, timeout, protocol, starttls_prelude)

    return list(await asyncio.gather(*(bounded_probe(group) for group in tls_groups())))


# Legacy cipher suites we offer in the raw fallback probe.
#
# OpenSSL 3.5 compiles 3DES, RC4, NULL and EXPORT suites out of the TLS cipher list entirely,
# so ssl.SSLContext cannot negotiate with a server that only speaks them and the host comes
# back unmeasured. A scanner that reports "unknown" for the weakest hosts on the network is
# worse than useless, so we build the ClientHello ourselves and read the server's choice out
# of the ServerHello. We never complete the handshake: the selected suite is all we need.
LEGACY_CIPHER_SUITES: dict[int, str] = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}

TLS_VERSION_NAMES = {0x0300: "SSLv3", 0x0301: "TLSv1", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2"}


@dataclass(frozen=True)
class LegacyResult:
    version: str | None
    cipher_suite: str | None
    status: str
    reason: str | None = None


def _legacy_client_hello(
    host: str, record_version: int = 0x0301, only: list[int] | None = None
) -> bytes:
    server_name = host.encode("idna")
    curves = (0x001D, 0x0017, 0x0018, 0x0019)
    extensions = b"".join(
        (
            _extension(0, struct.pack(">HBH", len(server_name) + 3, 0, len(server_name)) + server_name),
            _extension(10, struct.pack(">H", 2 * len(curves)) + b"".join(struct.pack(">H", c) for c in curves)),
            _extension(11, bytes([1, 0])),
            _extension(13, struct.pack(">H", 12) + struct.pack(">HHHHHH", 0x0401, 0x0501, 0x0601, 0x0403, 0x0201, 0x0202)),
        )
    )
    codes = list(only) if only else list(LEGACY_CIPHER_SUITES)
    body = (
        struct.pack(">H", 0x0303) + os.urandom(32) + bytes([0])
        + struct.pack(">H", 2 * len(codes)) + b"".join(struct.pack(">H", c) for c in codes)
        + bytes([1, 0]) + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = bytes([1]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + struct.pack(">HH", record_version, len(handshake)) + handshake


def _server_hello_choice(payload: bytes) -> tuple[int, int]:
    if len(payload) < 4 or payload[0] != 2:
        raise ValueError("malformed_server_hello")
    body = payload[4:]
    if len(body) < 38:
        raise ValueError("truncated_server_hello")
    version = struct.unpack(">H", body[0:2])[0]
    session_length = body[34]
    position = 35 + session_length
    if position + 2 > len(body):
        raise ValueError("truncated_server_hello_cipher")
    return version, struct.unpack(">H", body[position:position + 2])[0]


async def probe_legacy_cipher(
    host: str,
    port: int,
    timeout: float = 5.0,
    protocol: str | None = None,
    starttls_prelude: Prelude | None = None,
) -> LegacyResult:
    """Ask the server which legacy suite it picks, bypassing the local OpenSSL policy."""
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            try:
                if protocol and protocol.startswith("starttls:") and starttls_prelude:
                    await starttls_prelude(reader, writer, protocol or "")
                writer.write(_legacy_client_hello(host))
                await writer.drain()
                record_type, payload = await _read_record(reader)
                if record_type == 0x15:
                    return LegacyResult(None, None, "not_supported", "tls_alert")
                if record_type != 0x16:
                    return LegacyResult(None, None, "not_testable", "unexpected_record")
                version, suite = _server_hello_choice(payload)
                return LegacyResult(
                    TLS_VERSION_NAMES.get(version, f"0x{version:04x}"),
                    LEGACY_CIPHER_SUITES.get(suite, f"0x{suite:04x}"),
                    "supported",
                )
            finally:
                await close_quietly(writer)
    except TimeoutError:
        return LegacyResult(None, None, "not_testable", "timeout")
    except (asyncio.IncompleteReadError, ValueError, struct.error) as error:
        return LegacyResult(None, None, "not_testable", type(error).__name__)
    except OSError as error:
        return LegacyResult(None, None, "not_testable", getattr(error, "strerror", None) or "connection_error")


async def enumerate_cipher_suites(
    host: str,
    port: int,
    timeout: float = 5.0,
    protocol: str | None = None,
    starttls_prelude: Prelude | None = None,
    suites: dict[int, str] | None = None,
) -> tuple[list[str], list[str]]:
    """Return (accepted, rejected) suite names by offering each one on its own.

    Reading the server's pick from one ClientHello only tells you its FAVOURITE suite. A
    server that prefers AES-GCM but still accepts 3DES looks clean under that test, and the
    3DES is exactly what an attacker downgrades to. Offering one suite at a time is the only
    way to learn what a server will ACCEPT, which is what ISM-0471 and ISM-1369 are about.

    Each offer is a separate connection, so this is the expensive path: callers should reach
    for it when a host has already shown it speaks legacy TLS.
    """
    catalogue = suites or LEGACY_CIPHER_SUITES
    accepted: list[str] = []
    rejected: list[str] = []

    async def offer(code: int, name: str) -> None:
        try:
            async with asyncio.timeout(timeout):
                reader, writer = await asyncio.open_connection(host, port)
                try:
                    if protocol and protocol.startswith("starttls:") and starttls_prelude:
                        await starttls_prelude(reader, writer, protocol or "")
                    writer.write(_legacy_client_hello(host, only=[code]))
                    await writer.drain()
                    record_type, payload = await _read_record(reader)
                    if record_type != 0x16:
                        rejected.append(name)
                        return
                    _, chosen = _server_hello_choice(payload)
                    (accepted if chosen == code else rejected).append(name)
                finally:
                    await close_quietly(writer)
        except (TimeoutError, OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, struct.error):
            # Silence is a refusal here. A server that will not answer a single-suite offer
            # is not accepting that suite, which is the question we asked. Deliberately NOT a
            # bare except: this feeds the ISM-0471 finding, so a TypeError from a future edit
            # would be swallowed and produce a clean report, which is the worst failure mode
            # a compliance tool has.
            rejected.append(name)

    # Serially, not concurrently: a burst of connections to one host reads as an attack and
    # provokes rate limiting, which would show up as false "rejected" results.
    for code, name in catalogue.items():
        await offer(code, name)
    return accepted, rejected
