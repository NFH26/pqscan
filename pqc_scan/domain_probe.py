"""Domain-level email and web transport controls.

These controls are not about a cryptographic handshake, so they need a different kind of
evidence: DNS records and one HTTPS response header. They are in scope because the ISM
places them there, and because they are the cheapest genuinely unauthenticated evidence
available - an organisation that has not published SPF, DMARC or MTA-STS has an email
transport gap no TLS scan of its mail server would reveal.

    ISM-1589  MTA-STS is enabled                          -> _mta-sts TXT + policy file
    ISM-0574  SPF specifies authorised email servers       -> domain TXT, v=spf1
    ISM-1183  A hard fail SPF record is used               -> the SPF record ends in -all
    ISM-0861  DKIM signing is enabled                      -> <selector>._domainkey TXT
    ISM-1540  DMARC rejects emails that fail checks        -> _dmarc TXT, p=reject
    ISM-1424  HSTS is specified in response headers        -> Strict-Transport-Security

The DNS resolver here is deliberately minimal and hand-rolled, for the same reason the TLS
and IKE probes are: it keeps the install to `pip install pqc-scan` with no system packages,
and TXT lookups need none of what a full resolver library provides.
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field

from pqc_scan.netutil import close_quietly

# Selectors to try for DKIM. There is no way to enumerate them - a DKIM record lives at
# <selector>._domainkey.<domain> and the selector is only visible in a signed message header -
# so a miss means "not found with these selectors", never "DKIM is absent". The report says so.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail",
    "dkim", "smtp", "mandrill", "zoho", "protonmail", "fm1",
)


@dataclass
class DomainObservation:
    domain: str = ""
    spf: str | None = None
    spf_hard_fail: bool = False
    dmarc: str | None = None
    dmarc_policy: str | None = None
    dkim_selector: str | None = None
    mta_sts_dns: bool = False
    mta_sts_policy_mode: str | None = None
    hsts: str | None = None
    hsts_max_age: int | None = None
    errors: list[str] = field(default_factory=list)
    not_testable_reason: str | None = None
    # Which observations actually completed. Absence of evidence is not evidence of absence:
    # a timeout on _dmarc must never be reported as "this domain publishes no DMARC", because
    # that goes into a compliance report as a breach the operator did not commit.
    observed: set[str] = field(default_factory=set)


def _encode_name(name: str) -> bytes:
    return b"".join(
        bytes([len(label)]) + label for label in name.encode("idna").split(b".") if label
    ) + b"\x00"


def _skip_name(data: bytes, position: int) -> int:
    """Step over a DNS name, which may end in a compression pointer."""
    while position < len(data):
        length = data[position]
        if length == 0:
            return position + 1
        if length & 0xC0 == 0xC0:           # pointer: two bytes, and the name ends here
            return position + 2
        position += 1 + length
    raise ValueError("truncated_name")


def _parse_txt(data: bytes, expected_id: int) -> list[str]:
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != expected_id:
        raise ValueError("dns_id_mismatch")
    flags, questions, answers = struct.unpack(">HHH", data[2:8])
    if not flags & 0x8000:              # QR: this is a query, not an answer to ours
        raise ValueError("dns_not_a_response")
    if flags & 0x000F not in (0, 3):        # NOERROR or NXDOMAIN; anything else is a failure
        raise ValueError(f"dns_rcode_{flags & 0x000F}")
    position = 12
    for _ in range(questions):
        position = _skip_name(data, position) + 4
    records: list[str] = []
    for _ in range(answers):
        position = _skip_name(data, position)
        if position + 10 > len(data):
            break
        record_type, _, _, length = struct.unpack(">HHIH", data[position:position + 10])
        position += 10
        body = data[position:position + length]
        position += length
        if record_type != 16:               # TXT
            continue
        # A TXT record is one or more length-prefixed strings that concatenate.
        chunks, offset = [], 0
        while offset < len(body):
            size = body[offset]
            chunks.append(body[offset + 1:offset + 1 + size])
            offset += 1 + size
        records.append(b"".join(chunks).decode("utf-8", "replace"))
    return records


async def resolve_txt(name: str, timeout: float = 5.0, server: str | None = None) -> list[str]:
    """One TXT lookup, UDP with a TCP retry when the answer is truncated."""
    resolver = server or _system_resolver()
    query_id = int.from_bytes(os.urandom(2), "big")
    question = _encode_name(name) + struct.pack(">HH", 16, 1)
    query = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (resolver, 53))
        await loop.sock_sendall(sock, query)
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout)
    finally:
        sock.close()

    if len(data) >= 3 and data[2] & 0x02:   # TC: the answer did not fit in a datagram
        # The UDP read above is bounded but this retry was not, so a resolver that accepted
        # the connection and then stalled hung the whole scan with nothing above it to cancel.
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(resolver, 53)
            try:
                writer.write(struct.pack(">H", len(query)) + query)
                await writer.drain()
                size = struct.unpack(">H", await reader.readexactly(2))[0]
                data = await reader.readexactly(size)
            finally:
                await close_quietly(writer)
    return _parse_txt(data, query_id)


def _system_resolver() -> str:
    """The first nameserver in resolv.conf, falling back to a public resolver."""
    try:
        with open("/etc/resolv.conf") as handle:
            for line in handle:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1 and ":" not in parts[1]:
                        return parts[1]
    except OSError:
        pass
    return "1.1.1.1"


async def _read_http_response(reader: asyncio.StreamReader, limit: int = 65536) -> bytes:
    """Read until the headers are complete.

    `reader.read(n)` returns as soon as any bytes are available - often just the first
    segment. Assuming one read holds the whole response meant a site whose
    Strict-Transport-Security header landed past the first chunk was reported as having no
    HSTS at all, which is a false ISM-1424 finding in someone's compliance report.
    """
    buffer = b""
    while len(buffer) < limit:
        chunk = await reader.read(4096)
        if not chunk:
            break
        buffer += chunk
        if b"\r\n\r\n" in buffer:
            break
    return buffer


async def _fetch_mta_sts_policy(domain: str, timeout: float) -> tuple[str | None, bool]:
    """Read the MTA-STS policy file and return (mode, fetched).

    `fetched` matters as much as the mode: a firewall, a TLS error or a 502 on
    mta-sts.<domain> is not the same as a domain that has not published a policy, and only
    one of those is a control breach.
    """
    context = ssl.create_default_context()
    host = f"mta-sts.{domain}"
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, 443, ssl=context)
            try:
                writer.write(
                    b"GET /.well-known/mta-sts.txt HTTP/1.1\r\n"
                    + f"Host: {host}\r\n".encode()
                    + b"User-Agent: pqscan\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                body = await _read_http_response(reader)
            finally:
                await close_quietly(writer)
    except (TimeoutError, OSError, ssl.SSLError, asyncio.IncompleteReadError, ValueError):
        return None, False
    status = body.split(b"\r\n", 1)[0]
    if b" 200" not in status:
        # RFC 8461 requires the policy be served with a 200. A 404 page that happens to
        # contain the word "mode:" is not a policy.
        return None, True
    _, _, document = body.partition(b"\r\n\r\n")
    match = re.search(rb"^\s*mode\s*:\s*(\w+)", document, re.I | re.M)
    return (match.group(1).decode() if match else None), True


async def _fetch_hsts(domain: str, timeout: float) -> tuple[str | None, int | None, bool]:
    """Read the Strict-Transport-Security response header (ISM-1424).

    The third value says whether the fetch succeeded at all, so an unreachable site is not
    reported as a site that omits the header.
    """
    context = ssl.create_default_context()
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(domain, 443, ssl=context)
            try:
                # GET with a one-byte Range rather than HEAD: some servers answer HEAD
                # with a bare 405 that carries none of the security headers, which would
                # read as "no HSTS" on a site that sets it.
                writer.write(
                    b"GET / HTTP/1.1\r\n" + f"Host: {domain}\r\n".encode()
                    + b"Range: bytes=0-0\r\nUser-Agent: pqscan\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                head = await _read_http_response(reader)
            finally:
                await close_quietly(writer)
    except (TimeoutError, OSError, ssl.SSLError, asyncio.IncompleteReadError, ValueError):
        return None, None, False
    match = re.search(rb"strict-transport-security:\s*([^\r\n]+)", head, re.I)
    if not match:
        return None, None, True
    value = match.group(1).decode("utf-8", "replace").strip()
    age = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    return value, (int(age.group(1)) if age else None), True


async def probe_domain(domain: str, timeout: float = 5.0) -> DomainObservation:
    observation = DomainObservation(domain=domain)

    async def txt(name: str, label: str | None = None) -> list[str]:
        """Resolve, recording whether the lookup itself succeeded.

        A failed lookup and an empty answer are different facts. Conflating them turned a
        DNS timeout into "this domain publishes no DMARC", which lands in a compliance
        report as a breach the operator never committed.
        """
        try:
            records = await resolve_txt(name, timeout)
        except (TimeoutError, OSError, asyncio.IncompleteReadError, ValueError, struct.error) as error:
            # Only the ways a lookup can legitimately fail. A bare `except Exception` here
            # swallowed a NameError from a missing import and reported it as "DNS lookup
            # failed" - the tool looked like it was working and was not.
            observation.errors.append(f"DNS {name}: {type(error).__name__}: {error}")
            return []
        if label:
            observation.observed.add(label)
        return records

    root, dmarc, mta_sts = await asyncio.gather(
        txt(domain, "spf"), txt(f"_dmarc.{domain}", "dmarc"), txt(f"_mta-sts.{domain}", "mta_sts")
    )

    for record in root:
        if record.lower().startswith("v=spf1"):
            observation.spf = record
            # ISM-1183 wants a hard fail. "-all" rejects; "~all" only soft-fails and "?all"
            # does nothing, so neither satisfies the control.
            observation.spf_hard_fail = record.replace(" ", "").endswith("-all")
            break

    for record in dmarc:
        if record.lower().startswith("v=dmarc1"):
            observation.dmarc = record
            policy = re.search(r"\bp\s*=\s*(\w+)", record, re.I)
            observation.dmarc_policy = policy.group(1).lower() if policy else None
            break

    observation.mta_sts_dns = any(r.lower().startswith("v=stsv1") for r in mta_sts)
    if observation.mta_sts_dns:
        mode, fetched = await _fetch_mta_sts_policy(domain, timeout)
        observation.mta_sts_policy_mode = mode
        if not fetched:
            observation.observed.discard("mta_sts")
            observation.errors.append(f"could not fetch https://mta-sts.{domain}/.well-known/mta-sts.txt")

    for selector in DKIM_SELECTORS:
        records = await txt(f"{selector}._domainkey.{domain}")
        if any("p=" in record for record in records):
            observation.dkim_selector = selector
            break

    hsts, max_age, fetched = await _fetch_hsts(domain, timeout)
    observation.hsts, observation.hsts_max_age = hsts, max_age
    if fetched:
        observation.observed.add("hsts")
    else:
        observation.errors.append(f"could not fetch https://{domain}/ to read security headers")

    if not root and not dmarc and observation.errors:
        observation.not_testable_reason = "dns_failure"
    return observation
