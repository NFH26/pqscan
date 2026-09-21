"""IKEv2 IKE_SA_INIT probe for the ISM's Internet Protocol Security controls.

IKE_SA_INIT is the one exchange in IKEv2 that is entirely plaintext: no encryption, no key
derivation, no certificates. One UDP datagram gets the responder's SA payload back, and that
payload names exactly one chosen proposal - the encryption, PRF, integrity and Diffie-Hellman
transforms it settled on. The ISM's IPsec section is written in that same transform-registry
vocabulary, so the mapping is direct rather than interpretive:

    ISM-1233  IKE version 2 is used                 -> we got a v2 response at all
    ISM-1771  AES, preferably ENCR_AES_GCM_16       -> the ENCR transform and its key length
    ISM-1772  PRF_HMAC_SHA2_256/384/512             -> the PRF transform
    ISM-0998  AUTH_HMAC_SHA2_*, preferably NONE     -> the INTEG transform
    ISM-0999  DH/ECDH, preferably 384-bit ECP,      -> the D-H transform
              3072-bit MODP or 4096-bit MODP

The remaining four IPsec controls are not reachable here and we say so rather than guess:
tunnel vs transport mode (ISM-0494) and ESP vs AH (ISM-0496) are settled in IKE_AUTH, which
needs credentials; SA lifetime (ISM-0498) is local policy that IKEv2 does not carry in the SA
payload at all; and Child SA PFS (ISM-1000) only appears in CREATE_CHILD_SA.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct
from dataclasses import dataclass, field

# RFC 7296 transform types
TRANSFORM_ENCR, TRANSFORM_PRF, TRANSFORM_INTEG, TRANSFORM_DH = 1, 2, 3, 4

ENCRYPTION_NAMES = {
    3: "ENCR_3DES", 6: "ENCR_CAST", 7: "ENCR_BLOWFISH", 11: "ENCR_NULL",
    12: "ENCR_AES_CBC", 13: "ENCR_AES_CTR", 14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12", 16: "ENCR_AES_CCM_16", 18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12", 20: "ENCR_AES_GCM_16", 23: "ENCR_CAMELLIA_CBC",
    28: "ENCR_CHACHA20_POLY1305",
}
PRF_NAMES = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256", 6: "PRF_HMAC_SHA2_384", 7: "PRF_HMAC_SHA2_512",
}
INTEGRITY_NAMES = {
    0: "NONE", 1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96", 5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}
DH_GROUP_NAMES = {
    1: "MODP_768", 2: "MODP_1024", 5: "MODP_1536", 14: "MODP_2048",
    15: "MODP_3072", 16: "MODP_4096", 17: "MODP_6144", 18: "MODP_8192",
    19: "ECP_256", 20: "ECP_384", 21: "ECP_521", 31: "CURVE25519", 32: "CURVE448",
    35: "ML_KEM_512", 36: "ML_KEM_768", 37: "ML_KEM_1024",
}

# What we offer. Deliberately broad: we want to learn what the responder will settle for,
# not to prove it can do one strong thing. Weak transforms are included on purpose, because
# a gateway that accepts 3DES is the finding.
OFFERED_ENCRYPTION = ((20, 256), (20, 128), (12, 256), (12, 128), (3, None))
OFFERED_PRF = (7, 6, 5, 2)
OFFERED_INTEGRITY = (14, 13, 12, 2, 0)
OFFERED_DH = (20, 19, 15, 16, 14, 2)

# The group we actually send a KE payload for. If the responder wants a different one it
# replies INVALID_KE_PAYLOAD naming its choice, which answers ISM-0999 just as well.
KE_GROUP = 14

# Byte length of the KE public value for each group we can send one for. MODP values are
# plain integers of the modulus size; ECP values are an uncompressed point with the leading
# 0x04 tag stripped, per RFC 5903, so two coordinates and no tag.
KE_LENGTHS = {2: 128, 14: 256, 15: 384, 16: 512, 19: 64, 20: 96, 21: 132, 31: 32, 32: 56}
ECP_CURVES = {19: "SECP256R1", 20: "SECP384R1", 21: "SECP521R1"}


def _key_exchange_value(group: int) -> bytes:
    """A public value the responder will accept as well-formed for this group.

    MODP groups take any integer of the right width, so random bytes are fine - we never
    derive a key from it. ECP groups do not: the responder validates that the point is on the
    curve, so we generate a real one. We still never complete the exchange.
    """
    length = KE_LENGTHS.get(group)
    if group in ECP_CURVES:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec

            curve = getattr(ec, ECP_CURVES[group])()
            numbers = ec.generate_private_key(curve).public_key().public_numbers()
            size = (curve.key_size + 7) // 8
            return numbers.x.to_bytes(size, "big") + numbers.y.to_bytes(size, "big")
        except Exception:
            return os.urandom(length or 64)
    return os.urandom(length or 256)


# RFC 7296 notify message types we act on.
NOTIFY_INVALID_KE_PAYLOAD = 17
NOTIFY_COOKIE = 16390


@dataclass
class IKEObservation:
    responded: bool = False
    version_major: int | None = None
    encryption: str | None = None
    encryption_key_bits: int | None = None
    prf: str | None = None
    integrity: str | None = None
    dh_group: str | None = None
    notify_errors: list[str] = field(default_factory=list)
    cookie: bytes | None = None
    errors: list[str] = field(default_factory=list)
    not_testable_reason: str | None = None


def _attribute(attr_type: int, value: int) -> bytes:
    """A transform attribute in the short (AF=1) form; only key length is ever sent."""
    return struct.pack(">HH", 0x8000 | attr_type, value)


def _transform(last: bool, transform_type: int, transform_id: int, key_bits: int | None) -> bytes:
    body = _attribute(14, key_bits) if key_bits else b""
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(body), transform_type, 0, transform_id) + body


def _proposal() -> bytes:
    transforms: list[bytes] = []
    for transform_id, key_bits in OFFERED_ENCRYPTION:
        transforms.append(_transform(False, TRANSFORM_ENCR, transform_id, key_bits))
    for transform_id in OFFERED_PRF:
        transforms.append(_transform(False, TRANSFORM_PRF, transform_id, None))
    for transform_id in OFFERED_INTEGRITY:
        transforms.append(_transform(False, TRANSFORM_INTEG, transform_id, None))
    for transform_id in OFFERED_DH:
        transforms.append(_transform(False, TRANSFORM_DH, transform_id, None))
    # Mark the final transform as last.
    tail = transforms[-1]
    transforms[-1] = bytes([0]) + tail[1:]
    blob = b"".join(transforms)
    # Proposal: last(0), reserved, length, number, protocol IKE(1), SPI size 0, #transforms
    return struct.pack(">BBHBBBB", 0, 0, 8 + len(blob), 1, 1, 0, len(transforms)) + blob


def _payload(next_payload: int, body: bytes) -> bytes:
    return struct.pack(">BBH", next_payload, 0, 4 + len(body)) + body


def _sa_init_body(group: int = KE_GROUP) -> bytes:
    """The SA, KE and Nonce payloads of an IKE_SA_INIT, built once.

    Built separately because a cookie retry must resend the IDENTICAL body. The responder
    derives its cookie from our nonce and SPI, so a retry carrying a fresh nonce is a
    different request and simply earns another cookie - which is an infinite loop, not a
    probe.
    """
    sa = _payload(34, _proposal())                                   # next: KE
    ke = _payload(40, struct.pack(">HH", group, 0) + _key_exchange_value(group))  # next: Nonce
    nonce = _payload(0, os.urandom(32))                              # next: none
    return sa + ke + nonce


def _ike_sa_init(
    initiator_spi: bytes,
    group: int = KE_GROUP,
    cookie: bytes | None = None,
    body: bytes | None = None,
) -> bytes:
    body = _sa_init_body(group) if body is None else body
    first = 33                                                       # SA, unless a cookie leads
    if cookie is not None:
        # RFC 7296 section 2.6: when the responder is protecting itself against half-open
        # SAs it answers with a COOKIE and ignores any request that does not echo it back.
        # The cookie notify must come FIRST, before the SA payload.
        body = _payload(33, struct.pack(">BBH", 0, 0, NOTIFY_COOKIE) + cookie) + body
        first = 41
    header = (
        initiator_spi + b"\x00" * 8
        + bytes([first])       # next payload
        + bytes([0x20])        # version 2.0
        + bytes([34])          # exchange type: IKE_SA_INIT
        + bytes([0x08])        # flags: initiator
        + struct.pack(">II", 0, 28 + len(body))
    )
    return header + body


def _parse_transforms(blob: bytes, observation: IKEObservation, limit: int = 255) -> None:
    position = 0
    seen = 0
    while position + 8 <= len(blob) and seen < limit:
        seen += 1
        last, _, length, transform_type, _, transform_id = struct.unpack(">BBHBBH", blob[position:position + 8])
        if length < 8 or position + length > len(blob):
            raise ValueError("malformed_transform")
        attributes = blob[position + 8:position + length]
        if transform_type == TRANSFORM_ENCR:
            observation.encryption = ENCRYPTION_NAMES.get(transform_id, f"ENCR_{transform_id}")
            if len(attributes) >= 4:
                attr_type, value = struct.unpack(">HH", attributes[:4])
                if attr_type & 0x7FFF == 14:
                    observation.encryption_key_bits = value
        elif transform_type == TRANSFORM_PRF:
            observation.prf = PRF_NAMES.get(transform_id, f"PRF_{transform_id}")
        elif transform_type == TRANSFORM_INTEG:
            observation.integrity = INTEGRITY_NAMES.get(transform_id, f"INTEG_{transform_id}")
        elif transform_type == TRANSFORM_DH:
            observation.dh_group = DH_GROUP_NAMES.get(transform_id, f"GROUP_{transform_id}")
        position += length
        if last == 0:
            break


def _parse_proposals(body: bytes, observation: IKEObservation) -> None:
    """Read the responder's chosen proposal out of an SA payload.

    RFC 7296 section 3.3.1: a proposal substructure is an 8-byte header PLUS an SPI of the
    declared size, and Proposal Length bounds its transforms. Reading transforms from a fixed
    offset of 8 and handing the parser everything after it produced plausible but wrong
    ENCR/PRF/INTEG/DH names whenever a responder echoed a non-zero SPI - and a wrong transform
    name in a compliance report is worse than no answer, because nobody checks it.

    A responder returns exactly one chosen proposal, so the first is the answer.
    """
    position = 0
    while position + 8 <= len(body):
        _, _, length, _, _, spi_size, transform_count = struct.unpack(
            ">BBHBBBB", body[position:position + 8]
        )
        if length < 8 or position + length > len(body):
            raise ValueError("malformed_proposal")
        start = position + 8 + spi_size
        if start > position + length:
            raise ValueError("malformed_proposal_spi")
        _parse_transforms(body[start:position + length], observation, transform_count)
        return
    if body:
        raise ValueError("truncated_sa_payload")


def _parse_response(data: bytes, observation: IKEObservation) -> None:
    if len(data) < 28:
        raise ValueError("truncated_header")
    observation.version_major = data[17] >> 4
    next_payload = data[16]
    position = 28
    while position + 4 <= len(data) and next_payload != 0:
        this_payload = next_payload
        next_payload, _, length = struct.unpack(">BBH", data[position:position + 4])
        if length < 4 or position + length > len(data):
            raise ValueError("malformed_payload")
        body = data[position + 4:position + length]
        if this_payload == 33:                               # SA
            _parse_proposals(body, observation)
        elif this_payload == 41 and len(body) >= 4:          # NOTIFY
            notify_type = struct.unpack(">H", body[2:4])[0]
            if notify_type == NOTIFY_COOKIE:
                observation.cookie = body[4:]
            elif notify_type < 16384:                        # error range
                if notify_type == NOTIFY_INVALID_KE_PAYLOAD and len(body) >= 6:
                    wanted = struct.unpack(">H", body[4:6])[0]
                    observation.dh_group = DH_GROUP_NAMES.get(wanted, f"GROUP_{wanted}")
                    observation.notify_errors.append(f"INVALID_KE_PAYLOAD:{observation.dh_group}")
                else:
                    observation.notify_errors.append(f"NOTIFY_{notify_type}")
        position += length


async def probe_ike(
    host: str,
    port: int = 500,
    timeout: float = 5.0,
    group: int = KE_GROUP,
    _retry: bool = True,
    _cookie: bytes | None = None,
    _spi: bytes | None = None,
    _body: bytes | None = None,
) -> IKEObservation:
    """Send one IKE_SA_INIT and read the responder's chosen transforms."""
    observation = IKEObservation()
    initiator_spi = _spi or os.urandom(8)
    body = _body if _body is not None else _sa_init_body(group)
    packet = _ike_sa_init(initiator_spi, group, _cookie, body)
    if port == 4500:
        # RFC 3948: IKE on 4500 is prefixed with a four-byte zero non-ESP marker so it can be
        # told apart from ESP traffic sharing the port.
        packet = b"\x00\x00\x00\x00" + packet

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, packet)
        # UDP gives no delivery signal, so silence is ambiguous: a firewall drop and an
        # absent responder look identical. Retry once before calling it unreachable.
        for attempt in range(2):
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout)
                break
            except TimeoutError:
                if attempt == 1:
                    observation.not_testable_reason = "no_ike_response"
                    observation.errors.append(
                        f"no IKE response from {host}:{port} after {timeout}s "
                        "(no responder, or UDP filtered in between)"
                    )
                    return observation
                await loop.sock_sendall(sock, packet)
        if port == 4500 and data[:4] == b"\x00\x00\x00\x00":
            data = data[4:]
        if data[:8] != initiator_spi:
            observation.not_testable_reason = "spi_mismatch"
            observation.errors.append("IKE response did not match the initiator SPI")
            return observation
        observation.responded = True
        _parse_response(data, observation)

        if observation.cookie is not None and _cookie is None:
            # Not an error and not a finding: the gateway is asking us to prove we can
            # receive at the address we claimed. Any gateway under load does this, which is
            # most production gateways, so a probe that ignores it measures nothing there.
            with_cookie = await probe_ike(
                host, port, timeout, group=group, _retry=_retry,
                _cookie=observation.cookie, _spi=initiator_spi, _body=body,
            )
            if with_cookie.responded:
                with_cookie.notify_errors = ["COOKIE_CHALLENGE_ANSWERED", *with_cookie.notify_errors]
                return with_cookie

        wanted = next(
            (name for name in observation.notify_errors if name.startswith("INVALID_KE_PAYLOAD:")),
            None,
        )
        if wanted and _retry:
            # The responder told us which group it wants. Asking again with that group turns
            # a one-field answer into the full transform set, which is four more controls.
            code = next(
                (k for k, v in DH_GROUP_NAMES.items() if v == wanted.split(":", 1)[1]), None
            )
            if code is not None and code != group:
                second = await probe_ike(host, port, timeout, group=code, _retry=False)
                if second.responded and second.encryption:
                    second.notify_errors = observation.notify_errors + second.notify_errors
                    return second
    except (OSError, ValueError, struct.error) as error:
        observation.not_testable_reason = "ike_probe_failed"
        observation.errors.append(f"{type(error).__name__}: {error}")
    finally:
        sock.close()
    return observation
