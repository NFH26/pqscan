"""IKEv2 probe and IPsec scoring."""
import asyncio
import struct

import pytest

from pqc_scan.ike_probe import (
    DH_GROUP_NAMES,
    IKEObservation,
    _ike_sa_init,
    _key_exchange_value,
    _parse_response,
)
from pqc_scan.models import Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.probes import ProbeContext, probe_ipsec
from pqc_scan.scoring import Scorer


def test_ike_sa_init_is_a_well_formed_initiator_packet():
    spi = b"\x01" * 8
    packet = _ike_sa_init(spi)
    assert packet[:8] == spi
    assert packet[8:16] == b"\x00" * 8      # responder SPI is zero on the first message
    assert packet[16] == 33                  # first payload is SA
    assert packet[17] == 0x20                # IKE version 2.0
    assert packet[18] == 34                  # exchange type IKE_SA_INIT
    assert packet[19] == 0x08                # initiator flag
    assert struct.unpack(">I", packet[24:28])[0] == len(packet)


def test_ecp_key_exchange_value_is_a_real_point_not_random_bytes():
    # Responders validate that an ECP public value is on the curve, so random bytes get
    # rejected and we learn nothing. Two coordinates, no 0x04 tag, per RFC 5903.
    assert len(_key_exchange_value(20)) == 96
    assert len(_key_exchange_value(19)) == 64
    assert _key_exchange_value(20) != _key_exchange_value(20)


def test_parse_response_reads_the_chosen_transforms():
    def transform(last, ttype, tid, attrs=b""):
        return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs

    transforms = (
        transform(False, 1, 20, struct.pack(">HH", 0x800E, 256))   # ENCR_AES_GCM_16, 256-bit
        + transform(False, 2, 7)                                    # PRF_HMAC_SHA2_512
        + transform(False, 3, 0)                                    # NONE
        + transform(True, 4, 20)                                    # ECP_384
    )
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
    sa = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([33, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(sa))

    observation = IKEObservation()
    _parse_response(header + sa, observation)
    assert observation.version_major == 2
    assert observation.encryption == "ENCR_AES_GCM_16"
    assert observation.encryption_key_bits == 256
    assert observation.prf == "PRF_HMAC_SHA2_512"
    assert observation.integrity == "NONE"
    assert observation.dh_group == "ECP_384"


def test_invalid_ke_payload_reveals_the_group_the_responder_wants():
    # NOTIFY body: protocol id, SPI size, notify type, then the data - here the group.
    body = struct.pack(">BBH", 0, 0, 17) + struct.pack(">H", 20)
    notify = struct.pack(">BBH", 0, 0, 4 + len(body)) + body
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([41, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(notify))
    observation = IKEObservation()
    _parse_response(header + notify, observation)
    assert observation.dh_group == "ECP_384"
    assert observation.notify_errors == ["INVALID_KE_PAYLOAD:ECP_384"]


@pytest.mark.parametrize(
    "category,name,expected",
    [
        ("encryption", "ENCR_AES_GCM_16", "APPROVED"),     # ISM-1771's stated preference
        ("encryption", "ENCR_3DES", "NOT_APPROVED"),
        ("prf", "PRF_HMAC_SHA2_512", "APPROVED"),          # ISM-1772's stated preference
        ("prf", "PRF_HMAC_SHA1", "NOT_APPROVED"),
        ("integrity", "NONE", "APPROVED"),                 # ISM-0998 prefers NONE with AEAD
        ("dh_groups", "ECP_384", "TRANSITIONAL"),          # ISM-0999's stated preference
        ("dh_groups", "MODP_1024", "NOT_APPROVED"),
    ],
)
def test_ipsec_classifications_follow_the_ism(category, name, expected):
    assert RuleEngine().classify_ipsec(category, name).value == expected


def _finding(monkeypatch, observation):
    async def fake(host, port, timeout, *a, **k):
        return observation

    monkeypatch.setattr("pqc_scan.probes.probe_ike", fake)
    context = ProbeContext(engine=RuleEngine())
    finding = asyncio.run(probe_ipsec(Target(hostname="gw.example", port=500, protocol="ipsec"), context))
    Scorer().calculate_scores(finding, {}, context.engine)
    return finding


def test_classical_ecdh_gateway_is_not_reported_as_hybrid(monkeypatch):
    # ECP_384 is TRANSITIONAL because ISM-0999 PREFERS it, not because it resists quantum
    # attack. Reading readiness off the classification reported plain ECDH as HYBRID.
    finding = _finding(monkeypatch, IKEObservation(
        responded=True, version_major=2, encryption="ENCR_AES_GCM_16",
        prf="PRF_HMAC_SHA2_512", integrity="NONE", dh_group="ECP_384",
    ))
    assert finding.pq_readiness == "classical_only"
    assert finding.pq_status == "not_supported"


def test_mlkem_gateway_is_post_quantum(monkeypatch):
    finding = _finding(monkeypatch, IKEObservation(
        responded=True, version_major=2, encryption="ENCR_AES_GCM_16",
        prf="PRF_HMAC_SHA2_512", integrity="NONE", dh_group="ML_KEM_1024",
    ))
    assert finding.pq_readiness == "pure_pq_approved"


def test_integrity_none_without_an_aead_cipher_is_a_finding(monkeypatch):
    # ISM-0998 permits NONE only alongside AES-GCM. With a CBC cipher, NONE means the
    # exchange has no integrity protection at all - which the transform name alone hides.
    finding = _finding(monkeypatch, IKEObservation(
        responded=True, version_major=2, encryption="ENCR_AES_CBC",
        prf="PRF_HMAC_SHA2_512", integrity="NONE", dh_group="ECP_384",
    ))
    assert "ipsec_no_integrity_without_aead" in finding.validation_failures


def test_ikev1_only_responder_fails_ism_1233(monkeypatch):
    finding = _finding(monkeypatch, IKEObservation(
        responded=True, version_major=1, encryption="ENCR_3DES",
        prf="PRF_HMAC_SHA1", integrity="AUTH_HMAC_SHA1_96", dh_group="MODP_1024",
    ))
    assert "ike_version_not_approved" in finding.validation_failures
    assert finding.confidentiality_score == 100


def test_unreachable_responder_is_not_testable_rather_than_compliant(monkeypatch):
    finding = _finding(monkeypatch, IKEObservation(not_testable_reason="no_ike_response"))
    assert finding.not_testable_reason == "no_ike_response"
    assert finding.pq_readiness == "unknown"
    assert finding.confidentiality_score is None


def test_every_dh_group_name_is_unique():
    assert len(set(DH_GROUP_NAMES.values())) == len(DH_GROUP_NAMES)


def test_a_cookie_notify_is_recognised():
    # A gateway protecting itself against half-open SAs answers with COOKIE instead of an SA.
    # It sits in the non-error notify range, so an earlier version ignored it and measured
    # nothing against any loaded gateway - which is most production gateways.
    from pqc_scan.ike_probe import NOTIFY_COOKIE

    cookie = b"\xab" * 24
    body = struct.pack(">BBH", 0, 0, NOTIFY_COOKIE) + cookie
    notify = struct.pack(">BBH", 0, 0, 4 + len(body)) + body
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([41, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(notify))
    observation = IKEObservation()
    _parse_response(header + notify, observation)
    assert observation.cookie == cookie
    assert observation.notify_errors == []          # a cookie is a challenge, not an error


def test_a_cookie_retry_leads_with_the_cookie_payload():
    from pqc_scan.ike_probe import _sa_init_body

    spi = b"\x07" * 8
    body = _sa_init_body()
    packet = _ike_sa_init(spi, cookie=b"\xcd" * 24, body=body)
    assert packet[16] == 41                          # RFC 7296: the cookie notify comes first
    assert packet[:8] == spi
    assert struct.unpack(">I", packet[24:28])[0] == len(packet)


def test_a_cookie_retry_resends_an_identical_body():
    # The responder derives its cookie from our nonce and SPI, so a retry carrying a fresh
    # nonce is a different request and earns another cookie - an infinite loop, not a probe.
    from pqc_scan.ike_probe import _sa_init_body

    spi, body = b"\x07" * 8, _sa_init_body()
    first = _ike_sa_init(spi, body=body)
    retry = _ike_sa_init(spi, cookie=b"\xcd" * 24, body=body)
    assert body in first and body in retry


def test_transforms_are_read_past_a_non_zero_spi():
    # RFC 7296 3.3.1: the proposal header is 8 bytes PLUS the declared SPI. Reading from a
    # fixed offset of 8 produced plausible but wrong transform names whenever a responder
    # echoed an SPI - and a wrong name in a compliance report is worse than no answer.
    def transform(last, ttype, tid):
        return struct.pack(">BBHBBH", 0 if last else 3, 0, 8, ttype, 0, tid)

    spi = b"\x09" * 8
    transforms = transform(False, 1, 20) + transform(False, 2, 7) + transform(True, 4, 20)
    proposal = (
        struct.pack(">BBHBBBB", 0, 0, 8 + len(spi) + len(transforms), 1, 1, len(spi), 3)
        + spi + transforms
    )
    sa = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([33, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(sa))

    observation = IKEObservation()
    _parse_response(header + sa, observation)
    assert observation.encryption == "ENCR_AES_GCM_16"
    assert observation.prf == "PRF_HMAC_SHA2_512"
    assert observation.dh_group == "ECP_384"


def test_a_malformed_proposal_length_is_rejected_not_read_past():
    proposal = struct.pack(">BBHBBBB", 0, 0, 4, 1, 1, 0, 1)      # length 4, below the header
    sa = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([33, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(sa))
    with pytest.raises(ValueError):
        _parse_response(header + sa, IKEObservation())


def test_an_spi_longer_than_the_proposal_is_rejected():
    proposal = struct.pack(">BBHBBBB", 0, 0, 12, 1, 1, 200, 1)   # SPI overruns the proposal
    sa = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([33, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(sa))
    with pytest.raises(ValueError):
        _parse_response(header + sa, IKEObservation())
