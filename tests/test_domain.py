"""Domain-level email and web transport controls."""
import asyncio
import struct

import pytest

from pqc_scan.domain_probe import DomainObservation, _encode_name, _parse_txt, _skip_name
from pqc_scan.models import Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.probes import ProbeContext, probe_domain_target
from pqc_scan.scoring import Scorer


def _txt_response(query_id: int, name: str, values: list[str]) -> bytes:
    question = _encode_name(name) + struct.pack(">HH", 16, 1)
    answers = b""
    for value in values:
        encoded = value.encode()
        chunks = b"".join(
            bytes([len(encoded[i:i + 255])]) + encoded[i:i + 255]
            for i in range(0, len(encoded), 255)
        )
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(chunks)) + chunks
    header = struct.pack(">HHHHHH", query_id, 0x8180, 1, len(values), 0, 0)
    return header + question + answers


def test_txt_parser_reads_records_and_rejects_a_forged_id():
    data = _txt_response(0x1234, "example.com", ["v=spf1 -all"])
    assert _parse_txt(data, 0x1234) == ["v=spf1 -all"]
    # A response whose ID does not match the query is not an answer to our question.
    with pytest.raises(ValueError):
        _parse_txt(data, 0x9999)


def test_txt_parser_reassembles_a_record_split_across_strings():
    long_value = "v=DKIM1; k=rsa; p=" + "A" * 400
    data = _txt_response(0x4321, "s._domainkey.example.com", [long_value])
    assert _parse_txt(data, 0x4321) == [long_value]


def test_skip_name_handles_a_compression_pointer():
    assert _skip_name(b"\xc0\x0c", 0) == 2
    assert _skip_name(b"\x03www\x00", 0) == 5


ALL_OBSERVED = {"spf", "dmarc", "mta_sts", "hsts"}


def _score(observation: DomainObservation, monkeypatch, criticality="medium"):
    if not observation.observed and not observation.not_testable_reason:
        # These fixtures describe domains whose lookups all succeeded.
        observation.observed = set(ALL_OBSERVED)
    async def fake(domain, timeout):
        return observation

    monkeypatch.setattr("pqc_scan.probes.probe_domain", fake)
    context = ProbeContext(engine=RuleEngine())
    target = Target(hostname="example.gov.au", port=0, protocol="domain", criticality=criticality)
    finding = asyncio.run(probe_domain_target(target, context))
    Scorer().calculate_scores(finding, {}, context.engine)
    return finding


def test_a_fully_configured_domain_has_no_failures(monkeypatch):
    finding = _score(DomainObservation(
        domain="example.gov.au", spf="v=spf1 -all", spf_hard_fail=True,
        dmarc="v=DMARC1; p=reject", dmarc_policy="reject",
        dkim_selector="default", mta_sts_dns=True, mta_sts_policy_mode="enforce",
        hsts="max-age=31536000", hsts_max_age=31536000,
    ), monkeypatch)
    assert finding.validation_failures == []
    assert finding.authentication_score == 0


def test_soft_fail_spf_does_not_satisfy_ism_1183(monkeypatch):
    # "~all" still delivers forged mail, which is the outcome the control prevents.
    finding = _score(DomainObservation(
        domain="example.gov.au", spf="v=spf1 include:_spf.example.com ~all",
        dmarc="v=DMARC1; p=reject", dmarc_policy="reject",
        mta_sts_dns=True, mta_sts_policy_mode="enforce", hsts="max-age=1",
    ), monkeypatch)
    assert "spf_not_hard_fail (ISM-1183)" in finding.validation_failures


@pytest.mark.parametrize("policy", ["none", "quarantine"])
def test_dmarc_must_reject_not_merely_monitor(monkeypatch, policy):
    finding = _score(DomainObservation(
        domain="example.gov.au", spf="v=spf1 -all", spf_hard_fail=True,
        dmarc=f"v=DMARC1; p={policy}", dmarc_policy=policy,
        mta_sts_dns=True, mta_sts_policy_mode="enforce", hsts="max-age=1",
    ), monkeypatch)
    assert any("dmarc_policy_not_reject" in tag for tag in finding.validation_failures)


def test_mta_sts_in_testing_mode_does_not_satisfy_ism_1589(monkeypatch):
    finding = _score(DomainObservation(
        domain="example.gov.au", spf="v=spf1 -all", spf_hard_fail=True,
        dmarc="v=DMARC1; p=reject", dmarc_policy="reject",
        mta_sts_dns=True, mta_sts_policy_mode="testing", hsts="max-age=1",
    ), monkeypatch)
    assert any("mta_sts_not_enforcing" in tag for tag in finding.validation_failures)


def test_missing_dkim_is_inconclusive_not_a_breach(monkeypatch):
    # A DKIM selector cannot be enumerated - it only appears in a signed message header - so
    # absence of a hit is absence of evidence, and must not be scored as a failure.
    finding = _score(DomainObservation(
        domain="example.gov.au", spf="v=spf1 -all", spf_hard_fail=True,
        dmarc="v=DMARC1; p=reject", dmarc_policy="reject",
        mta_sts_dns=True, mta_sts_policy_mode="enforce", hsts="max-age=1",
        dkim_selector=None,
    ), monkeypatch)
    assert finding.validation_failures == []
    assert any("inconclusive" in tag for tag in finding.rule_findings)


def test_domain_findings_carry_no_confidentiality_score(monkeypatch):
    # An SPF record says nothing about quantum resistance. Inventing a confidentiality
    # number here would imply a measurement that was never made.
    finding = _score(DomainObservation(domain="example.gov.au"), monkeypatch)
    assert finding.confidentiality_score is None
    assert finding.pq_readiness == "unknown"


def test_dns_failure_is_reported_as_not_testable(monkeypatch):
    finding = _score(DomainObservation(
        domain="example.gov.au", not_testable_reason="dns_failure",
        errors=["DNS example.gov.au: TimeoutError"],
    ), monkeypatch)
    assert finding.not_testable_reason == "dns_failure"
    assert finding.authentication_score is None


def test_a_failed_lookup_is_not_reported_as_a_missing_record(monkeypatch):
    # The defect this guards: a DNS timeout on _dmarc used to be indistinguishable from a
    # domain that publishes no DMARC, so a network hiccup became a control breach in a
    # compliance report.
    observation = DomainObservation(domain="example.gov.au", observed={"spf", "hsts"})
    observation.spf, observation.spf_hard_fail = "v=spf1 -all", True
    observation.hsts = "max-age=31536000"
    finding = _score(observation, monkeypatch)
    assert not any("dmarc_absent" in tag for tag in finding.validation_failures)
    assert not any("mta_sts_absent" in tag for tag in finding.validation_failures)
    # It must still be visible, just not as a breach.
    assert any("dmarc (ISM-1540) (not observed" in tag for tag in finding.rule_findings)
    assert any("mta_sts (ISM-1589) (not observed" in tag for tag in finding.rule_findings)


def test_an_unfetchable_site_is_not_reported_as_missing_hsts(monkeypatch):
    observation = DomainObservation(domain="example.gov.au", observed={"spf", "dmarc", "mta_sts"})
    observation.spf, observation.spf_hard_fail = "v=spf1 -all", True
    observation.dmarc, observation.dmarc_policy = "v=DMARC1; p=reject", "reject"
    observation.mta_sts_dns, observation.mta_sts_policy_mode = True, "enforce"
    finding = _score(observation, monkeypatch)
    assert not any("hsts_absent" in tag for tag in finding.validation_failures)
    assert any("hsts (ISM-1424) (not observed" in tag for tag in finding.rule_findings)


def test_a_dns_answer_must_have_the_response_bit_set():
    # A query echoed back, or an off-path datagram, is not an answer to our question.
    import struct

    from pqc_scan.domain_probe import _encode_name, _parse_txt

    question = _encode_name("example.com") + struct.pack(">HH", 16, 1)
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    with pytest.raises(ValueError, match="dns_not_a_response"):
        _parse_txt(query, 0x1234)


def test_http_headers_are_read_past_the_first_chunk():
    # read(n) returns as soon as any bytes are available. Assuming one read holds the whole
    # response reported sites as missing HSTS when the header landed in a later segment.
    import asyncio as _asyncio

    from pqc_scan.domain_probe import _read_http_response

    class Dribbling:
        def __init__(self):
            self.chunks = [
                b"HTTP/1.1 200 OK\r\n", b"Server: x\r\n",
                b"Strict-Transport-Security: max-age=31536000\r\n", b"\r\n",
            ]

        async def read(self, _n):
            return self.chunks.pop(0) if self.chunks else b""

    body = _asyncio.run(_read_http_response(Dribbling()))
    assert b"Strict-Transport-Security" in body


def test_a_programming_error_is_not_reported_as_a_dns_failure(monkeypatch):
    # A bare `except Exception` once swallowed a NameError from a missing import and
    # reported it as "DNS lookup failed". The tool looked like it was working and was not,
    # and the only clue was an odd line in the Issues table.
    import asyncio as _asyncio

    from pqc_scan.domain_probe import probe_domain

    async def broken(*_a, **_k):
        raise NameError("close_quietly is not defined")

    monkeypatch.setattr("pqc_scan.domain_probe.resolve_txt", broken)
    with pytest.raises(NameError):
        _asyncio.run(probe_domain("example.gov.au", 1.0))
