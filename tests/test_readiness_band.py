"""PQScan's 0-5 readiness band.

Deliberately not the PKI Consortium's PQCMM: that model rates a named product as shipped, on
evidence a handshake cannot see. These tests pin the distinction this band exists to make -
an endpoint that cannot do post-quantum and one that can but does not are both "classical",
and only the second is a configuration change away from done.
"""
import pytest

from pqc_scan.models import HostFinding, Target
from pqc_scan.scoring import Scorer


def band(readiness, confidentiality, authentication, **kwargs) -> HostFinding:
    finding = HostFinding(target=Target(hostname="x.example"), **kwargs)
    finding.pq_readiness = readiness
    finding.confidentiality_score = confidentiality
    finding.authentication_score = authentication
    Scorer().assign_readiness_band(finding)
    return finding


def test_pure_pq_is_the_top_band():
    result = band("pure_pq_approved", 0, 0)
    assert result.readiness_band == 5
    assert result.readiness_band_name == "PQ approved"


def test_hybrid_in_use_is_band_four():
    assert band("hybrid_transitional", 30, 65).readiness_band == 4


def test_capable_but_not_negotiating_ranks_above_incapable():
    # The distinction the whole band exists for. Both endpoints are classical; one is a
    # preference line away from compliant and the other needs new software.
    capable = band("classical_only", 62, 38, groups_supported=["x25519", "X25519MLKEM768"])
    incapable = band("classical_only", 62, 38, groups_supported=["x25519", "secp256r1"])
    assert capable.readiness_band == 3
    assert capable.readiness_band_name == "PQ capable"
    assert incapable.readiness_band < capable.readiness_band


def test_pq_capability_is_read_from_either_group_list():
    from_probe = band("classical_only", 62, 38, pq_groups_supported=["MLKEM1024"])
    assert from_probe.readiness_band == 3


def test_sound_classical_is_band_two():
    assert band("classical_only", 40, 40).readiness_band == 2


def test_dated_classical_is_band_one():
    assert band("classical_only", 100, 100).readiness_band == 1


@pytest.mark.parametrize(
    "failure",
    ["no_tls_offered", "null_or_export_cipher", "broken_stream_cipher", "weak_dh_parameters"],
)
def test_an_unprotected_endpoint_is_band_zero(failure):
    # Absent security, not low maturity. Scoring these above 0 would let a plaintext service
    # outrank a merely dated one.
    assert band("classical_only", 50, 10, validation_failures=[failure]).readiness_band == 0


def test_obsolete_protocol_is_band_zero_regardless_of_score():
    assert band("classical_only", 20, 20, obsolete_tls_only=True).readiness_band == 0


def test_an_unmeasured_endpoint_gets_no_band():
    result = band("unknown", None, None)
    assert result.readiness_band is None
    assert result.readiness_band_name is None


def test_a_domain_finding_gets_no_band():
    # SPF and DMARC say nothing about an endpoint's cryptographic posture.
    finding = HostFinding(target=Target(hostname="example.gov.au"), service="domain")
    finding.pq_readiness = "unknown"
    finding.authentication_score = 40
    Scorer().assign_readiness_band(finding)
    assert finding.readiness_band is None


def test_bands_never_invert_with_readiness():
    # A post-quantum endpoint must never band below a classical one with identical scores.
    hybrid = band("hybrid_transitional", 65, 100).readiness_band
    classical = band("classical_only", 65, 100).readiness_band
    assert hybrid >= classical


def test_every_band_is_defined_and_named():
    levels = Scorer().weights["readiness_band"]["levels"]
    assert sorted(levels) == [0, 1, 2, 3, 4, 5]
    for key, rules in levels.items():
        assert (rules or {}).get("name"), key
        assert (rules or {}).get("summary"), key


def test_the_band_does_not_claim_to_be_the_pqcmm():
    # The PQCMM rates a product on evidence a scan cannot see. Borrowing its level names
    # would imply a conformance claim this tool has no basis to make.
    names = {
        (rules or {}).get("name") for rules in Scorer().weights["readiness_band"]["levels"].values()
    }
    assert not names & {"Initial", "Foundational", "Advanced", "Managed", "Optimized"}
