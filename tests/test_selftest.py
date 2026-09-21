"""The self-test's own logic, checked without touching the network."""

from pqc_scan.models import HostFinding, Target
from pqc_scan.selftest import FAIL, PASS, UNREACHABLE, check, load_cases


def finding(**kwargs) -> HostFinding:
    base = {"target": Target(hostname="x.example", port=443)}
    base.update(kwargs)
    return HostFinding(**base)


def case(**expect) -> dict:
    return {"name": "case", "host": "x.example", "port": 443, "expect": expect}


def test_a_matching_finding_passes():
    result = check(
        case(service="tls", readiness="hybrid_transitional", measured=True, group_contains="MLKEM"),
        finding(service="tls", pq_readiness="hybrid_transitional",
                negotiated_group="X25519MLKEM768", confidentiality_score=20),
    )
    assert result.status == PASS


def test_an_unreachable_endpoint_is_not_a_failure():
    # Outbound UDP 500 and port 21 are commonly filtered. Calling that a scanner defect
    # would train the operator to ignore the output, which defeats the whole command.
    for reason in ("timeout", "dns_failure", "no_ike_response", "service_unavailable"):
        result = check(case(service="tls", measured=True), finding(not_testable_reason=reason))
        assert result.status == UNREACHABLE, reason


def test_an_unmeasured_endpoint_fails():
    # The failure this tool exists to avoid: going quiet on the hosts that matter most.
    result = check(case(measured=True), finding(service="tls", confidentiality_score=None))
    assert result.status == FAIL
    assert "not measured" in result.detail


def test_wrong_readiness_fails_with_both_values_named():
    result = check(
        case(readiness="hybrid_transitional"),
        finding(service="tls", pq_readiness="classical_only", confidentiality_score=10),
    )
    assert result.status == FAIL
    assert "classical_only" in result.detail and "hybrid_transitional" in result.detail


def test_a_required_finding_that_is_missing_fails():
    result = check(case(findings=["expired"]), finding(service="tls", confidentiality_score=10))
    assert result.status == FAIL
    assert "missing finding" in result.detail


def test_a_forbidden_finding_that_appears_fails():
    result = check(
        case(absent=["strict_verify_error"]),
        finding(service="tls", confidentiality_score=10,
                handshake_errors=[], validation_failures=["strict_verify_error:boom"]),
    )
    assert result.status == FAIL
    assert "unexpected finding" in result.detail


def test_band_bounds_are_enforced_in_both_directions():
    assert check(case(max_band=0), finding(service="tls", confidentiality_score=100, readiness_band=2)).status == FAIL
    assert check(case(min_band=3), finding(service="tls", confidentiality_score=10, readiness_band=1)).status == FAIL
    assert check(case(min_band=3), finding(service="tls", confidentiality_score=10, readiness_band=3)).status == PASS


def test_a_missing_band_does_not_silently_satisfy_a_bound():
    # pqcmm_level of None must not compare as "within range".
    assert check(case(max_band=0), finding(service="tls", confidentiality_score=100, readiness_band=None)).status == FAIL


def test_every_protocol_the_scanner_supports_has_a_case():

    services = {(c.get("expect") or {}).get("service") for c in load_cases()}
    # ikev2 is an alias for the ipsec probe, so the service names are what must be covered.
    assert {"tls", "ssh", "ipsec", "domain"} <= services


def test_shipped_cases_are_well_formed():
    for entry in load_cases():
        assert entry.get("name") and entry.get("host") is not None
        assert isinstance(entry.get("expect"), dict) and entry["expect"], entry["name"]
