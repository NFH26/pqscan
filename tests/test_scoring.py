import datetime
import re

import pytest

from pqc_scan.models import CertificateData, Classification, HostFinding, Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.scoring import Scorer


@pytest.fixture
def dummy_engine():
    return RuleEngine("asd_ism")

def test_chain_classification_vs_auth_score(dummy_engine):
    scorer = Scorer()

    leaf_cert = CertificateData(
        fingerprint_sha256="leaf",
        subject_cn="leaf.local",
        issuer="Root CA",
        not_before=datetime.datetime.now(datetime.UTC),
        not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="RSA",
        pub_key_size=2048,
        sig_algo="sha256WithRSAEncryption",
        sig_hash="sha256",
        is_self_signed=False,
        pub_key_classification=Classification.APPROVED,
        sig_classification=Classification.APPROVED
    )
    strong_int = CertificateData(
        fingerprint_sha256="strong",
        subject_cn="Strong CA",
        issuer="Root CA",
        not_before=datetime.datetime.now(datetime.UTC),
        not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="ML-DSA",
        pub_key_size=None,
        sig_algo="ml-dsa-87",
        sig_hash="sha384",
        is_self_signed=False,
        pub_key_classification=Classification.APPROVED,
        sig_classification=Classification.APPROVED
    )
    weak_int = CertificateData(
        fingerprint_sha256="weak",
        subject_cn="Weak CA",
        issuer="Root CA",
        not_before=datetime.datetime.now(datetime.UTC),
        not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="RSA",
        pub_key_size=1024,
        sig_algo="sha1WithRSAEncryption",
        sig_hash="sha1",
        is_self_signed=False,
        pub_key_classification=Classification.NOT_APPROVED_AFTER_2030,
        sig_classification=Classification.NOT_APPROVED_AFTER_2030
    )

    certs_map = {"leaf": leaf_cert, "strong": strong_int, "weak": weak_int}

    host1 = HostFinding(target=Target(hostname="clean", criticality="medium"), certificate_fingerprints=["leaf", "strong"])
    host2 = HostFinding(target=Target(hostname="dirty", criticality="medium"), certificate_fingerprints=["leaf", "weak"])

    scorer.calculate_scores(host1, certs_map, dummy_engine)
    scorer.calculate_scores(host2, certs_map, dummy_engine)

    assert host2.authentication_score > host1.authentication_score
    assert host1.chain_classification != host2.chain_classification
    assert host2.chain_classification == Classification.NOT_APPROVED_AFTER_2030
    assert "worst hash in chain: NOT_APPROVED (+20)" in host2.authentication_explanation

def test_criticality_multipliers(dummy_engine):
    scorer = Scorer()
    leaf_cert = CertificateData(
        fingerprint_sha256="leaf", subject_cn="l.local", issuer="Root",
        not_before=datetime.datetime.now(datetime.UTC), not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="RSA", pub_key_size=2048, sig_algo="sha256WithRSAEncryption", sig_hash="sha256",
        is_self_signed=False, pub_key_classification=Classification.APPROVED, sig_classification=Classification.APPROVED
    )
    certs_map = {"leaf": leaf_cert}

    # Use a known negotiated group so confidentiality score evaluates properly
    f_low = HostFinding(target=Target(hostname="t", criticality="low"), certificate_fingerprints=["leaf"], negotiated_group="X25519", pq_status="not_supported")
    f_high = HostFinding(target=Target(hostname="t", criticality="high"), certificate_fingerprints=["leaf"], negotiated_group="X25519", pq_status="not_supported")

    scorer.calculate_scores(f_low, certs_map, dummy_engine)
    scorer.calculate_scores(f_high, certs_map, dummy_engine)

    assert f_low.confidentiality_score is not None
    assert f_high.confidentiality_score is not None
    assert f_low.confidentiality_score != f_high.confidentiality_score
    assert f_high.confidentiality_score > f_low.confidentiality_score
    assert f_low.pq_readiness == "classical_only"


def test_pq_readiness_uses_profile_mapping(dummy_engine):
    scorer = Scorer()
    finding = HostFinding(
        target=Target(hostname="hybrid"),
        negotiated_group="X25519MLKEM768",
        pq_status="supported",
    )

    scorer.calculate_scores(finding, {}, dummy_engine)

    assert finding.pq_readiness == "hybrid_transitional"


def test_non_tls13_adds_ism1139_finding_even_when_score_caps(dummy_engine):
    scorer = Scorer()
    finding = HostFinding(
        target=Target(hostname="legacy"),
        tls_version="TLSv1.2",
        negotiated_group="secp256r1",
        pq_status="not_supported",
    )

    scorer.calculate_scores(finding, {}, dummy_engine)

    assert "tls_version_not_approved (ISM-1139)" in finding.rule_findings


def test_cipher_and_classification_findings_are_preserved(dummy_engine):
    scorer = Scorer()
    finding = HostFinding(
        target=Target(hostname="secret", classification="S"),
        tls_version="TLSv1.3",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        negotiated_group="x25519",
        pq_status="not_supported",
    )

    scorer.calculate_scores(finding, {}, dummy_engine)

    assert "cipher_not_aes_gcm (ISM-1369)" in finding.rule_findings


def test_tls13_always_has_forward_secrecy_but_tls12_rsa_does_not(dummy_engine):
    scorer = Scorer()
    tls13 = HostFinding(
        target=Target(hostname="tls13"),
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
        pq_status="supported",
    )
    tls12 = HostFinding(
        target=Target(hostname="tls12"),
        tls_version="TLSv1.2",
        cipher_suite="TLS_RSA_WITH_AES_128_GCM_SHA256",
        negotiated_group="secp256r1",
        pq_status="not_supported",
    )

    scorer.calculate_scores(tls13, {}, dummy_engine)
    scorer.calculate_scores(tls12, {}, dummy_engine)

    assert "no_forward_secrecy (ISM-1372, ISM-1453)" not in tls13.rule_findings
    assert "no_forward_secrecy (ISM-1372, ISM-1453)" in tls12.rule_findings


def test_explanation_terms_sum_to_confidentiality_subtotal(dummy_engine):
    scorer = Scorer()
    finding = HostFinding(
        target=Target(hostname="terms", criticality="medium"),
        tls_version="TLSv1.2",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        negotiated_group="secp256r1",
        pq_status="not_supported",
    )

    scorer.calculate_scores(finding, {}, dummy_engine)

    explanation = finding.confidentiality_explanation
    subtotal = int(re.search(r"subtotal (\d+)", explanation).group(1))
    terms = [int(value) for value in re.findall(r"\(\+(\d+)\)", explanation)]
    assert sum(terms) == subtotal
    assert "tls_version_not_approved (ISM-1139)" in finding.rule_findings
    assert "cipher_not_aes_gcm (ISM-1369)" in finding.rule_findings
    assert "no_forward_secrecy (ISM-1372, ISM-1453)" in finding.rule_findings

def test_unmeasured_host_excluded(dummy_engine):
    scorer = Scorer()
    finding = HostFinding(target=Target(hostname="test", criticality="medium"), negotiated_group="unknown")
    scorer.calculate_scores(finding, {}, dummy_engine)
    assert finding.confidentiality_score is None

def test_empty_chain_is_none(dummy_engine):
    scorer = Scorer()
    finding = HostFinding(target=Target(hostname="test", criticality="medium"), certificate_fingerprints=[])
    scorer.calculate_scores(finding, {}, dummy_engine)
    assert finding.chain_classification is None


def test_single_self_signed_certificate_is_not_approved(dummy_engine):
    scorer = Scorer()
    certificate = CertificateData(
        fingerprint_sha256="self-signed",
        subject_cn="self-signed.local",
        issuer="self-signed.local",
        not_before=datetime.datetime.now(datetime.UTC),
        not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="RSA",
        pub_key_size=2048,
        sig_algo="sha256WithRSAEncryption",
        sig_hash="sha256",
        is_self_signed=True,
        pub_key_classification=Classification.NOT_APPROVED_AFTER_2030,
        sig_classification=Classification.NOT_APPROVED_AFTER_2030,
    )
    finding = HostFinding(
        target=Target(hostname="self-signed.local"),
        certificate_fingerprints=[certificate.fingerprint_sha256],
        negotiated_group="X25519",
        pq_status="not_supported",
    )

    scorer.calculate_scores(finding, {certificate.fingerprint_sha256: certificate}, dummy_engine)

    assert finding.chain_classification == Classification.REVIEW
    assert finding.chain_classification != Classification.APPROVED


def test_worst_intermediate_is_one_chain_penalty(dummy_engine):
    scorer = Scorer()
    leaf = CertificateData(
        fingerprint_sha256="leaf-ecdsa", subject_cn="Leaf", sig_algo="ecdsa-with-SHA256", sig_hash="sha256",
        not_before=datetime.datetime.now(datetime.UTC), not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="ECDSA", pub_key_classification=Classification.NOT_APPROVED_AFTER_2030,
        sig_classification=Classification.NOT_APPROVED_AFTER_2030,
    )
    rsa_one = CertificateData(
        fingerprint_sha256="rsa-1", subject_cn="RSA One", sig_algo="sha256WithRSAEncryption", sig_hash="sha256",
        not_before=datetime.datetime.now(datetime.UTC), not_after=datetime.datetime.now(datetime.UTC),
        pub_key_algo="RSA", pub_key_classification=Classification.NOT_APPROVED_AFTER_2030,
        sig_classification=Classification.NOT_APPROVED_AFTER_2030,
    )
    rsa_two = rsa_one.model_copy(update={"fingerprint_sha256": "rsa-2", "subject_cn": "RSA Two"})
    sha1 = rsa_one.model_copy(
        update={
            "fingerprint_sha256": "sha1",
            "subject_cn": "SHA1 Intermediate",
            "sig_algo": "sha1WithRSAEncryption",
            "sig_hash": "sha1",
            "sig_classification": Classification.NOT_APPROVED,
        }
    )
    certs = {cert.fingerprint_sha256: cert for cert in (leaf, rsa_one, rsa_two, sha1)}

    one_rsa = HostFinding(target=Target(hostname="one-rsa", criticality="low"), certificate_fingerprints=["leaf-ecdsa", "rsa-1"], negotiated_group="X25519")
    two_rsa = HostFinding(target=Target(hostname="two-rsa", criticality="low"), certificate_fingerprints=["leaf-ecdsa", "rsa-1", "rsa-2"], negotiated_group="X25519")
    with_sha1 = HostFinding(target=Target(hostname="with-sha1", criticality="low"), certificate_fingerprints=["leaf-ecdsa", "rsa-1", "sha1"], negotiated_group="X25519")

    for finding in (one_rsa, two_rsa, with_sha1):
        scorer.calculate_scores(finding, certs, dummy_engine)

    assert one_rsa.authentication_score == two_rsa.authentication_score
    assert with_sha1.authentication_score > one_rsa.authentication_score
    assert "weakest signature in chain: sha1WithRSAEncryption on SHA1 Intermediate -> NOT_APPROVED" in with_sha1.authentication_explanation


def test_authentication_score_expected_policy_values(dummy_engine):
    scorer = Scorer()
    now = datetime.datetime.now(datetime.UTC)

    def certificate(name, sig_algo, sig_hash, classification, self_signed=False):
        return CertificateData(
            fingerprint_sha256=name,
            subject_cn=name,
            not_before=now,
            not_after=now,
            pub_key_algo="RSA",
            sig_algo=sig_algo,
            sig_hash=sig_hash,
            is_self_signed=self_signed,
            pub_key_classification=classification,
            sig_classification=classification,
        )

    leaf = certificate("leaf", "sha256WithRSAEncryption", "sha256", Classification.NOT_APPROVED_AFTER_2030)
    intermediate = certificate("intermediate", "sha256WithRSAEncryption", "sha256", Classification.NOT_APPROVED_AFTER_2030)
    sha1 = certificate("sha1", "sha1WithRSAEncryption", "sha1", Classification.NOT_APPROVED)
    certs = {c.fingerprint_sha256: c for c in (leaf, intermediate, sha1)}

    def score(finding, fingerprints):
        finding.certificate_fingerprints = fingerprints
        scorer.calculate_scores(finding, certs, dummy_engine)
        return finding.authentication_score

    assert score(HostFinding(target=Target(hostname="clean")), ["leaf", "intermediate"]) == 60
    assert score(HostFinding(target=Target(hostname="expired"), validation_failures=["expired"]), ["leaf", "intermediate"]) == 80
    assert score(HostFinding(target=Target(hostname="hostname"), validation_failures=["hostname_mismatch"]), ["leaf", "intermediate"]) == 80
    self_signed_leaf = leaf.model_copy(update={"is_self_signed": True})
    certs["leaf"] = self_signed_leaf
    assert score(HostFinding(target=Target(hostname="self"), validation_failures=["no_chain (self_signed)", "untrusted_issuer"]), ["leaf"]) == 100
    assert score(HostFinding(target=Target(hostname="sha1")), ["leaf", "sha1"]) == 100
    assert score(HostFinding(target=Target(hostname="incomplete"), validation_failures=["untrusted_issuer", "incomplete_chain"]), ["leaf", "intermediate"]) == 100
    assert score(HostFinding(target=Target(hostname="high", criticality="high")), ["leaf", "intermediate"]) == 78


def test_remediation_maps_findings_to_actions():
    from pqc_scan.models import HostFinding, Target
    from pqc_scan.parsers import RuleEngine
    from pqc_scan.remediation import actions_for, consolidate

    engine = RuleEngine("asd_ism")
    classical = HostFinding(
        target=Target(hostname="old.example", port=443, criticality="high"),
        pq_readiness="classical_only",
        rule_findings=["tls_version_not_approved (ISM-1139)", "expired", "key_size_below_preferred (informational)"],
    )
    hybrid = HostFinding(
        target=Target(hostname="new.example", port=443),
        pq_readiness="hybrid_transitional",
        rule_findings=["tls_version_not_approved (ISM-1139)"],
    )
    unreachable = HostFinding(
        target=Target(hostname="dead.example", port=443),
        not_testable_reason="dns_failure", rule_findings=["tls_version_not_approved (ISM-1139)"],
    )

    actions = actions_for(classical, engine)
    assert actions, "a classical host must produce advice"
    assert actions[0].priority == 1
    assert all(action.why for action in actions), "every action explains itself"
    # a preference is advice, but never the first thing asked for
    assert actions[-1].effort == "certificate"

    # an endpoint that could not be measured gets no advice: we do not know anything about it
    assert actions_for(unreachable, engine) == []

    # NOT_APPROVED_AFTER_2030 must not fall through to the NOT_APPROVED entry
    chain = HostFinding(target=Target(hostname="c.example", port=443), rule_findings=["NOT_APPROVED_AFTER_2030"])
    assert "retire at the end of 2030" in actions_for(chain, engine)[0].action

    # one config change that fixes two hosts outranks a single-host change of equal priority
    estate = consolidate([classical, hybrid, unreachable], engine)
    tls_action = next(a for a in estate if "TLS 1.3" in a.action and "disable" in a.action)
    assert sorted(tls_action.hosts) == ["new.example:443 (tls)", "old.example:443 (tls)"]
    assert estate.index(tls_action) < len(estate) - 1


def test_advice_names_the_service_not_just_the_host():
    """An estate can run two VPNs and a dozen SSH hosts.

    Advice that says "12 endpoints" tells nobody which box to log into, so every action
    carries its endpoints and every endpoint carries the service it runs.
    """
    from pqc_scan.models import HostFinding, Target
    from pqc_scan.parsers import RuleEngine
    from pqc_scan.remediation import consolidate, endpoint_label

    engine = RuleEngine("asd_ism")
    ssh = HostFinding(
        target=Target(hostname="jump.example", port=22), service="ssh",
        pq_readiness="classical_only",
    )
    vpn_a = HostFinding(
        target=Target(hostname="vpn-a.example", port=500), service="ipsec",
        pq_readiness="classical_only",
    )
    vpn_b = HostFinding(
        target=Target(hostname="vpn-b.example", port=500), service="ipsec",
        pq_readiness="classical_only",
    )
    domain = HostFinding(
        target=Target(hostname="example.com", port=0), service="domain",
        pq_readiness="classical_only",
    )

    assert endpoint_label(ssh) == "jump.example:22 (ssh)"
    assert endpoint_label(vpn_a) == "vpn-a.example:500 (ipsec)"
    # A domain control has no port, so a ":0" would be a lie.
    assert endpoint_label(domain) == "example.com (domain)"

    shared = consolidate([ssh, vpn_a, vpn_b, domain], engine)
    assert shared, "classical endpoints must produce advice"
    covered = {host for action in shared for host in action.hosts}
    # The two VPNs stay distinguishable: a reader can tell which concentrator to change.
    assert "vpn-a.example:500 (ipsec)" in covered
    assert "vpn-b.example:500 (ipsec)" in covered
    assert "jump.example:22 (ssh)" in covered
