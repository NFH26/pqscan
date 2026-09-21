import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqc_scan.models import Classification
from pqc_scan.parsers import RuleEngine, parse_certificate_pem


@pytest.fixture
def dummy_engine():
    return RuleEngine("asd_ism")

def test_signature_patterns(dummy_engine):
    # ISM approved asymmetric algorithms and ML-DSA parameter guidance, September 2026 PDF pp. 4, 10.
    assert dummy_engine.classify_signature("ml-dsa-87") == Classification.APPROVED
    assert dummy_engine.classify_signature("ml-dsa-65") == Classification.TRANSITIONAL
    assert dummy_engine.classify_signature("mldsa44") == Classification.NOT_APPROVED
    assert dummy_engine.classify_signature("SLH-DSA-SHA2-128s") == Classification.NOT_APPROVED
    assert dummy_engine.classify_signature("ecdsa-with-SHA384") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_signature("sha256WithRSAEncryption") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_signature("rsassaPss") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_signature("ed25519") == Classification.NOT_APPROVED
    assert dummy_engine.classify_signature("dsa_with_SHA256") == Classification.NOT_APPROVED
    assert dummy_engine.classify_signature("MLKEM1024") == Classification.APPROVED
    assert dummy_engine.classify_signature("MLKEM512") == Classification.NOT_APPROVED

def test_group_aliases(dummy_engine):
    assert dummy_engine.classify_key_exchange("x25519") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_key_exchange("curve25519") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_key_exchange("secp256r1") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_key_exchange("p-521") == Classification.NOT_APPROVED_AFTER_2030


def test_rules_load_from_any_working_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    engine = RuleEngine("asd_ism")

    assert engine.profile_name == "asd_ism"
    assert engine.rules["group_aliases"]["p-521"] == "p-521"


def test_parse_certificate_pem_returns_certificate_data(dummy_engine):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    parsed = parse_certificate_pem(pem, dummy_engine)

    assert parsed.fingerprint_sha256 == certificate.fingerprint(hashes.SHA256()).hex()
    assert parsed.subject_cn == "example.test"
    assert parsed.sans == ["example.test"]
    assert parsed.pub_key_algo == "RSA"
    assert parsed.pub_key_size == 2048
    assert parsed.sig_hash == "sha256"
    assert parsed.is_self_signed is True
    assert parsed.is_ca is True
    assert parsed.pub_key_classification == Classification.NOT_APPROVED_AFTER_2030

def test_ssh_algorithms_are_classified_from_the_profile(dummy_engine):
    from pqc_scan.models import Classification

    # key exchange: ML-KEM hybrid is transitional, classical retires in 2030, SHA-1 is out
    assert dummy_engine.classify_ssh("key_exchange", "mlkem768x25519-sha256") == Classification.TRANSITIONAL
    assert dummy_engine.classify_ssh("key_exchange", "curve25519-sha256") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_ssh("key_exchange", "diffie-hellman-group14-sha1") == Classification.NOT_APPROVED
    # sntrup761 is NTRU Prime, not ML-KEM, so it is not an ASD-approved post-quantum algorithm
    assert dummy_engine.classify_ssh("key_exchange", "sntrup761x25519-sha512") == Classification.NOT_APPROVED_AFTER_2030

    # host keys: ssh-rsa is SHA-1 signed, ssh-dss is DSA, neither is approved
    assert dummy_engine.classify_ssh("host_keys", "ssh-rsa") == Classification.NOT_APPROVED
    assert dummy_engine.classify_ssh("host_keys", "ssh-dss") == Classification.NOT_APPROVED
    assert dummy_engine.classify_ssh("host_keys", "rsa-sha2-512") == Classification.NOT_APPROVED_AFTER_2030
    # certificate host key types inherit their base algorithm
    assert dummy_engine.classify_ssh("host_keys", "ssh-rsa-cert-v01@openssh.com") == Classification.NOT_APPROVED

    # AES is the only approved symmetric algorithm, so ChaCha20 is not approved
    assert dummy_engine.classify_ssh("ciphers", "aes256-gcm@openssh.com") == Classification.APPROVED
    assert dummy_engine.classify_ssh("ciphers", "chacha20-poly1305@openssh.com") == Classification.NOT_APPROVED
    assert dummy_engine.classify_ssh("ciphers", "aes128-gcm@openssh.com") == Classification.NOT_APPROVED_AFTER_2030

    # SHA-256 is not approved beyond 2030; SHA-512 is
    assert dummy_engine.classify_ssh("macs", "hmac-sha2-512-etm@openssh.com") == Classification.APPROVED
    assert dummy_engine.classify_ssh("macs", "hmac-sha2-256-etm@openssh.com") == Classification.NOT_APPROVED_AFTER_2030
    assert dummy_engine.classify_ssh("macs", "hmac-sha1") == Classification.NOT_APPROVED

    # signalling entries are not algorithms and must not appear as findings
    assert dummy_engine.ssh_ignored("ext-info-s")
    assert dummy_engine.ssh_ignored("kex-strict-s-v00@openssh.com")
    assert not dummy_engine.ssh_ignored("curve25519-sha256")
