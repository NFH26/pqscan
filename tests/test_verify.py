from pqc_scan.verify import (
    CommandResult,
    _normalized_date,
    _normalized_key,
    compare_host,
    independent_scores,
    normalize_group,
    parse_group,
    parse_verify_failures,
    parse_version,
)


def test_verify_parses_openssl_version_and_group():
    output = "Protocol version: TLSv1.3\nNegotiated TLS1.3 group: X25519MLKEM768\n"

    assert parse_version(output) == "TLSv1.3"
    assert normalize_group(parse_group(output)) == "x25519mlkem768"


def test_s_client_command_keeps_certificate_output(monkeypatch):
    captured = []

    def fake_run(command, timeout, stdin=b""):
        captured.append(command)
        return CommandResult("", 0, False)

    monkeypatch.setattr("pqc_scan.verify.run_command", fake_run)
    from pqc_scan.verify import s_client

    s_client("example.test", 443, "tls", 1.0)

    assert "-showcerts" in captured[0]
    assert "-brief" not in captured[0]


def test_verify_normalizes_equivalent_key_and_date_formats():
    assert _normalized_key("id-ecPublicKey 256") == _normalized_key("ECDSA 256")
    assert _normalized_date("2026-12-04T23:29:33+00:00") == _normalized_date("Dec 4 23:29:33 2026 GMT")


def test_verify_comparison_reports_deliberately_wrong_scan(monkeypatch):
    pem = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"

    def fake_client(host, port, protocol, timeout, extra=()):
        return CommandResult(
            "Protocol version: TLSv1.2\nNegotiated TLS1.3 group: X25519\n"
            + pem
            + "\nVerify return code: 0 (ok)\n",
            0,
            False,
        )

    monkeypatch.setattr("pqc_scan.verify.s_client", fake_client)
    monkeypatch.setattr(
        "pqc_scan.verify.certificate_facts",
        lambda value, timeout: {"sig": "sha256WithRSAEncryption", "key": "rsaEncryption", "bits": "2048", "not_after": "Jan 1 00:00:00 2030 GMT"},
    )
    finding = {
        "target": {"hostname": "example.test", "port": 443},
        "tls_version": "TLSv1.2",
        "negotiated_group": "X25519",
        "certificate_fingerprints": ["leaf"],
        "validation_failures": [],
    }
    certificates = {"leaf": {"sig_algo": "ecdsa-with-SHA256", "pub_key_algo": "EC", "pub_key_size": 256, "not_after": "2030"}}

    result = compare_host({"hostname": "example.test", "port": "443", "protocol": "tls"}, (finding, certificates), 1.0)

    assert result.status == "DIFF"
    assert "leaf_signature" in result.fields


def test_verify_maps_openssl_validation_code():
    assert parse_verify_failures("Verify return code: 10 (certificate has expired)") == {"expired"}


def test_one_sided_connection_is_diff(monkeypatch):
    monkeypatch.setattr("pqc_scan.verify.s_client", lambda *args, **kwargs: CommandResult("", 1, False))
    finding = {"target": {"hostname": "example.test", "port": 443}, "not_testable_reason": None}

    result = compare_host({"hostname": "example.test", "port": "443", "protocol": "tls"}, (finding, {}), 1.0)

    assert result.status == "DIFF"


def test_independent_score_check_uses_profile_weights():
    confidentiality, authentication = independent_scores(
        {
            "group": "X25519MLKEM768",
            "pq_groups": ["X25519MLKEM768"],
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "leaf_signature": "sha256WithRSAEncryption",
            "leaf_hash": "sha256",
            "leaf_key": "rsaEncryption 2048",
            "intermediate_signatures": [],
            "validation_failures": [],
            "leaf_not_after": "Jan 1 2027 00:00:00 GMT",
        },
        {"criticality": "medium", "data_lifetime_years": 0},
    )

    assert confidentiality == 20
    assert authentication == 65
