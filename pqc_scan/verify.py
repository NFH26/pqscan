"""Cross-check scanner observations against local OpenSSL output."""
from __future__ import annotations

import csv
import datetime
import json
import re
import subprocess
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

PQ_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024"]
ALIASES = {
    "prime256v1": "secp256r1",
    "p-256": "secp256r1",
    "prime384v1": "secp384r1",
    "p-384": "secp384r1",
    "curve25519": "x25519",
}
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
VERIFY_FAILURES = {
    "self-signed certificate in certificate chain": "untrusted_root",
    "unable to verify the first certificate": "incomplete_chain_or_unknown_issuer",
    "unable to get local issuer certificate": "incomplete_chain_or_unknown_issuer",
    "certificate has expired": "expired",
    "hostname mismatch": "hostname_mismatch",
    "self-signed certificate": "self_signed",
}


@dataclass(frozen=True)
class CommandResult:
    output: str
    returncode: int | None
    timed_out: bool


@dataclass
class VerifyResult:
    host: str
    status: str
    fields: list[str] = field(default_factory=list)
    values: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None


def normalize_group(group: str | None) -> str:
    value = (group or "unknown").strip().lower()
    return ALIASES.get(value, value)


def run_command(command: list[str], timeout: float, stdin: bytes = b"") -> CommandResult:
    try:
        process = subprocess.run(command, input=stdin, capture_output=True, timeout=timeout)
        output = process.stdout.decode("utf-8", "ignore") + process.stderr.decode("utf-8", "ignore")
        return CommandResult(output, process.returncode, False)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout.decode("utf-8", "ignore") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode("utf-8", "ignore") if isinstance(error.stderr, bytes) else (error.stderr or "")
        return CommandResult(stdout + stderr, None, True)


def openssl_version(timeout: float = 10.0) -> tuple[str, tuple[int, int] | None]:
    result = run_command(["openssl", "version"], timeout)
    match = re.search(r"OpenSSL\s+(\d+)\.(\d+)", result.output)
    parsed = (int(match.group(1)), int(match.group(2))) if match else None
    return result.output.strip(), parsed


def s_client(host: str, port: int, protocol: str | None, timeout: float, extra: tuple[str, ...] = ()) -> CommandResult:
    command = ["openssl", "s_client", "-showcerts", "-connect", f"{host}:{port}", "-servername", host, *extra]
    cafile = __import__("ssl").get_default_verify_paths().cafile
    if cafile:
        command.extend(["-CAfile", cafile])
    if protocol and protocol.startswith("starttls:"):
        command.extend(["-starttls", protocol.split(":", 1)[1]])
    return run_command(command, timeout)


def parse_group(output: str) -> str:
    match = re.search(r"Negotiated\s+(?:TLS1\.3\s+)?group:\s*(\S+)", output, re.I)
    if match:
        return match.group(1)
    match = re.search(r"(?:Server|Peer)\s+Temp\s+Key:\s*(.+)", output, re.I)
    if match:
        parts = [part.strip() for part in match.group(1).split(",")]
        return parts[1] if len(parts) == 3 else parts[0]
    return "unknown"


def parse_version(output: str) -> str | None:
    for pattern in (r"Protocol\s*(?:version)?\s*:\s*(TLSv[\d.]+)", r"New,\s*(TLSv[\d.]+),", r"^\s*(TLSv[\d.]+),\s*Cipher"):
        match = re.search(pattern, output, re.M)
        if match:
            return match.group(1)
    return None


def certificate_facts(pem: str, timeout: float = 10.0) -> dict[str, str]:
    result = run_command(["openssl", "x509", "-noout", "-text"], timeout, pem.encode())
    patterns = {
        "sig": r"Signature Algorithm:\s*(\S+)",
        "key": r"Public Key Algorithm:\s*(\S+)",
        "bits": r"Public-Key:\s*\((\d+) bit\)",
        "not_after": r"Not After\s*:\s*(.+)",
    }
    # Walrus, so each pattern is searched once rather than twice.
    facts = {
        name: (match.group(1).strip() if (match := re.search(pattern, result.output)) else "?")
        for name, pattern in patterns.items()
    }
    hash_match = re.search(r"Signature Algorithm:\s*(?:ecdsa-with-|sha|rsa(?:ssapsswith)?-)?(sha\d+)", result.output, re.I)
    facts["hash"] = hash_match.group(1).lower() if hash_match else "?"
    curve_match = re.search(r"ASN1 OID:\s*(\S+)", result.output, re.I)
    facts["curve"] = curve_match.group(1).lower() if curve_match else "?"
    return facts


def parse_verify_failures(output: str) -> set[str]:
    match = re.search(r"Verify return code:\s*\d+\s*\(([^)]+)\)", output, re.I)
    if not match:
        return set()
    reason = match.group(1).lower()
    for text, mapped in VERIFY_FAILURES.items():
        if text in reason:
            return {mapped}
    return set()


def _normalized(value: Any) -> str:
    return str(value or "?").strip().lower()


def _normalized_key(value: str) -> str:
    normalized = _normalized(value)
    normalized = normalized.replace("id-ecpublickey", "ecdsa").replace("rsaencryption", "rsa")
    return normalized


def _normalized_date(value: str) -> str:
    text = str(value or "?").strip()
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return _normalized(text)
    return parsed.astimezone(datetime.UTC).date().isoformat()


def load_scan(path: str | Path) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    with Path(path).open() as handle:
        data = json.load(handle)
    certificates = data.get("certs", {})
    return {
        f"{finding['target']['hostname']}:{finding['target']['port']}": (finding, certificates)
        for finding in data.get("findings", [])
    }


def compare_host(row: dict[str, str], scan_entry: tuple[dict[str, Any], dict[str, Any]] | None, timeout: float, probe_pq: bool = False) -> VerifyResult:
    host = row["hostname"]
    port = int(row.get("port") or 443)
    protocol = row.get("protocol") or ""
    key = f"{host}:{port}"
    finding, certificates = scan_entry if scan_entry else (None, {})
    verify_extra = ("-tls1_1", "-cipher", "DEFAULT:@SECLEVEL=0") if finding and finding.get("obsolete_tls_only") else ()
    result = s_client(host, port, protocol, timeout, verify_extra)
    pems = PEM_RE.findall(result.output)
    not_testable_reason = finding.get("not_testable_reason") if finding else None
    if not pems and not_testable_reason:
        return VerifyResult(key, "NOT_TESTABLE", reason=not_testable_reason)
    if not pems and finding:
        return VerifyResult(key, "DIFF", ["openssl_connection"], {"scan": "connected", "openssl": "not_testable"}, "openssl_no_certificate")
    if not pems and result.timed_out:
        return VerifyResult(key, "DIFF", ["scanner_connection"], {"scan": "not_testable", "openssl": "timed_out"}, "scanner_not_testable")
    if not pems:
        return VerifyResult(key, "NOT_TESTABLE", reason="openssl_no_certificate")
    facts = [certificate_facts(pem, timeout) for pem in pems]
    verify_output = s_client(host, port, protocol, timeout, (*verify_extra, "-verify_hostname", host)).output
    scan_certs = finding.get("certificate_fingerprints", []) if finding else []
    scan_leaf = certificates.get(scan_certs[0], {}) if scan_certs else {}
    expected = {
        "tls_version": (finding or {}).get("tls_version"),
        "group": normalize_group((finding or {}).get("negotiated_group")),
        "certificate_count": len(scan_certs),
        "leaf_signature": scan_leaf.get("sig_algo", "?"),
        "leaf_hash": scan_leaf.get("sig_hash", "?"),
        "leaf_key": f"{scan_leaf.get('pub_key_algo', '?')} {scan_leaf.get('pub_key_size', '?')}",
        "leaf_curve": normalize_group(scan_leaf.get("pub_key_curve")) if scan_leaf.get("pub_key_curve") else "?",
        "leaf_not_after": str(scan_leaf.get("not_after", "?")),
        "intermediate_signatures": [certificates.get(fingerprint, {}).get("sig_algo", "?") for fingerprint in scan_certs[1:]],
        "intermediate_hashes": [certificates.get(fingerprint, {}).get("sig_hash", "?") for fingerprint in scan_certs[1:]],
        "validation_failures": sorted(
            failure.split("(")[-1].rstrip(")") for failure in (finding or {}).get("validation_failures", [])
        ),
    }
    actual = {
        "tls_version": parse_version(result.output),
        "group": normalize_group(parse_group(result.output)),
        "certificate_count": len(pems),
        "leaf_signature": facts[0]["sig"],
        "leaf_hash": facts[0].get("hash", "?"),
        "leaf_key": f"{facts[0]['key']} {facts[0]['bits']}",
        # Normalised, so a curve OpenSSL calls "prime256v1" compares equal to the "secp256r1"
        # the scanner reports. The un-normalised duplicate below this line silently won and
        # made every ECDSA host look like a mismatch in `pqc verify`.
        "leaf_curve": (
            normalize_group(facts[0].get("curve", "?"))
            if facts[0].get("curve", "?") != "?" else "?"
        ),
        "cipher_suite": (cipher_match.group(1) if (cipher_match := re.search(r"(?:Cipher is|Cipher:)\s*(\S+)", result.output, re.I)) else "?"),
        "leaf_not_after": facts[0]["not_after"],
        "intermediate_signatures": [fact["sig"] for fact in facts[1:]],
        "intermediate_hashes": [fact.get("hash", "?") for fact in facts[1:]],
        "validation_failures": sorted(parse_verify_failures(verify_output)),
    }
    def _differs(name: str) -> bool:
        want: Any = expected[name]
        got: Any = actual[name]
        if isinstance(want, list):
            return [_normalized(item) for item in want] != [_normalized(item) for item in got]
        if name == "leaf_key":
            return _normalized_key(str(want)) != _normalized_key(str(got))
        if name == "leaf_not_after":
            return _normalized_date(str(want)) != _normalized_date(str(got))
        return _normalized(want) != _normalized(got)

    differences = [
        name for name in expected
        if expected[name] not in (None, "?") and _differs(name)
    ]
    if probe_pq and actual["tls_version"] == "TLSv1.3":
        actual["pq_groups"] = [group for group in PQ_GROUPS if normalize_group(parse_group(s_client(host, port, protocol, timeout, ("-groups", group, "-tls1_3")).output)) == group.lower()]
    return VerifyResult(key, "DIFF" if differences else "MATCH", differences, {"scan": expected, "openssl": actual})


def verify_hosts(input_path: str, scan_path: str, host: str | None = None, timeout: float = 15.0, probe_pq: bool = False) -> list[VerifyResult]:
    scan = load_scan(scan_path)
    with Path(input_path).open() as handle:
        rows = list(csv.DictReader(line for line in handle if not line.lstrip().startswith("#")))
    return [compare_host(row, scan.get(f"{row['hostname']}:{int(row.get('port') or 443)}"), timeout, probe_pq) for row in rows if not host or row["hostname"] == host]


def independent_scores(actual: dict[str, Any], target: dict[str, Any], profile_name: str = "asd_ism") -> tuple[int | None, int | None]:
    """Recompute scores from OpenSSL facts without calling the scanner scorer."""
    import yaml

    from pqc_scan.parsers import RuleEngine

    rules_path = Path(__file__).resolve().parent / "rules" / "scoring.yaml"
    with rules_path.open() as handle:
        weights = yaml.safe_load(handle)
    engine = RuleEngine(profile_name)
    criticality = target.get("criticality", "medium")
    c_mult = weights["confidentiality"]["criticality_multiplier"][criticality]
    a_mult = weights["authentication"]["criticality_multiplier"][criticality]

    group = actual.get("group", "unknown")
    pq_offered = bool(actual.get("pq_groups"))
    tls_rules = engine.rules.get("tls", {})
    protocol_weights = weights["confidentiality"].get("protocol", {})
    if group == "unknown":
        confidentiality = None
    else:
        group_class = engine.classify_key_exchange(group).value
        base = weights["confidentiality"]["key_exchange"][group_class]
        if not pq_offered:
            base += weights["confidentiality"]["no_pq_group_offered"]
        tls_version = actual.get("tls_version")
        if tls_version not in tls_rules.get("approved_versions", []):
            base += protocol_weights.get("tls_version_not_approved", 0)
        cipher_name = str(actual.get("cipher_suite", "")).lower()
        symmetric = tls_rules.get("symmetric", {})
        if cipher_name and "gcm" not in cipher_name:
            base += protocol_weights.get("cipher_not_aes_gcm", 0)
        if any(token and token in cipher_name for token in symmetric.get("NOT_APPROVED_AFTER_2030", [])):
            base += protocol_weights.get("symmetric_not_approved_after_2030", 0)
        if any(token and token in cipher_name for token in symmetric.get("NOT_APPROVED", [])):
            base += protocol_weights.get("symmetric_not_approved", 0)
        if tls_version != "TLSv1.3" and cipher_name and not any(token in cipher_name for token in ("ecdhe", "dhe")):
            base += protocol_weights.get("no_forward_secrecy", 0)
        lifetime = int(target.get("data_lifetime_years") or 0)
        if lifetime > 10:
            base += weights["confidentiality"]["data_lifetime_years"]["over_10"]
        elif lifetime >= 5:
            base += weights["confidentiality"]["data_lifetime_years"]["5_to_10"]
        confidentiality = min(weights["confidentiality"]["cap"], int(base * c_mult))

    signatures = [actual.get("leaf_signature", "?"), *list(actual.get("intermediate_signatures", []))]
    signature_classes = [engine.classify_signature(signature) for signature in signatures]
    severity = {
        "APPROVED": 0,
        "TRANSITIONAL": 1,
        "REVIEW": 2,
        "NOT_APPROVED_AFTER_2030": 3,
        "NOT_APPROVED": 4,
    }
    weakest = max(signature_classes, key=lambda classification: severity[classification.value]) if signature_classes else None
    authentication = weights["authentication"]["signature_algorithm"][weakest.value] if weakest else 0
    hashes = [str(actual.get("leaf_hash", "")).lower(), *(str(value).lower() for value in actual.get("intermediate_hashes", []))]
    if any(hash_name in {"sha1", "md5"} for hash_name in hashes):
        authentication += weights["authentication"]["hashes"]["NOT_APPROVED"]
    elif any(hash_name in {"sha224", "sha256"} for hash_name in hashes):
        authentication += weights["authentication"]["hashes"]["NOT_APPROVED_AFTER_2030"]
    validation_failures = actual.get("validation_failures", [])
    authentication += min(
        weights["authentication"]["validation_failure_cap"],
        len(validation_failures) * weights["authentication"]["validation_failure_penalty"],
    )
    key_rules = engine.rules.get("key_sizes", {})
    key_name = str(actual.get("leaf_key", "")).lower()
    bits_match = re.search(r"(\d+)\s*$", key_name)
    bits = int(bits_match.group(1)) if bits_match else None
    key_algo = "RSA" if "rsa" in key_name else "ECDSA" if "ec" in key_name else None
    if key_algo and bits is not None and key_algo in key_rules:
        rules = key_rules[key_algo]
        if bits < rules.get("minimum_bits", 0):
            authentication += weights["authentication"]["key_size"].get("below_minimum", 0)
        elif bits < rules.get("preferred_bits", bits):
            authentication += min(weights["authentication"]["key_size"].get("below_preferred", 0), weights["authentication"].get("informational_note_cap", 0))
        # The scorer also notes a curve that is not the ISM-preferred one (ISM-0474/0475).
        preferred_curve = rules.get("preferred_curve")
        leaf_curve = actual.get("leaf_curve")
        if preferred_curve and leaf_curve not in (None, "?") and leaf_curve != preferred_curve:
            authentication += min(
                weights["authentication"]["key_size"].get("below_preferred", 0),
                weights["authentication"].get("informational_note_cap", 0),
            )
    classification_rules = engine.rules.get("classification_curve_rules", {}).get(target.get("classification", "OS"))
    if classification_rules and actual.get("leaf_curve") not in (None, "?") and actual["leaf_curve"] not in classification_rules.get("allowed_curves", []):
        authentication += weights["authentication"].get("classification_curve_violation", 0)
    not_after = actual.get("leaf_not_after")
    if not_after and not_after != "?":
        try:
            expiry = parsedate_to_datetime(not_after)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=datetime.UTC)
            milestones = engine.rules["profile"]["milestones"]
            complete = datetime.datetime.strptime(milestones["transition_complete_by"], "%Y-%m-%d").replace(tzinfo=datetime.UTC)
            started = datetime.datetime.strptime(milestones["migration_started_by"], "%Y-%m-%d").replace(tzinfo=datetime.UTC)
            if expiry > complete:
                authentication += weights["authentication"]["not_after_2030"]
            elif expiry > started:
                authentication += weights["authentication"]["not_after_2028"]
        except (TypeError, ValueError):
            pass
    return confidentiality, min(weights["authentication"]["cap"], int(authentication * a_mult))
