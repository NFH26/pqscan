"""Offline checks that need no network: rule integrity, scoring invariants, output artifacts.

These answer questions a live scan cannot. A live scan tells you the tool reached a server and
agreed with a known answer; these tell you the rule profile is internally coherent, that the
scoring cannot be gamed, and that every output format is still well formed. They run in about
a second and need nothing but the repository.
"""
from __future__ import annotations

import csv
import itertools
import json
import re
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pqc_scan.cbom import build_cbom
from pqc_scan.models import CertificateData, Classification, HostFinding, Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.reporters import Reporter
from pqc_scan.scoring import Scorer

RULES = Path(__file__).resolve().parent / "rules"
CLASSIFICATIONS = {c.value for c in Classification}


@dataclass
class CheckResult:
    suite: str
    name: str
    ok: bool
    detail: str = ""


def _result(suite: str, name: str, problems: Iterable[str]) -> CheckResult:
    problems = [p for p in problems if p]
    return CheckResult(suite, name, not problems, "; ".join(problems[:6]))


# --------------------------------------------------------------------------------------
# Rule profile integrity
# --------------------------------------------------------------------------------------

def _cited_controls() -> set[str]:
    """Every ISM control number PQScan mentions anywhere in its rules or code."""
    found: set[str] = set()
    root = Path(__file__).resolve().parent
    for path in list(root.rglob("*.yaml")) + list(root.rglob("*.py")):
        if path.name == "ism_controls.txt":
            continue
        found.update(re.findall(r"ISM-\d{4}", path.read_text(encoding="utf-8", errors="replace")))
    return found


def _known_controls() -> tuple[set[str], str]:
    path = RULES / "ism_controls.txt"
    if not path.exists():
        return set(), "missing"
    version = "unknown"
    known: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# catalog version:"):
            version = line.split(":", 1)[1].strip()
        elif line and not line.startswith("#"):
            known.add(line.split("\t", 1)[0].strip())
    return known, version


def check_control_numbers() -> CheckResult:
    """Every control PQScan cites must exist in ASD's published catalog.

    The ISM is reissued quarterly and control numbers are retired, so a citation that was
    right last quarter can silently stop being right. Reporting a client against a control
    that no longer exists is the kind of error that costs credibility rather than a rerun.
    """
    known, version = _known_controls()
    if not known:
        return CheckResult("rules", "ISM control numbers exist", False,
                           "ism_controls.txt is missing; run tools/refresh_ism_controls.py")
    cited = _cited_controls()
    unknown = sorted(cited - known)
    detail = f"{len(unknown)} not in catalog {version}: {', '.join(unknown[:8])}" if unknown else ""
    result = _result("rules", "ISM control numbers exist", [detail])
    if result.ok:
        result.detail = f"{len(cited)} citations, all valid in ISM {version}"
    return result


def check_no_null_tokens() -> CheckResult:
    """No algorithm list may contain a YAML null.

    A bare `null` in a list parses as None, not the string "null". That silently disabled the
    NULL-cipher check and let an unencrypted endpoint score better than a 3DES one.
    """
    problems: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                if value is None:
                    problems.append(f"{path}[{index}] is a YAML null")
                else:
                    walk(value, f"{path}[{index}]")

    for name in ("asd_ism.yaml", "scoring.yaml"):
        walk(yaml.safe_load((RULES / name).read_text()), name)
    return _result("rules", "no YAML nulls in algorithm lists", problems)


def check_classification_tables() -> CheckResult:
    """Every classification bucket must be a name the scorer understands, with no duplicates."""
    profile = yaml.safe_load((RULES / "asd_ism.yaml").read_text())
    problems: list[str] = []
    for section in ("ssh", "ipsec", "tls"):
        for category, table in (profile.get(section) or {}).items():
            if not isinstance(table, dict) or not table:
                continue
            if not set(table).issubset(CLASSIFICATIONS | {"NO_ENCRYPTION"}):
                unexpected = set(table) - CLASSIFICATIONS - {"NO_ENCRYPTION"}
                if all(isinstance(v, (list, type(None))) for v in table.values()):
                    problems.append(f"{section}.{category}: unknown buckets {sorted(unexpected)}")
                continue
            seen: dict[str, str] = {}
            for bucket, entries in table.items():
                # NO_ENCRYPTION is deliberately an overlay on NOT_APPROVED, not a rival
                # bucket: a NULL cipher is both unapproved and absent encryption, and the
                # scorer adds a separate penalty for the second fact.
                if bucket == "NO_ENCRYPTION":
                    continue
                for entry in entries or []:
                    key = str(entry).lower()
                    if key in seen:
                        problems.append(
                            f"{section}.{category}: {entry!r} in both {seen[key]} and {bucket}"
                        )
                    seen[key] = bucket
    return _result("rules", "classification tables are well formed", problems)


def check_port_map_matches_probes() -> CheckResult:
    """Every protocol the port map names must actually be implemented.

    These are two lists that have to agree and nothing used to check that they did: the map
    advertised starttls:mysql, no prelude implemented it, and every MySQL target came back
    unsupported_protocol without anyone noticing.
    """
    from pqc_scan.collectors import SUPPORTED_STARTTLS
    from pqc_scan.probes import PROBES

    mapping = yaml.safe_load((RULES / "port_map.yaml").read_text()).get("ports", {})
    problems: list[str] = []
    for port, protocol in mapping.items():
        name = str(protocol)
        if name.startswith("starttls:"):
            if name not in SUPPORTED_STARTTLS:
                problems.append(f"port {port}: {name} has no prelude")
        elif name.split(":", 1)[0] not in PROBES:
            problems.append(f"port {port}: {name} has no probe")
    return _result("rules", "port map matches the implemented probes", problems)


def check_docs_and_metadata_agree() -> CheckResult:
    """The packaged version, the changelog and the docs must not drift apart.

    Every report carries the tool version, so a version that disagrees with what was
    released is a support problem forever.
    """
    from pqc_scan.cli import TOOL_VERSION

    root = Path(__file__).resolve().parent.parent
    problems: list[str] = []
    if "unknown" in TOOL_VERSION:
        problems.append("the package is not installed, so the version cannot be read")

    # The repository files are not shipped in the wheel, so this half of the check only
    # applies in a source checkout. An installed copy is not missing its README; it simply
    # does not carry one, and reporting that as a failure would cry wolf on every user.
    if not (root / "pyproject.toml").exists():
        result = _result("rules", "version, changelog and docs agree", problems)
        if result.ok:
            result.detail = f"version {TOOL_VERSION} (installed; repository files not checked)"
        return result

    changelog = root / "CHANGELOG.md"
    if changelog.exists() and TOOL_VERSION not in changelog.read_text(encoding="utf-8"):
        problems.append(f"CHANGELOG.md has no entry for {TOOL_VERSION}")
    for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE"):
        if not (root / name).exists():
            problems.append(f"{name} is missing")
    docs = root / "docs"
    if docs.exists():
        for link in ("getting-started", "scanning", "scoring", "ism-coverage", "outputs", "ci",
                     "architecture"):
            if not (docs / f"{link}.md").exists():
                problems.append(f"docs/{link}.md is linked from the README but missing")
    result = _result("rules", "version, changelog and docs agree", problems)
    if result.ok:
        result.detail = f"version {TOOL_VERSION}, changelog and docs present"
    return result


def check_weights_complete() -> CheckResult:
    """Every classification must have a weight, or scoring raises KeyError mid-scan."""
    weights = yaml.safe_load((RULES / "scoring.yaml").read_text())
    problems: list[str] = []
    for axis, key in (("confidentiality", "key_exchange"), ("authentication", "signature_algorithm")):
        table = (weights.get(axis) or {}).get(key) or {}
        missing = CLASSIFICATIONS - set(table)
        if missing:
            problems.append(f"{axis}.{key} missing {sorted(missing)}")
    for axis in ("confidentiality", "authentication"):
        multipliers = (weights.get(axis) or {}).get("criticality_multiplier") or {}
        missing = {"low", "medium", "high"} - set(multipliers)
        if missing:
            problems.append(f"{axis}.criticality_multiplier missing {sorted(missing)}")
    return _result("rules", "scoring weights are complete", problems)


def check_remediation_coverage() -> CheckResult:
    """Every classification that can be reported must have remediation advice to offer."""
    from pqc_scan.remediation import actions_for

    problems: list[str] = []
    for value in ("NOT_APPROVED", "NOT_APPROVED_AFTER_2030", "TRANSITIONAL"):
        finding = HostFinding(target=Target(hostname="x.example"))
        finding.rule_findings = [f"key_exchange {value}"]
        finding.pq_readiness = "classical_only"
        finding.pq_status = "not_supported"
        try:
            actions_for(finding, RuleEngine())
        except Exception as error:
            problems.append(f"{value}: {type(error).__name__}: {error}")
    return _result("rules", "remediation advice resolves", problems)


# --------------------------------------------------------------------------------------
# Scoring invariants
# --------------------------------------------------------------------------------------

def _scored(**kwargs: Any) -> HostFinding:
    engine = RuleEngine()
    scorer = Scorer()
    target = Target(
        hostname="x.example", port=443,
        criticality=kwargs.pop("criticality", "medium"),
        data_lifetime_years=kwargs.pop("data_lifetime_years", 0),
    )
    finding = HostFinding(target=target, service="tls", **kwargs)
    scorer.calculate_scores(finding, {}, engine)
    scorer.assign_readiness_band(finding)
    return finding


def check_weaker_crypto_never_scores_better() -> CheckResult:
    """The central invariant. If it can be violated, every number in the report is suspect."""
    ladder = [
        ("MLKEM1024", "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
        ("X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
        ("x25519", "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
        ("secp256r1", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    ]
    problems: list[str] = []
    scores = []
    for group, version, cipher in ladder:
        finding = _scored(
            negotiated_group=group, tls_version=version, cipher_suite=cipher,
            pq_status="supported" if "MLKEM" in group else "not_supported",
        )
        scores.append((group, finding.confidentiality_score))
    for (stronger, high), (weaker, low) in itertools.pairwise(scores):
        if high is None or low is None:
            problems.append(f"{stronger} or {weaker} produced no score")
        elif high > low:
            problems.append(f"{stronger} scored {high}, worse than {weaker} at {low}")
    return _result("scoring", "stronger crypto always scores better", problems)


def check_no_encryption_is_the_worst_case() -> CheckResult:
    """A NULL cipher must never outrank a weak-but-real one."""
    problems: list[str] = []
    null_cipher = _scored(
        negotiated_group="secp256r1", tls_version="TLSv1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_NULL_SHA", obsolete_tls_only=True,
        max_supported_tls="TLSv1.2",
    )
    triple_des = _scored(
        negotiated_group="secp256r1", tls_version="TLSv1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", obsolete_tls_only=True,
        max_supported_tls="TLSv1.2",
    )
    if (null_cipher.confidentiality_score or 0) < (triple_des.confidentiality_score or 0):
        problems.append(
            f"NULL scored {null_cipher.confidentiality_score}, better than 3DES at "
            f"{triple_des.confidentiality_score}"
        )
    return _result("scoring", "no encryption is the worst case", problems)


def check_scores_stay_in_range() -> CheckResult:
    """No combination may exceed the cap or go negative."""
    problems: list[str] = []
    for criticality in ("low", "medium", "high"):
        for lifetime in (0, 6, 20):
            finding = _scored(
                negotiated_group="diffie-hellman-group1-sha1", tls_version="SSLv3",
                cipher_suite="TLS_RSA_WITH_NULL_MD5", criticality=criticality,
                data_lifetime_years=lifetime, obsolete_tls_only=True, max_supported_tls="SSLv3",
                validation_failures=["expired", "self_signed", "hostname_mismatch"],
            )
            for axis, score in (("conf", finding.confidentiality_score), ("auth", finding.authentication_score)):
                if score is not None and not 0 <= score <= 100:
                    problems.append(f"{axis}={score} at criticality={criticality} lifetime={lifetime}")
    return _result("scoring", "scores stay within 0-100", problems)


def check_unmeasured_is_never_compliant() -> CheckResult:
    """An endpoint we could not measure must never present as a pass."""
    finding = _scored(negotiated_group="unknown", pq_status="not_determinable")
    problems: list[str] = []
    if finding.confidentiality_score is not None:
        problems.append(f"unmeasured endpoint scored {finding.confidentiality_score}")
    if finding.pq_readiness != "unknown":
        problems.append(f"readiness {finding.pq_readiness!r}, expected 'unknown'")
    if finding.readiness_band is not None:
        problems.append(f"band {finding.readiness_band}, expected none")
    return _result("scoring", "unmeasured is never reported as compliant", problems)


def check_pqcmm_ordering() -> CheckResult:
    """Readiness must never lower a band, and a broken endpoint must sit at 0."""
    problems: list[str] = []
    hybrid = _scored(negotiated_group="X25519MLKEM768", tls_version="TLSv1.3",
                     cipher_suite="TLS_AES_128_GCM_SHA256", pq_status="supported")
    classical = _scored(negotiated_group="x25519", tls_version="TLSv1.3",
                        cipher_suite="TLS_AES_128_GCM_SHA256", pq_status="not_supported")
    if (hybrid.readiness_band or 0) < (classical.readiness_band or 0):
        problems.append(
            f"hybrid banded {hybrid.readiness_band}, below classical at {classical.readiness_band}"
        )
    broken = _scored(negotiated_group="x25519", tls_version="TLSv1.3",
                     cipher_suite="TLS_AES_256_GCM_SHA384",
                     validation_failures=["no_tls_offered"])
    if broken.readiness_band != 0:
        problems.append(f"plaintext service banded {broken.readiness_band}, expected 0")
    return _result("scoring", "readiness bands are correctly ordered", problems)


# --------------------------------------------------------------------------------------
# Output artifacts
# --------------------------------------------------------------------------------------

def _sample() -> tuple[list[HostFinding], dict[str, CertificateData]]:
    engine, scorer = RuleEngine(), Scorer()
    certificate = CertificateData(
        fingerprint_sha256="a" * 64, subject_cn="example.gov.au", issuer="CN=Test CA",
        pub_key_algo="rsaEncryption", pub_key_size=2048, sig_algo="sha256WithRSAEncryption",
        usages=["example.gov.au:443 (tls)"],
    )
    findings = [
        HostFinding(target=Target(hostname="tls.example", port=443), service="tls",
                    version="TLSv1.3", tls_version="TLSv1.3", negotiated_group="X25519MLKEM768",
                    cipher_suite="TLS_AES_256_GCM_SHA384", pq_status="supported",
                    certificate_fingerprints=["a" * 64]),
        HostFinding(target=Target(hostname="ssh.example", port=22), service="ssh",
                    version="SSH-2.0", negotiated_group="mlkem768x25519-sha256",
                    algorithms={"key_exchange": [{"name": "mlkem768x25519-sha256",
                                                  "classification": "TRANSITIONAL", "in_use": False}],
                                "signature": [{"name": "rsa-sha2-512",
                                               "classification": "NOT_APPROVED_AFTER_2030", "in_use": False}]}),
        HostFinding(target=Target(hostname="vpn.example", port=500), service="ipsec",
                    version="IKEv2", negotiated_group="ECP_384", cipher_suite="ENCR_AES_GCM_16",
                    algorithms={"key_exchange": [{"name": "ECP_384", "classification": "TRANSITIONAL", "in_use": True}],
                                "cipher": [{"name": "ENCR_AES_GCM_16", "classification": "APPROVED", "in_use": True}],
                                "mac": [{"name": "NONE", "classification": "APPROVED", "in_use": True}]}),
        HostFinding(target=Target(hostname="mail.example", port=0), service="domain",
                    version="domain", negotiated_group="n/a",
                    validation_failures=["spf_absent (ISM-0574)"]),
        HostFinding(target=Target(hostname="dead.example", port=443), service="tls",
                    not_testable_reason="timeout"),
    ]
    for finding in findings:
        scorer.calculate_scores(finding, {"a" * 64: certificate}, engine)
        scorer.assign_readiness_band(finding)
    return findings, {"a" * 64: certificate}


def check_outputs() -> list[CheckResult]:
    """Every output format must be produced and well formed, for every service type."""
    findings, certificates = _sample()
    engine = RuleEngine()
    results: list[CheckResult] = []
    reporter = Reporter(
        findings, certificates, engine.profile_name, engine=engine,
        metadata={"operator": "selftest", "engagement": "selftest", "authorised": True,
                  "probe_method": "native", "rules_version": engine.rules.get("profile", {}).get("rules_version")},
    )
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)

        problems: list[str] = []
        try:
            html_path = base / "report.html"
            reporter.write_html(str(html_path))
            html = html_path.read_text(encoding="utf-8")
            if "<html" not in html.lower():
                problems.append("HTML has no root element")
            for finding in findings:
                if finding.target.hostname not in html:
                    problems.append(f"{finding.target.hostname} missing from HTML")
            # An artifact that reaches out to the network leaks who read the report.
            for pattern in ('src="http', "<link", "@import"):
                if pattern in html:
                    problems.append(f"HTML is not self-contained ({pattern})")
        except Exception as error:
            problems.append(f"{type(error).__name__}: {error}")
        results.append(_result("outputs", "HTML report", problems))

        problems = []
        try:
            csv_path = base / "findings.csv"
            reporter.write_csv(str(csv_path))
            with csv_path.open() as handle:
                rows = list(csv.reader(handle))
            if len(rows) != len(findings) + 1:
                problems.append(f"{len(rows) - 1} data rows for {len(findings)} findings")
            if len({len(r) for r in rows}) != 1:
                problems.append("rows have inconsistent column counts")
        except Exception as error:
            problems.append(f"{type(error).__name__}: {error}")
        results.append(_result("outputs", "CSV export", problems))

        problems = []
        try:
            payload = json.loads(json.dumps(
                {"findings": [json.loads(f.model_dump_json()) for f in findings]}
            ))
            if len(payload["findings"]) != len(findings):
                problems.append("finding count changed through serialisation")
            required = {"target", "service", "pq_readiness", "confidentiality_score", "readiness_band"}
            missing = required - set(payload["findings"][0])
            if missing:
                problems.append(f"JSON missing {sorted(missing)}")
        except Exception as error:
            problems.append(f"{type(error).__name__}: {error}")
        results.append(_result("outputs", "JSON export", problems))

        problems = []
        try:
            document = build_cbom(findings, certificates, rules_version="test")
            if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
                problems.append("not a CycloneDX 1.6 document")
            refs = [c["bom-ref"] for c in document["components"]]
            if len(refs) != len(set(refs)):
                problems.append("duplicate bom-ref values")
            kinds = {c["cryptoProperties"]["assetType"] for c in document["components"]}
            for expected in ("algorithm", "protocol", "certificate"):
                if expected not in kinds:
                    problems.append(f"no {expected} components")
            json.dumps(document)  # must be serialisable
        except Exception as error:
            problems.append(f"{type(error).__name__}: {error}")
        results.append(_result("outputs", "CycloneDX CBOM", problems))

    return results


def check_every_service_scores() -> CheckResult:
    """Each probe's output must survive scoring, so one protocol cannot break a whole scan."""
    findings, _ = _sample()
    problems: list[str] = []
    for finding in findings:
        if finding.not_testable_reason:
            continue
        if finding.confidentiality_score is None and finding.authentication_score is None:
            problems.append(f"{finding.service}: no score produced")
    return _result("scoring", "every service type scores", problems)


SUITES: dict[str, list[Callable[[], Any]]] = {
    "rules": [
        check_control_numbers, check_no_null_tokens, check_classification_tables,
        check_weights_complete, check_remediation_coverage, check_port_map_matches_probes,
        check_docs_and_metadata_agree,
    ],
    "scoring": [
        check_weaker_crypto_never_scores_better, check_no_encryption_is_the_worst_case,
        check_scores_stay_in_range, check_unmeasured_is_never_compliant,
        check_pqcmm_ordering, check_every_service_scores,
    ],
    "outputs": [check_outputs],
}


def run_offline_checks() -> list[CheckResult]:
    results: list[CheckResult] = []
    for checks in SUITES.values():
        for check in checks:
            try:
                produced = check()
            except Exception as error:
                results.append(CheckResult("?", check.__name__, False,
                                           f"{type(error).__name__}: {error}"))
                continue
            results.extend(produced if isinstance(produced, list) else [produced])
    return results
