"""CycloneDX Cryptographic Bill of Materials export.

ASD names the CBOM in two ISM controls:

    ISM-2083  "A cryptographic bill of materials is produced and made available to consumers
              of software."
    ISM-2082  "If a cryptographic bill of materials is available for imported third-party
              software components, it is used during software development..."

Both sit in the Guidelines for software development, so they bind an organisation as a
software PRODUCER. This exporter does something adjacent and, for a scanner, more useful: it
builds a CBOM from what endpoints were observed to actually negotiate, rather than from what
a source tree declares. Those are different claims and the document says which one it is -
every component here carries evidence of observation, not a code reference.

Format: CycloneDX 1.6 with the `cryptographic-asset` component type and the `cryptoProperties`
block. Three kinds of component are emitted: algorithms (with an `assetType` of `algorithm`),
protocols, and certificates. Certificates are deduplicated by SHA-256 fingerprint and list
every endpoint that served them, because one certificate commonly serves many.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from pqc_scan.models import CertificateData, Classification, HostFinding

SPEC_VERSION = "1.6"

# NIST security category per FIPS 203/204, for the parameter sets the ISM names.
NIST_CATEGORIES = {
    "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5,
    "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5,
}

# CycloneDX primitive for each role a scanner observes.
ROLE_PRIMITIVES = {
    "key_exchange": "kem",
    "signature": "signature",
    "cipher": "ae",
    "mac": "mac",
    "prf": "kdf",
}


def _bom_ref(*parts: str) -> str:
    return "crypto/" + "/".join(p.replace(" ", "-") for p in parts if p)


def _algorithm_component(name: str, role: str, classification: str, in_use: bool) -> dict[str, Any]:
    upper = name.upper()
    category = next((v for k, v in NIST_CATEGORIES.items() if k.replace("-", "") in upper.replace("-", "").replace("_", "")), None)
    properties = [
        {"name": "pqscan:ism-classification", "value": classification},
        # "observed" distinguishes what an endpoint actually negotiated from what it merely
        # advertised. A CBOM built from a source tree cannot make that distinction at all.
        {"name": "pqscan:observed", "value": "negotiated" if in_use else "offered"},
    ]
    crypto: dict[str, Any] = {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": ROLE_PRIMITIVES.get(role, "other"),
            "executionEnvironment": "unknown",
            "implementationPlatform": "unknown",
            "cryptoFunctions": ["keygen"] if role == "key_exchange" else ["sign"] if role == "signature" else ["encrypt"],
        },
    }
    if category:
        crypto["algorithmProperties"]["nistQuantumSecurityLevel"] = category
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("algorithm", role, name),
        "name": name,
        "cryptoProperties": crypto,
        "properties": properties,
    }


def _protocol_component(finding: HostFinding) -> dict[str, Any] | None:
    version = finding.version or finding.tls_version
    if not version:
        return None
    family = {"tls": "tls", "ssh": "ssh", "ipsec": "ipsec"}.get(finding.service)
    if not family:
        return None
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("protocol", finding.target.hostname, str(finding.target.port), version),
        "name": f"{version} on {finding.target.hostname}:{finding.target.port}",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {"type": family, "version": version},
        },
        "properties": [
            {"name": "pqscan:endpoint", "value": f"{finding.target.hostname}:{finding.target.port}"},
            {"name": "pqscan:pq-readiness", "value": finding.pq_readiness},
            {"name": "pqscan:system", "value": finding.target.system_name},
            {"name": "pqscan:classification", "value": finding.target.classification},
        ],
    }


def _certificate_component(certificate: CertificateData) -> dict[str, Any]:
    properties = [
        {"name": "pqscan:signature-algorithm", "value": certificate.sig_algo or "unknown"},
        {"name": "pqscan:public-key-classification", "value": _value(certificate.pub_key_classification)},
        {"name": "pqscan:signature-classification", "value": _value(certificate.sig_classification)},
    ]
    # One certificate commonly serves many endpoints; the usage list is what makes a CBOM
    # actionable, because it says what breaks when this key has to be replaced.
    properties.extend({"name": "pqscan:used-by", "value": usage} for usage in certificate.usages)
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("certificate", certificate.fingerprint_sha256),
        "name": certificate.subject_cn or certificate.fingerprint_sha256[:16],
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": certificate.subject_cn or "",
                "issuerName": certificate.issuer or "",
                "notValidBefore": _isoformat(certificate.not_before),
                "notValidAfter": _isoformat(certificate.not_after),
                "signatureAlgorithmRef": _bom_ref("algorithm", "signature", certificate.sig_algo or "unknown"),
                "subjectPublicKeyRef": _bom_ref("algorithm", "public-key", certificate.pub_key_algo or "unknown"),
                "certificateFormat": "X.509",
            },
        },
        "properties": properties,
    }


def _value(item: Any) -> str:
    return item.value if isinstance(item, Classification) else str(item)


def _isoformat(value: Any) -> str:
    if value is None:
        return ""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def build_cbom(
    findings: list[HostFinding],
    certificates: dict[str, CertificateData],
    rules_version: str = "unknown",
    operator: str = "unknown",
    engagement: str = "unknown",
) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(component: dict[str, Any] | None) -> None:
        if component and component["bom-ref"] not in seen:
            seen.add(component["bom-ref"])
            components.append(component)

    for finding in findings:
        add(_protocol_component(finding))
        for role, entries in (finding.algorithms or {}).items():
            for entry in entries:
                add(_algorithm_component(
                    entry["name"], role, entry.get("classification", "REVIEW"), entry.get("in_use", False)
                ))
        # The TLS path records its negotiated group and cipher outside `algorithms`, so they
        # would otherwise be missing from the inventory entirely.
        if finding.negotiated_group and finding.negotiated_group not in ("unknown", "n/a"):
            add(_algorithm_component(finding.negotiated_group, "key_exchange", "REVIEW", True))
        if finding.cipher_suite:
            add(_algorithm_component(finding.cipher_suite, "cipher", "REVIEW", True))

    for certificate in certificates.values():
        add(_certificate_component(certificate))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(),
            "tools": {"components": [{"type": "application", "name": "pqscan", "publisher": "Nayef Alharbi"}]},
            "properties": [
                # State the provenance of the claim. A CBOM from a source scan and a CBOM
                # from observed traffic are different evidence, and a reader has to know which.
                {"name": "pqscan:evidence", "value": "observed-network-negotiation"},
                {"name": "pqscan:ruleset", "value": rules_version},
                {"name": "pqscan:ism-controls", "value": "ISM-2082, ISM-2083"},
                {"name": "pqscan:operator", "value": operator},
                {"name": "pqscan:engagement", "value": engagement},
            ],
        },
        "components": components,
    }


def write_cbom(path: str, document: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
