from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Classification(StrEnum):
    APPROVED = "APPROVED"
    TRANSITIONAL = "TRANSITIONAL"
    REVIEW = "REVIEW"
    NOT_APPROVED_AFTER_2030 = "NOT_APPROVED_AFTER_2030"
    NOT_APPROVED = "NOT_APPROVED"

class Target(BaseModel):
    hostname: str
    port: int = 443
    protocol: str | None = None
    data_lifetime_years: int = 0
    owner: str = "Unknown"
    system_name: str = "Unknown"
    criticality: Literal["low", "medium", "high"] = "medium"
    classification: Literal["NC", "OS", "P", "S", "TS"] = "OS"

class CertificateData(BaseModel):
    fingerprint_sha256: str
    subject_cn: str | None = None
    sans: list[str] = Field(default_factory=list)
    issuer: str = ""
    not_before: Any = None
    not_after: Any = None
    pub_key_algo: str = ""
    pub_key_size: int | None = None
    pub_key_curve: str | None = None
    sig_algo: str = ""
    sig_hash: str | None = None
    is_self_signed: bool = False
    is_ca: bool = False
    pub_key_classification: Classification = Classification.REVIEW
    sig_classification: Classification = Classification.REVIEW
    usages: list[str] = Field(default_factory=list)

class HostFinding(BaseModel):
    # Reject unknown constructor arguments. A mistyped or undeclared field used to be
    # accepted and thrown away, which loses evidence without failing anything.
    model_config = ConfigDict(extra="forbid")

    """One result, whatever protocol produced it.

    Probes differ; this shape does not. Scoring, reporting and the CBOM all work on this and
    never learn which protocol was involved, so adding a protocol costs one probe plus one
    rules section, not a second copy of everything downstream.
    """

    target: Target
    service: Literal["tls", "ssh", "ipsec", "domain"] = "tls"
    # Protocol-neutral version for display ("TLSv1.3", "SSH-2.0"). tls_version stays as the
    # TLS-specific field because `pqc verify` compares it against openssl directly.
    version: str | None = None
    # role -> [{name, classification, in_use}]. Roles are shared across protocols:
    # key_exchange, signature, cipher, mac.
    algorithms: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    pq_readiness: Literal["pure_pq_approved", "hybrid_transitional", "classical_only", "unknown"] = "unknown"
    observations: dict[str, Any] = Field(default_factory=dict)
    rule_findings: list[str] = Field(default_factory=list)
    not_testable_reason: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    negotiated_group: str = "unknown"
    pq_groups_offered: list[str] = Field(default_factory=list)
    # Post-quantum groups the endpoint accepted during the capability probe. This was being
    # passed to the constructor without being declared, so pydantic dropped it silently and
    # the capability evidence never reached the report or the JSON export.
    pq_groups_supported: list[str] = Field(default_factory=list)
    groups_supported: list[str] = Field(default_factory=list)
    best_supported_group: str | None = None
    # True only when the endpoint would accept a group that is STRONGER under the rule
    # profile than the one it negotiates with a default client, not merely different.
    capability_exceeds_default: bool = False
    probe_method: str = "native"
    pq_status: Literal["supported", "not_supported", "not_determinable"] = "not_determinable"
    certificate_fingerprints: list[str] = Field(default_factory=list)
    validation_failures: list[str] = Field(default_factory=list)
    handshake_errors: list[str] = Field(default_factory=list)
    # Suites the server will ACCEPT, which is not the same as the one it prefers. A server
    # that leads with AES-GCM and still accepts 3DES is an ISM-0471 finding; reading only the
    # preferred suite misses exactly the suite an attacker would downgrade to.
    accepted_cipher_suites: list[str] = Field(default_factory=list)
    obsolete_tls_only: bool = False
    max_supported_tls: str | None = None
    confidentiality_score: int | None = None
    authentication_score: int | None = None
    chain_classification: Classification | None = None
    chain_classification_reason: str = "standard"
    # PQScan's own readiness band, 0-5. Not the PKI Consortium's PQCMM: that model rates a
    # named product on evidence a handshake cannot see. This one describes what the endpoint
    # actually does, and separates "cannot do post-quantum" from "can but does not".
    readiness_band: int | None = None
    readiness_band_name: str | None = None
    confidentiality_explanation: str = ""
    authentication_explanation: str = ""
