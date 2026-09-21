from pathlib import Path
from typing import ClassVar

import yaml

from pqc_scan.models import CertificateData, Classification, HostFinding
from pqc_scan.parsers import RuleEngine


class Scorer:
    def __init__(self, rules_path: str | None = None):
        path = Path(rules_path) if rules_path else Path(__file__).resolve().parent / "rules" / "scoring.yaml"
        with path.open() as f:
            self.weights = yaml.safe_load(f)

    SEVERITY: ClassVar = {
        Classification.APPROVED: 0,
        Classification.TRANSITIONAL: 1,
        Classification.REVIEW: 2,
        Classification.NOT_APPROVED_AFTER_2030: 3,
        Classification.NOT_APPROVED: 4,
    }

    def _unapproved_offered(self, finding: HostFinding, roles: tuple[str, ...], weights: dict) -> tuple[int, list[str]]:
        """ISM-0471: only approved algorithms are used by cryptographic equipment.

        An endpoint that OFFERS an unapproved algorithm will use it when a client asks for it,
        so offering one is a breach in itself, not only a risk when it is selected. Charged per
        algorithm and capped so a long legacy list cannot swamp the rest of the score.
        """
        offenders = [
            item["name"]
            for role in roles
            for item in finding.algorithms.get(role, [])
            if item["classification"] == Classification.NOT_APPROVED.value
        ]
        if not offenders:
            return 0, []
        per = weights.get("unapproved_algorithm_offered", 0)
        total = min(len(offenders) * per, weights.get("unapproved_algorithm_cap", len(offenders) * per))
        label = f"unapproved_algorithm_offered (ISM-0471): {', '.join(offenders)}"
        return total, [label]

    def _score_ssh(self, finding: HostFinding, engine: RuleEngine) -> None:
        """Score an SSH endpoint with the same weights the TLS path uses.

        The ISM's Secure Shell section directs the reader back to the approved-algorithm
        controls, so key exchange is the confidentiality dimension and the host key is the
        authentication dimension, exactly as for TLS.
        """
        conf_weights = self.weights["confidentiality"]
        auth_weights = self.weights["authentication"]
        criticality = finding.target.criticality
        conf_multiplier = conf_weights["criticality_multiplier"][criticality]
        auth_multiplier = auth_weights["criticality_multiplier"][criticality]

        kex = finding.algorithms.get("key_exchange", [])
        host_keys = finding.algorithms.get("signature", [])
        if not kex and not host_keys:
            finding.confidentiality_explanation = "Not measured (no algorithms observed)."
            finding.authentication_explanation = "Not measured (no algorithms observed)."
            finding.pq_readiness = "unknown"
            return

        def best(entries):
            return min(
                (Classification(item["classification"]) for item in entries),
                key=lambda value: self.SEVERITY[value], default=None,
            )

        def worst(entries):
            return max(
                (Classification(item["classification"]) for item in entries),
                key=lambda value: self.SEVERITY[value], default=None,
            )

        # Confidentiality: the strongest key exchange is what a modern client gets.
        best_kex = best(kex)
        conf_score = conf_weights["key_exchange"][best_kex.value] if best_kex else conf_weights["key_exchange"]["NOT_APPROVED"]
        conf_explanation = [f"best key exchange offered -> {best_kex.value if best_kex else 'none'} (+{conf_score})"]
        if best_kex not in (Classification.APPROVED, Classification.TRANSITIONAL):
            conf_score += conf_weights["no_pq_group_offered"]
            conf_explanation.append(f"no post-quantum key exchange offered (+{conf_weights['no_pq_group_offered']})")
            finding.pq_status = "not_supported"
        else:
            finding.pq_status = "supported"
        lifetime = finding.target.data_lifetime_years
        if lifetime > 10:
            conf_score += conf_weights["data_lifetime_years"]["over_10"]
            conf_explanation.append(f"data_lifetime > 10y (+{conf_weights['data_lifetime_years']['over_10']})")
        elif lifetime >= 5:
            conf_score += conf_weights["data_lifetime_years"]["5_to_10"]
            conf_explanation.append(f"data_lifetime > 5y (+{conf_weights['data_lifetime_years']['5_to_10']})")
        penalty, labels = self._unapproved_offered(finding, ("key_exchange", "cipher", "mac"), conf_weights)
        if penalty:
            conf_score += penalty
            conf_explanation.append(f"{labels[0]} (+{penalty})")
            finding.rule_findings.extend(labels)
        finding.confidentiality_score = min(conf_weights["cap"], int(conf_score * conf_multiplier))
        finding.confidentiality_explanation = "\n    ".join(conf_explanation) + (
            f"\n    subtotal {conf_score} x criticality {criticality} {conf_multiplier} = {finding.confidentiality_score}"
        )

        # Authentication: the weakest host key is what an attacker steers a client toward.
        worst_key = worst(host_keys)
        auth_score = auth_weights["signature_algorithm"][worst_key.value] if worst_key else auth_weights["signature_algorithm"]["NOT_APPROVED"]
        auth_explanation = [f"weakest host key offered -> {worst_key.value if worst_key else 'none'} (+{auth_score})"]
        penalty, labels = self._unapproved_offered(finding, ("signature",), auth_weights)
        if penalty:
            auth_score += penalty
            auth_explanation.append(f"{labels[0]} (+{penalty})")
            finding.rule_findings.extend(labels)
        if "ssh_version_not_approved" in finding.validation_failures:
            points = auth_weights["validation_failure_penalty"]
            auth_score += points
            auth_explanation.append(f"ssh_version_not_approved (ISM-1506) (+{points})")
        finding.authentication_score = min(auth_weights["cap"], int(auth_score * auth_multiplier))
        finding.authentication_explanation = "\n    ".join(auth_explanation) + (
            f"\n    subtotal {auth_score} x criticality {criticality} {auth_multiplier} = {finding.authentication_score} (capped at {auth_weights['cap']})"
        )

        finding.pq_readiness = (
            "pure_pq_approved" if best_kex == Classification.APPROVED
            else "hybrid_transitional" if best_kex == Classification.TRANSITIONAL
            else "classical_only"
        )

    def _score_ipsec(self, finding: HostFinding, engine: RuleEngine) -> None:
        """Score an IKEv2 responder.

        IKEv2 returns the single proposal the responder chose, not a menu, so there is no
        best/worst distinction to make: what came back IS what a peer gets. Confidentiality
        is the D-H group (ISM-0999) plus the encryption transform (ISM-1771); authentication
        is the integrity transform (ISM-0998), since that is what protects the exchange from
        tampering.
        """
        conf_weights = self.weights["confidentiality"]
        auth_weights = self.weights["authentication"]
        criticality = finding.target.criticality
        conf_multiplier = conf_weights["criticality_multiplier"][criticality]
        auth_multiplier = auth_weights["criticality_multiplier"][criticality]

        def one(role: str) -> Classification | None:
            entries = finding.algorithms.get(role, [])
            return Classification(entries[0]["classification"]) if entries else None

        group = one("key_exchange")
        if group is None:
            finding.confidentiality_explanation = "Not measured (no IKE response)."
            finding.authentication_explanation = "Not measured (no IKE response)."
            finding.pq_readiness = "unknown"
            return

        conf_score = conf_weights["key_exchange"][group.value]
        conf_explanation = [f"IKE D-H group {finding.negotiated_group} -> {group.value} (ISM-0999) (+{conf_score})"]

        cipher = one("cipher")
        if cipher and cipher in (Classification.NOT_APPROVED, Classification.NOT_APPROVED_AFTER_2030):
            points = conf_weights["protocol"].get("symmetric_not_approved", 0)
            conf_score += points
            conf_explanation.append(f"encryption {finding.cipher_suite} -> {cipher.value} (ISM-1771) (+{points})")
        if "ipsec_encryption_not_aes_gcm (ISM-1771)" in finding.rule_findings:
            points = conf_weights["protocol"].get("cipher_not_aes_gcm", 0)
            conf_score += points
            conf_explanation.append(f"encryption is not AES-GCM (ISM-1771) (+{points})")

        # Readiness is about post-quantum, and for IPsec the classification table cannot
        # answer it: ECP_384 is TRANSITIONAL because ISM-0999 PREFERS it, not because it is
        # quantum-resistant. Reading readiness off the classification would have reported a
        # plain ECDH gateway as HYBRID. Only an ML-KEM group makes an IPsec endpoint anything
        # other than classical.
        name = (finding.negotiated_group or "").upper()
        if name == "ML_KEM_1024":
            finding.pq_readiness = "pure_pq_approved"
        elif name.startswith("ML_KEM"):
            finding.pq_readiness = "hybrid_transitional"
        else:
            finding.pq_readiness = "classical_only"
        finding.pq_status = "not_supported" if finding.pq_readiness == "classical_only" else "supported"
        if finding.pq_status == "not_supported":
            conf_score += conf_weights["no_pq_group_offered"]
            conf_explanation.append(f"no post-quantum key exchange (+{conf_weights['no_pq_group_offered']})")

        finding.confidentiality_score = min(conf_weights["cap"], int(conf_score * conf_multiplier))
        finding.confidentiality_explanation = "\n    ".join(conf_explanation) + (
            f"\n    subtotal {conf_score} x criticality {criticality} {conf_multiplier} = {finding.confidentiality_score}"
        )

        integrity = one("mac")
        auth_score = auth_weights["signature_algorithm"][integrity.value] if integrity else auth_weights["signature_algorithm"]["NOT_APPROVED"]
        auth_explanation = [f"integrity {finding.observations.get('integrity')} -> "
                f"{integrity.value if integrity else 'none'} (ISM-0998) (+{auth_score})"]
        for failure in ("ike_version_not_approved", "ipsec_no_integrity_without_aead"):
            if failure in finding.validation_failures:
                points = auth_weights["validation_failure_penalty"]
                auth_score += points
                auth_explanation.append(f"{failure} (+{points})")
        finding.authentication_score = min(auth_weights["cap"], int(auth_score * auth_multiplier))
        finding.authentication_explanation = "\n    ".join(auth_explanation) + (
            f"\n    subtotal {auth_score} x criticality {criticality} {auth_multiplier} = {finding.authentication_score}"
        )

    def _score_domain(self, finding: HostFinding) -> None:
        """Score a domain's email and web transport posture.

        Confidentiality is left unset on purpose: an SPF record says nothing about quantum
        resistance, and putting a number there would imply a measurement we did not make.
        """
        auth_weights = self.weights["authentication"]
        criticality = finding.target.criticality
        auth_multiplier = auth_weights["criticality_multiplier"][criticality]
        finding.confidentiality_score = None
        finding.pq_readiness = "unknown"

        if finding.not_testable_reason:
            finding.authentication_explanation = "Not measured (DNS lookups failed)."
            return

        points = auth_weights["validation_failure_penalty"]
        breaches = list(finding.validation_failures)
        auth_score = len(breaches) * points
        explanation = [f"{tag} (+{points})" for tag in breaches] or ["all observed controls met (+0)"]
        finding.authentication_score = min(auth_weights["cap"], int(auth_score * auth_multiplier))
        finding.authentication_explanation = "\n    ".join(explanation) + (
            f"\n    subtotal {auth_score} x criticality {criticality} {auth_multiplier} = {finding.authentication_score}"
        )

    def assign_readiness_band(self, finding: HostFinding) -> None:
        """Place an endpoint on PQScan's 0-5 readiness band.

        Derived from the same evidence as the scores, so it adds no new measurement - what it
        adds is the distinction the raw number hides: an endpoint that CANNOT do post-quantum
        and one that CAN but does not are both "classical", and only the second is a
        configuration change away from done.

        Deliberately not the PKI Consortium's PQCMM. That model rates a named product as
        shipped, and its upper levels require an SBOM, a CBOM, crypto-agility, an HNDL
        register and FIPS or Common Criteria validation - none of which a handshake reveals.

        An endpoint we could not measure gets no band: "unmeasured" is not a posture, and a 0
        would read as a finding.
        """
        model = self.weights.get("readiness_band", {})
        levels = model.get("levels", {})
        if not levels or finding.confidentiality_score is None:
            return
        disqualifiers = set(model.get("disqualifiers", []))
        if disqualifiers.intersection(finding.validation_failures) or (
            model.get("disqualify_obsolete_protocol") and finding.obsolete_tls_only
        ):
            finding.readiness_band = 0
            finding.readiness_band_name = (levels.get(0) or {}).get("name", "Unprotected")
            return
        if finding.pq_readiness == "unknown":
            return

        for level in sorted(levels, reverse=True):
            rules = levels[level] or {}
            readiness = rules.get("requires_readiness")
            if readiness and finding.pq_readiness not in readiness:
                continue
            if rules.get("requires_pq_capability") and not self._offers_post_quantum(finding):
                continue
            limit = rules.get("max_confidentiality")
            if limit is not None and finding.confidentiality_score > limit:
                continue
            limit = rules.get("max_authentication")
            if limit is not None and (
                finding.authentication_score is None or finding.authentication_score > limit
            ):
                continue
            finding.readiness_band = int(level)
            finding.readiness_band_name = rules.get("name")
            return
        finding.readiness_band = 0
        finding.readiness_band_name = (levels.get(0) or {}).get("name", "Unprotected")

    @staticmethod
    def _offers_post_quantum(finding: HostFinding) -> bool:
        """Does this endpoint accept a post-quantum key exchange it is not choosing to use?

        This is the whole point of the capability probe. A server with X25519MLKEM768 in its
        group list but x25519 in its ServerHello is one preference line away from compliant,
        and telling those apart from a server with no support at all is the difference
        between a morning's work and a procurement cycle.
        """
        candidates = list(finding.groups_supported or []) + list(finding.pq_groups_supported or [])
        markers = ("mlkem", "ml-kem", "kyber")
        return any(marker in name.lower() for name in candidates for marker in markers)

    def calculate_scores(self, finding: HostFinding, certs_map: dict[str, CertificateData], engine: RuleEngine) -> None:
        conf_weights = self.weights["confidentiality"]
        auth_weights = self.weights["authentication"]
        criticality = finding.target.criticality
        conf_multiplier = conf_weights["criticality_multiplier"][criticality]
        auth_multiplier = auth_weights["criticality_multiplier"][criticality]
        if finding.service == "ssh":
            self._score_ssh(finding, engine)
            return
        if finding.service == "ipsec":
            self._score_ipsec(finding, engine)
            return
        if finding.service == "domain":
            self._score_domain(finding)
            return
        tls_rules = engine.rules.get("tls", {})
        protocol_weights = conf_weights.get("protocol", {})
        confidentiality_findings: list[tuple[str, int]] = []
        if finding.tls_version and finding.tls_version not in tls_rules.get("approved_versions", []):
            confidentiality_findings.append(("tls_version_not_approved (ISM-1139)", protocol_weights.get("tls_version_not_approved", 0)))
        cipher_name = (finding.cipher_suite or "").lower()
        symmetric = tls_rules.get("symmetric", {})
        if cipher_name and "gcm" not in cipher_name:
            confidentiality_findings.append(("cipher_not_aes_gcm (ISM-1369)", protocol_weights.get("cipher_not_aes_gcm", 0)))
        if any(token and token in cipher_name for token in symmetric.get("NOT_APPROVED_AFTER_2030", [])):
            confidentiality_findings.append(("symmetric_not_approved_after_2030", protocol_weights.get("symmetric_not_approved_after_2030", 0)))
        if any(token and token in cipher_name for token in symmetric.get("NOT_APPROVED", [])):
            confidentiality_findings.append(("symmetric_not_approved", protocol_weights.get("symmetric_not_approved", 0)))
        if any(token and token in cipher_name for token in symmetric.get("NO_ENCRYPTION", [])):
            # Nothing weaker exists, so this alone must reach the cap.
            confidentiality_findings.append(("no_encryption (ISM-0469, ISM-1369)", protocol_weights.get("no_encryption", 0)))
        if (
            cipher_name
            and finding.tls_version != "TLSv1.3"
            and not any(token in cipher_name for token in ("ecdhe", "dhe"))
        ):
            confidentiality_findings.append(("no_forward_secrecy (ISM-1372, ISM-1453)", protocol_weights.get("no_forward_secrecy", 0)))
        # What the server ACCEPTS, not just what it prefers. A downgrade attack does not ask
        # the server for its favourite suite.
        accepted = [name.lower() for name in finding.accepted_cipher_suites]
        weak_accepted = sorted({
            name for name in accepted
            if any(token and token in name for token in
                   symmetric.get("NOT_APPROVED", []) + symmetric.get("NO_ENCRYPTION", []))
        })
        if weak_accepted:
            confidentiality_findings.append((
                f"unapproved_cipher_accepted (ISM-0471): {len(weak_accepted)} suite(s)",
                protocol_weights.get("unapproved_cipher_accepted", 0),
            ))
        # ISM-1372 and ISM-1453: RSA key transport carries no forward secrecy. A server can
        # prefer ECDHE and still accept a static-RSA suite, which defeats both controls.
        if any(
            name.startswith("tls_rsa_with") or "_rsa_export_" in name
            for name in accepted
        ):
            confidentiality_findings.append((
                "static_rsa_key_transport_accepted (ISM-1372, ISM-1453)",
                protocol_weights.get("no_forward_secrecy", 0),
            ))
        for name, _ in confidentiality_findings:
            if name not in finding.rule_findings:
                finding.rule_findings.append(name)
        # Only a STRONGER capability is a finding. ffdhe2048 and x25519 are both
        # NOT_APPROVED_AFTER_2030, so "supports ffdhe2048 as well as x25519" tells a reader
        # nothing and previously produced misleading advice.
        if finding.best_supported_group and finding.best_supported_group != finding.negotiated_group:
            rank = {"APPROVED": 0, "TRANSITIONAL": 1, "NOT_APPROVED_AFTER_2030": 2, "REVIEW": 3, "NOT_APPROVED": 4}
            best = rank.get(engine.classify_key_exchange(finding.best_supported_group).value, 9)
            current = rank.get(engine.classify_key_exchange(finding.negotiated_group).value, 9)
            if best < current:
                finding.capability_exceeds_default = True
                finding.rule_findings.append("capability_exceeds_default_negotiation")
        protocol_penalty = sum(weight for _, weight in confidentiality_findings)
        protocol_explanation = [f"{name} (+{weight})" for name, weight in confidentiality_findings]

        if "no_tls_offered" in finding.validation_failures:
            # Plaintext on the wire. There is no key exchange to classify and nothing about
            # it is post-quantum, so it scores as the worst case rather than as unmeasured.
            finding.confidentiality_score = conf_weights["cap"]
            finding.pq_status = "not_supported"
            finding.pq_readiness = "classical_only"
            finding.confidentiality_explanation = (
                "no_tls_offered: the service refused to upgrade to TLS, so traffic is "
                f"unencrypted (ISM-1139). Scored at the cap ({conf_weights['cap']})."
            )
            finding.rule_findings.append("no_tls_offered (ISM-1139)")
        elif finding.obsolete_tls_only:
            conf_score = conf_weights["no_pq_group_offered"] + conf_weights["key_exchange"]["NOT_APPROVED"] + protocol_penalty
            finding.confidentiality_score = min(conf_weights["cap"], int(conf_score * conf_multiplier))
            finding.pq_status = "not_supported"
            # Measured, and the answer is no. Post-quantum key exchange requires TLS 1.3, so
            # a host stuck below it is classical with certainty, not unmeasured.
            finding.pq_readiness = "classical_only"
            finding.confidentiality_explanation = (
                f"obsolete_tls ({finding.max_supported_tls}):\n"
                f"    key exchange -> NOT_APPROVED (+{conf_weights['key_exchange']['NOT_APPROVED']})\n"
                f"    pq_state not_supported (+{conf_weights['no_pq_group_offered']})\n"
                + "\n".join(f"    {line}" for line in protocol_explanation) + "\n"
                f"    subtotal {conf_score} x criticality {criticality} {conf_multiplier} = {finding.confidentiality_score}"
            )
        elif finding.negotiated_group == "unknown" or finding.pq_status == "not_determinable":
            finding.confidentiality_score = None
            finding.pq_readiness = "unknown"
            finding.confidentiality_explanation = "Not measured (undetermined group or connection failed)."
        else:
            cls = engine.classify_key_exchange(finding.negotiated_group)
            readiness = engine.rules.get("pq_readiness", {})
            finding.pq_readiness = next(
                (name for name, classes in readiness.items() if cls.value in classes),
                "unknown",
            )
            conf_score = conf_weights["key_exchange"][cls.value]
            ex = [f"key exchange {finding.negotiated_group} -> {cls.value} (+{conf_score})"]
            ex.extend(protocol_explanation)

            if finding.pq_status == "not_supported":
                conf_score += conf_weights["no_pq_group_offered"]
                ex.append(f"pq_state not_supported (+{conf_weights['no_pq_group_offered']})")

            lifetime = finding.target.data_lifetime_years
            if lifetime > 10:
                conf_score += conf_weights["data_lifetime_years"]["over_10"]
                ex.append(f"data_lifetime > 10y (+{conf_weights['data_lifetime_years']['over_10']})")
            elif lifetime >= 5:
                conf_score += conf_weights["data_lifetime_years"]["5_to_10"]
                ex.append(f"data_lifetime > 5y (+{conf_weights['data_lifetime_years']['5_to_10']})")
            conf_score += protocol_penalty

            finding.confidentiality_score = min(conf_weights["cap"], int(conf_score * conf_multiplier))
            finding.confidentiality_explanation = "\n    ".join(ex) + f"\n    subtotal {conf_score} x criticality {criticality} {conf_multiplier} = {finding.confidentiality_score}"

        if finding.obsolete_tls_only:
            finding.chain_classification = Classification.REVIEW
            finding.chain_classification_reason = f"obsolete_tls ({finding.max_supported_tls})"
            obsolete_penalty = auth_weights.get("obsolete_tls_penalty", 40)
            finding.authentication_score = min(auth_weights["cap"], int(obsolete_penalty * auth_multiplier))
            finding.authentication_explanation = f"obsolete_tls review penalty ({obsolete_penalty}) x criticality {criticality} {auth_multiplier} = {finding.authentication_score}"
            return

        if not finding.certificate_fingerprints:
            finding.chain_classification = None
            finding.authentication_score = None
            finding.authentication_explanation = "No certificates collected."
            return

        if len(finding.certificate_fingerprints) == 1:
            leaf_cert = certs_map.get(finding.certificate_fingerprints[0])
            if leaf_cert and leaf_cert.is_self_signed:
                if "self_signed" not in finding.validation_failures:
                    finding.validation_failures.append("self_signed")
            else:
                if "incomplete_chain" not in finding.validation_failures:
                    finding.validation_failures.append("incomplete_chain")
            finding.chain_classification = Classification.REVIEW
            finding.chain_classification_reason = "Single certificate; chain not established"

        auth_score = 0
        weakest_signature: CertificateData | None = None
        weakest_signature_class = Classification.APPROVED
        worst_chain_class = Classification.APPROVED
        reason_tag = "standard"
        auth_explanation = []
        hash_classes = engine.rules.get("hashes", {})
        approved_hashes = [h.lower() for h in hash_classes.get("APPROVED", [])]
        transitional_hashes = [h.lower() for h in hash_classes.get("NOT_APPROVED_AFTER_2030", [])]
        failed_hashes = [h.lower() for h in hash_classes.get("NOT_APPROVED", [])]
        chain_hashes: list[str] = []
        for index, fingerprint in enumerate(finding.certificate_fingerprints):
            cert = certs_map.get(fingerprint)
            if not cert:
                continue

            if weakest_signature is None or self.SEVERITY[cert.sig_classification] > self.SEVERITY[weakest_signature_class]:
                weakest_signature = cert
                weakest_signature_class = cert.sig_classification
            if cert.sig_hash:
                chain_hashes.append(cert.sig_hash.lower())

            # Count every supplied post-leaf certificate, including a root, as chain evidence.
            if (
                index > 0
                and len(finding.certificate_fingerprints) > 1
                and self.SEVERITY[cert.sig_classification] > self.SEVERITY[worst_chain_class]
            ):
                worst_chain_class = cert.sig_classification
                reason_tag = f"{cert.sig_algo} intermediate: {cert.subject_cn or 'Unknown'}"
        if weakest_signature is not None:
            signature_points = auth_weights["signature_algorithm"][weakest_signature_class.value]
            auth_score += signature_points
            auth_explanation.append(
                f"weakest signature in chain: {weakest_signature.sig_algo} on "
                f"{weakest_signature.subject_cn or 'Unknown'} -> "
                f"{weakest_signature_class.value} (+{signature_points})"
            )

        if any(hash_name in failed_hashes for hash_name in chain_hashes):
            auth_score += auth_weights["hashes"]["NOT_APPROVED"]
            auth_explanation.append(f"worst hash in chain: NOT_APPROVED (+{auth_weights['hashes']['NOT_APPROVED']})")
        elif any(hash_name in transitional_hashes for hash_name in chain_hashes):
            auth_score += auth_weights["hashes"]["NOT_APPROVED_AFTER_2030"]
            auth_explanation.append(f"worst hash in chain: NOT_APPROVED_AFTER_2030 (+{auth_weights['hashes']['NOT_APPROVED_AFTER_2030']})")
        elif any(hash_name in approved_hashes for hash_name in chain_hashes):
            auth_explanation.append("worst hash in chain: APPROVED (+0)")

        leaf_cert = certs_map.get(finding.certificate_fingerprints[0])
        if leaf_cert and leaf_cert.not_after:
            if leaf_cert.not_after > engine.deadline_complete:
                auth_score += auth_weights["not_after_2030"]
                auth_explanation.append(f"notAfter > 2030 (+{auth_weights['not_after_2030']})")
            elif leaf_cert.not_after > engine.deadline_started:
                auth_score += auth_weights["not_after_2028"]
                auth_explanation.append(f"notAfter > 2028 (+{auth_weights['not_after_2028']})")

        if len(finding.certificate_fingerprints) > 1:
            finding.chain_classification = worst_chain_class
            finding.chain_classification_reason = reason_tag

        val_failures = list(set(finding.validation_failures))
        val_penalty = len(val_failures) * auth_weights["validation_failure_penalty"]
        capped_val = min(auth_weights["validation_failure_cap"], val_penalty)
        if capped_val > 0:
            auth_score += capped_val
            auth_explanation.append(f"validation failures {val_failures} (+{capped_val})")

        leaf_cert = certs_map.get(finding.certificate_fingerprints[0]) if finding.certificate_fingerprints else None
        key_rules = engine.rules.get("key_sizes", {})
        key_weight = auth_weights.get("key_size", {})
        # Accumulated, then capped once at the end. Assigning here meant that when both the
        # key size and the curve were below preferred, only the second counted - while the
        # explanation printed both, so the breakdown did not add up to the score.
        info_notes = 0
        if leaf_cert and leaf_cert.pub_key_algo in key_rules:
            rules = key_rules[leaf_cert.pub_key_algo]
            if leaf_cert.pub_key_size is not None and leaf_cert.pub_key_size < rules.get("minimum_bits", 0):
                points = key_weight.get("below_minimum", 0)
                auth_score += points
                auth_explanation.append(f"key_size_below_minimum (ISM-0472/0474/0475/0476) (+{points})")
                finding.rule_findings.append("key_size_below_minimum (ISM-0472/0474/0475/0476)")
            elif leaf_cert.pub_key_size is not None and leaf_cert.pub_key_size < rules.get("preferred_bits", leaf_cert.pub_key_size):
                points = key_weight.get("below_preferred", 0)
                info_notes += points
                auth_explanation.append(f"key_size_below_preferred (informational) (+{points})")
                finding.rule_findings.append("key_size_below_preferred (informational)")
            preferred_curve = rules.get("preferred_curve")
            if preferred_curve and leaf_cert.pub_key_curve and leaf_cert.pub_key_curve != preferred_curve:
                points = key_weight.get("below_preferred", 0)
                info_notes += points
                auth_explanation.append(f"curve_below_preferred (informational) (+{points})")
                finding.rule_findings.append("curve_below_preferred (informational)")
        classification_rules = engine.rules.get("classification_curve_rules", {}).get(finding.target.classification)
        if classification_rules and leaf_cert and leaf_cert.pub_key_curve and leaf_cert.pub_key_curve not in classification_rules.get("allowed_curves", []):
            points = auth_weights.get("classification_curve_violation", 0)
            auth_score += points
            auth_explanation.append(f"classification_curve_violation (ISM-1761/1762/1763/1764) (+{points})")
            finding.rule_findings.append("classification_curve_violation (ISM-1761/1762/1763/1764)")
        # ISM wording matters here: controls phrased "is used" are mandatory and carry a real
        # penalty, while "preferably" is a preference. The cap keeps preferences from adding
        # up to look like a breach.
        auth_score += min(info_notes, auth_weights.get("informational_note_cap", 0))

        finding.authentication_score = min(auth_weights["cap"], int(auth_score * auth_multiplier))
        finding.authentication_explanation = "\n    ".join(auth_explanation) + f"\n    subtotal {auth_score} x criticality {criticality} {auth_multiplier} = {finding.authentication_score} (capped at {auth_weights['cap']})"
