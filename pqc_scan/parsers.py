import datetime
import logging
import re
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqc_scan.models import CertificateData, Classification

# A named logger, so a library consumer can silence or route these without touching the
# root logger, which is shared with whatever embeds this package.
_log = logging.getLogger(__name__)


class RuleEngine:
    def __init__(self, profile_name: str = "asd_ism"):
        rules_path = Path(__file__).resolve().parent / "rules" / f"{profile_name}.yaml"
        with rules_path.open() as f:
            data = yaml.safe_load(f)

        req_keys = ['profile', 'signature_patterns', 'group_aliases', 'key_exchange_groups']
        for k in req_keys:
            if k not in data:
                raise KeyError(f"Missing required key '{k}' in rules")
        if "name" not in data["profile"]:
            raise KeyError("Missing 'profile.name' in rules")
        if "milestones" not in data["profile"]:
            raise KeyError("Missing 'profile.milestones' in rules")

        self.profile_name = data["profile"]["name"]
        self.rules = data
        milestones = data['profile']['milestones']
        start_date = milestones.get('migration_started_by') or milestones.get('transitional_deadline') or "2028-01-01"
        comp_date = milestones.get('transition_complete_by') or milestones.get('transitional_deadline') or "2030-01-01"
        self.deadline_started = datetime.datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=datetime.UTC)
        self.deadline_complete = datetime.datetime.strptime(comp_date, "%Y-%m-%d").replace(tzinfo=datetime.UTC)

    def classify_key_exchange(self, group_name: str) -> Classification:
        if not group_name:
            return Classification.REVIEW
        g_clean = group_name.strip().lower()
        aliases = self.rules.get("group_aliases", {})
        key_groups = self.rules.get("key_exchange_groups", {})

        canonical = aliases.get(g_clean)
        targets_to_check = [canonical] if canonical else []
        targets_to_check.append(g_clean)

        for target in targets_to_check:
            if not target:
                continue
            t_lower = target.strip().lower()
            for classification_str, group_list in key_groups.items():
                for g in group_list:
                    if g.strip().lower() == t_lower:
                        return Classification(classification_str)

        _log.warning("Unrecognised key exchange group: '{group_name}'")
        return Classification.REVIEW

    def classify_signature(self, sig_name: str) -> Classification:
        if not sig_name:
            return Classification.REVIEW
        s_clean = sig_name.strip().lower()
        patterns = self.rules.get("signature_patterns", [])
        for entry in patterns:
            pat = entry.get("pattern", "")
            if pat and re.search(str(pat).strip().lower(), s_clean, re.IGNORECASE):
                cls = entry.get("classification")
                if cls:
                    return Classification(str(cls).upper())
        key_exchange_class = self.classify_key_exchange(sig_name)
        if key_exchange_class != Classification.REVIEW:
            return key_exchange_class
        _log.warning("Unrecognised signature algorithm: '{sig_name}'. Defaulting to REVIEW.")
        return Classification.REVIEW

    def ssh_ignored(self, name: str) -> bool:
        """Signalling entries that appear in a KEXINIT name-list but are not algorithms."""
        return name.strip().lower() in {
            item.lower() for item in self.rules.get("ssh", {}).get("ignore", [])
        }

    def classify_ssh(self, category: str, name: str) -> Classification:
        """Classify one SSH algorithm.

        `category` is key_exchange, host_keys, ciphers or macs. OpenSSH certificate host key
        types are the base algorithm with a suffix, so they inherit the base classification
        rather than falling through to REVIEW.
        """
        if not name:
            return Classification.REVIEW
        cleaned = name.strip().lower()
        for suffix in ("-cert-v01@openssh.com", "-cert-v00@openssh.com"):
            if cleaned.endswith(suffix):
                cleaned = cleaned[: -len(suffix)]
        table = self.rules.get("ssh", {}).get(category, {})
        for classification, entries in table.items():
            for entry in entries or []:
                if str(entry).strip().lower() == cleaned:
                    return Classification(str(classification).upper())
        _log.warning("Unrecognised SSH %s algorithm: %r", category, name)
        return Classification.REVIEW

    def classify_ipsec(self, category: str, name: str) -> Classification:
        """Classify one IKEv2 transform. `category` is encryption, prf, integrity or dh_groups."""
        if not name:
            return Classification.REVIEW
        cleaned = name.strip().upper()
        table = self.rules.get("ipsec", {}).get(category, {})
        for classification, entries in table.items():
            for entry in entries or []:
                if str(entry).strip().upper() == cleaned:
                    return Classification(str(classification).upper())
        _log.warning("Unrecognised IPsec %s transform: %r", category, name)
        return Classification.REVIEW

    def classify_public_key(self, algorithm: str) -> Classification:
        if not algorithm:
            return Classification.REVIEW
        algorithms = self.rules.get("public_key_algorithms", {})
        for name, classification in algorithms.items():
            if str(name).lower() == algorithm.strip().lower():
                return Classification(str(classification).upper())
        _log.warning("Unrecognised public key algorithm: '{algorithm}'. Defaulting to REVIEW.")
        return Classification.REVIEW

def _public_key_details(public_key: object) -> tuple[str, int | None, str | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size, public_key.curve.name
    # Ed25519 and Ed448 keys carry no key_size attribute at all, so reading one raised
    # AttributeError on every Ed25519 certificate. Both curves are fixed size.
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, "ed448"
    if isinstance(public_key, dh.DHPublicKey):
        return "DH", public_key.key_size, None
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, None
    return type(public_key).__name__, getattr(public_key, "key_size", None), None


def parse_certificate_pem(pem_data: str, engine: RuleEngine) -> CertificateData:
    certificate = x509.load_pem_x509_certificate(pem_data.encode("ascii"))
    public_key_algo, public_key_size, public_key_curve = _public_key_details(certificate.public_key())
    try:
        raw_cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_cn = raw_cn.decode("utf-8", "replace") if isinstance(raw_cn, bytes) else raw_cn
    except IndexError:
        subject_cn = None
    try:
        sans = [str(value.value) if hasattr(value, "value") else str(value) for value in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        sans = []
    try:
        is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    try:
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
    except AttributeError:
        not_before = certificate.not_valid_before.replace(tzinfo=datetime.UTC)
        not_after = certificate.not_valid_after.replace(tzinfo=datetime.UTC)
    try:
        algorithm = certificate.signature_hash_algorithm
        sig_hash = algorithm.name if algorithm is not None else None
    except (ValueError, AttributeError):
        # Ed25519 and Ed448 have no separate signature hash; cryptography raises here.
        sig_hash = None
    sig_algo = certificate.signature_algorithm_oid._name or certificate.signature_algorithm_oid.dotted_string

    return CertificateData(
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        subject_cn=subject_cn,
        sans=sans,
        issuer=certificate.issuer.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        pub_key_algo=public_key_algo,
        pub_key_size=public_key_size,
        pub_key_curve=public_key_curve,
        sig_algo=sig_algo,
        sig_hash=sig_hash,
        is_self_signed=certificate.subject == certificate.issuer,
        is_ca=is_ca,
        pub_key_classification=engine.classify_public_key(public_key_algo),
        sig_classification=engine.classify_signature(sig_algo),
    )
