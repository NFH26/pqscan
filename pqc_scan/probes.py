"""One probe per protocol, one result shape for all of them.

Architecture, deliberately small:

    port_map.yaml  ->  protocol name  ->  PROBES[name]  ->  HostFinding  ->  Scorer  ->  Reporter

A probe's only job is to observe an endpoint and describe what it found in the shared
HostFinding shape. It never scores, never formats and never knows about reports. Everything
downstream works on HostFinding and never learns which protocol produced it.

To add a protocol (IKE, S/MIME, a database wire protocol):
  1. write `async def probe_x(target, context) -> HostFinding` here or in its own module,
  2. add its algorithm classifications to the rule profile,
  3. register it in PROBES and give it a port in port_map.yaml.
Nothing else changes.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, cast

from pqc_scan.collectors import NativeTLSCollector
from pqc_scan.domain_probe import probe_domain
from pqc_scan.ike_probe import probe_ike
from pqc_scan.models import CertificateData, Classification, HostFinding, Target
from pqc_scan.parsers import RuleEngine, parse_certificate_pem
from pqc_scan.ssh_probe import probe_ssh
from pqc_scan.tls_probe import enumerate_cipher_suites

# Worst wins when summarising a list of algorithms.
SEVERITY = {
    Classification.APPROVED: 0,
    Classification.TRANSITIONAL: 1,
    Classification.REVIEW: 2,
    Classification.NOT_APPROVED_AFTER_2030: 3,
    Classification.NOT_APPROVED: 4,
}


# Ranked from the rule profile rather than a hardcoded list, so a group added to the YAML is
# ordered correctly without a code change.
_GROUP_RANK = {
    "APPROVED": 0, "TRANSITIONAL": 1, "NOT_APPROVED_AFTER_2030": 2, "REVIEW": 3, "NOT_APPROVED": 4,
}


def best_supported_group(groups: list[str], engine: RuleEngine) -> str | None:
    """Strongest group the endpoint will accept, by ISM classification.

    This lives with the probe, not in the scan loop. It is derived from what the probe
    observed, so computing it in the CLI meant every other caller - the library API, the
    self-test - silently got a finding with the field unset, and the "can do better than it
    does" marker never fired for them.
    """
    if not groups:
        return None
    return min(
        groups,
        key=lambda name: (_GROUP_RANK.get(engine.classify_key_exchange(name).value, 9), name),
    )


@dataclass
class ProbeContext:
    """Everything a probe needs that is not the target itself."""

    engine: RuleEngine
    timeout: float = 10.0
    verbose: bool = False
    no_pq_probe: bool = False
    # Off by default: enumerating suites means one connection per suite, which is slow and
    # looks aggressive. Worth it when you need to know what a server ACCEPTS, not prefers.
    enumerate_ciphers: bool = False
    # Ceiling on the WHOLE of one host, as a multiple of `timeout`. Each phase has its own
    # timeout and they compose: an IKE cookie retry inside an INVALID_KE retry, or fourteen
    # sequential DKIM lookups, could otherwise hold a slot for minutes. A host that overruns
    # is reported as timed out, which is true, rather than quietly stalling the scan.
    host_budget_multiplier: float = 6.0
    # Shared across hosts on purpose: one certificate can serve many endpoints, and the
    # inventory records every usage. Probes only ever ADD to it.
    certificates: dict[str, CertificateData] = field(default_factory=dict)


def _best(entries: list[dict], engine: RuleEngine) -> str | None:
    """Strongest algorithm in a role, by classification."""
    if not entries:
        return None
    return min(entries, key=lambda item: SEVERITY[Classification(item["classification"])])["name"]


async def probe_tls(target: Target, context: ProbeContext) -> HostFinding:
    collector = NativeTLSCollector(
        timeout=context.timeout, no_pq_probe=context.no_pq_probe, verbose=context.verbose
    )
    observation = await collector.collect_tls(target)
    # On the obsolete-TLS path the handshake never completes, so tls_version is None while
    # max_supported_tls holds what the server would actually speak. That is the version the
    # readiness verdict must be based on.
    effective_version = observation.tls_version or observation.max_supported_tls
    pq_groups, pq_status, probe_errors = await collector.probe_pq_groups(
        target, effective_version, observation.negotiated_group, observation.supported_groups
    )
    errors = list(observation.errors) + probe_errors

    fingerprints: list[str] = []
    usage = f"{target.hostname}:{target.port} ({target.protocol})"
    for pem in observation.pems:
        try:
            certificate = parse_certificate_pem(pem, context.engine)
        except Exception as error:  # a malformed certificate must not lose the whole host
            errors.append(f"Cert parse error: {error}")
            continue
        stored = context.certificates.setdefault(certificate.fingerprint_sha256, certificate)
        # A retry under a sniffed protocol, or a re-run, would otherwise append the same
        # endpoint twice and double-count it in the CBOM's used-by list - the one field that
        # makes the document actionable.
        if usage not in stored.usages:
            stored.usages.append(usage)
        fingerprints.append(certificate.fingerprint_sha256)

    accepted_suites: list[str] = []
    if context.enumerate_ciphers and observation.tls_version != "TLSv1.3":
        # TLS 1.3 has five suites, all approved, and negotiates them separately from the
        # legacy list, so enumerating there tells you nothing. Below 1.3 it tells you
        # everything: which weak suites survive in the config behind a strong default.
        accepted_suites, _ = await enumerate_cipher_suites(
            target.hostname, target.port, timeout=context.timeout,
            protocol=target.protocol, starttls_prelude=collector._perform_starttls,
        )

    return HostFinding(
        target=target,
        service="tls",
        accepted_cipher_suites=accepted_suites,
        version=observation.tls_version,
        tls_version=observation.tls_version,
        cipher_suite=observation.cipher_suite,
        observations={
            "tls_version": observation.tls_version,
            "cipher_suite": observation.cipher_suite,
            "negotiated_group": observation.negotiated_group,
        },
        not_testable_reason=_not_testable(errors, context.no_pq_probe),
        negotiated_group=observation.negotiated_group,
        pq_groups_supported=pq_groups,
        pq_status=pq_status,
        pq_groups_offered=collector.pq_groups,
        groups_supported=observation.supported_groups,
        best_supported_group=best_supported_group(observation.supported_groups, context.engine),
        probe_method="native",
        certificate_fingerprints=fingerprints,
        handshake_errors=errors,
        validation_failures=observation.validation_failures,
        obsolete_tls_only=observation.obsolete_tls_only,
        max_supported_tls=observation.max_supported_tls,
    )


async def probe_ssh_target(target: Target, context: ProbeContext) -> HostFinding:
    engine = context.engine
    observation = await probe_ssh(target.hostname, target.port, context.timeout)

    def classify(category: str, names: list[str]) -> list[dict]:
        return [
            {
                "name": name,
                "classification": engine.classify_ssh(category, name).value,
                # SSH servers advertise everything they accept, so each entry is "offered".
                # The client chooses, which is why offering a weak algorithm is itself a
                # finding under ISM-0471 rather than only a risk when it is selected.
                "in_use": False,
            }
            for name in names
            if not engine.ssh_ignored(name)
        ]

    algorithms = {
        "key_exchange": classify("key_exchange", observation.kex_algorithms),
        "signature": classify("host_keys", observation.host_key_algorithms),
        "cipher": classify("ciphers", observation.ciphers),
        "mac": classify("macs", observation.macs),
    }
    best_kex = _best(algorithms["key_exchange"], engine)

    approved_versions = engine.rules.get("ssh", {}).get("approved_protocol_versions", [])
    errors = list(observation.errors)
    validation_failures = []
    if observation.protocol_version and approved_versions and observation.protocol_version not in approved_versions:
        # ISM-1506: the use of SSH version 1 is disabled for SSH connections.
        validation_failures.append("ssh_version_not_approved")

    return HostFinding(
        target=target,
        service="ssh",
        version=f"SSH-{observation.protocol_version}" if observation.protocol_version else None,
        cipher_suite=_best(algorithms["cipher"], engine),
        algorithms=algorithms,
        observations={"banner": observation.banner, "software": observation.software},
        not_testable_reason=observation.not_testable_reason,
        negotiated_group=best_kex or "unknown",
        groups_supported=[item["name"] for item in algorithms["key_exchange"]],
        probe_method="native",
        handshake_errors=errors,
        validation_failures=validation_failures,
    )


async def probe_ipsec(target: Target, context: ProbeContext) -> HostFinding:
    """Assess an IKEv2 responder against the ISM's IPsec controls."""
    engine = context.engine
    # 0 means "not specified"; anything else is what the operator or the port map chose, and
    # a genuine IKE responder on a non-standard port must not be silently redirected to 500.
    port = target.port or 500
    observation = await probe_ike(target.hostname, port, context.timeout)

    def entry(category: str, name: str | None) -> list[dict]:
        if not name:
            return []
        return [{
            "name": name,
            "classification": engine.classify_ipsec(category, name).value,
            # Unlike SSH, IKEv2 returns the ONE proposal the responder chose, so every
            # transform here is actually in use rather than merely offered.
            "in_use": True,
        }]

    algorithms = {
        "key_exchange": entry("dh_groups", observation.dh_group),
        "cipher": entry("encryption", observation.encryption),
        "mac": entry("integrity", observation.integrity),
        "prf": entry("prf", observation.prf),
    }

    rules = engine.rules.get("ipsec", {})
    validation_failures: list[str] = []
    rule_findings: list[str] = []

    if observation.responded:
        if observation.version_major not in rules.get("approved_versions", [2]):
            # ISM-1233: IKE version 2 is used for key exchange when establishing IPsec.
            validation_failures.append("ike_version_not_approved")
            rule_findings.append("ike_version_not_approved (ISM-1233)")
        if observation.encryption and "GCM" not in observation.encryption:
            # ISM-1771 prefers ENCR_AES_GCM_16.
            rule_findings.append("ipsec_encryption_not_aes_gcm (ISM-1771)")
        if observation.integrity == "NONE" and not (
            observation.encryption and ("GCM" in observation.encryption or "CCM" in observation.encryption)
        ):
            # ISM-0998 allows NONE only alongside AES-GCM. Without an AEAD cipher there is
            # no integrity protection at all, which the transform name alone would hide.
            validation_failures.append("ipsec_no_integrity_without_aead")
            rule_findings.append("ipsec_no_integrity_without_aead (ISM-0998)")

    finding = HostFinding(
        target=target,
        service="ipsec",
        version=f"IKEv{observation.version_major}" if observation.version_major else None,
        cipher_suite=observation.encryption,
        algorithms=algorithms,
        observations={
            "encryption": observation.encryption,
            "encryption_key_bits": observation.encryption_key_bits,
            "prf": observation.prf,
            "integrity": observation.integrity,
            "dh_group": observation.dh_group,
            "notify": observation.notify_errors,
            # Named so the report can say which controls this probe cannot reach, rather
            # than leaving them silently absent.
            "controls_not_observable": rules.get("not_observable", {}),
        },
        not_testable_reason=observation.not_testable_reason,
        negotiated_group=observation.dh_group or "unknown",
        groups_supported=[observation.dh_group] if observation.dh_group else [],
        probe_method="native",
        handshake_errors=list(observation.errors),
        validation_failures=validation_failures,
    )
    finding.rule_findings.extend(rule_findings)
    return finding


async def probe_domain_target(target: Target, context: ProbeContext) -> HostFinding:
    """Assess a domain's email and web transport controls.

    Unlike the other probes this one is not about an endpoint's handshake, so it produces no
    key exchange and no readiness verdict - an organisation's SPF record tells you nothing
    about quantum resistance. It scores on the authentication axis only, and deliberately
    leaves confidentiality unset rather than inventing a number for it.
    """
    observation = await probe_domain(target.hostname, context.timeout)

    findings: list[str] = []
    failures: list[str] = []

    def fail(tag: str) -> None:
        failures.append(tag)
        findings.append(tag)

    def unknown(control: str, why: str) -> None:
        """Record a control we could not observe, without charging it as a breach."""
        findings.append(f"{control} (not observed: {why})")

    for control, label, why in (
        ("spf (ISM-0574)", "spf", "DNS lookup failed"),
        ("dmarc (ISM-1540)", "dmarc", "DNS lookup failed"),
        ("mta_sts (ISM-1589)", "mta_sts", "DNS lookup or policy fetch failed"),
        ("hsts (ISM-1424)", "hsts", "the site could not be fetched"),
    ):
        if label not in observation.observed:
            unknown(control, why)

    if observation.not_testable_reason is None:
        if "spf" in observation.observed:
            if not observation.spf:
                fail("spf_absent (ISM-0574)")
            elif not observation.spf_hard_fail:
                # ISM-1183 asks for a hard fail. "~all" only soft-fails, so a forged sender
                # is still delivered, which is the outcome the control exists to prevent.
                fail("spf_not_hard_fail (ISM-1183)")
        if "dmarc" in observation.observed:
            if not observation.dmarc:
                fail("dmarc_absent (ISM-1540)")
            elif observation.dmarc_policy != "reject":
                # ISM-1540 requires that failing email be REJECTED. p=none and p=quarantine
                # both still deliver it somewhere.
                fail(f"dmarc_policy_not_reject (ISM-1540): p={observation.dmarc_policy}")
        if "mta_sts" in observation.observed:
            if not observation.mta_sts_dns:
                fail("mta_sts_absent (ISM-1589)")
            elif observation.mta_sts_policy_mode != "enforce":
                fail(f"mta_sts_not_enforcing (ISM-1589): mode={observation.mta_sts_policy_mode}")
        if "hsts" in observation.observed and not observation.hsts:
            fail("hsts_absent (ISM-1424)")
        if not observation.dkim_selector:
            # Not a failure. A DKIM record lives at a selector name that only appears in a
            # signed message header, so it cannot be enumerated: absence of a hit is absence
            # of evidence, and reporting it as a breach would be wrong.
            findings.append("dkim_not_found_with_common_selectors (ISM-0861, inconclusive)")

    return HostFinding(
        target=target,
        service="domain",
        version="domain",
        observations={
            "spf": observation.spf,
            "spf_hard_fail": observation.spf_hard_fail,
            "dmarc": observation.dmarc,
            "dmarc_policy": observation.dmarc_policy,
            "dkim_selector": observation.dkim_selector,
            "mta_sts": observation.mta_sts_policy_mode if observation.mta_sts_dns else None,
            "hsts": observation.hsts,
            "hsts_max_age": observation.hsts_max_age,
        },
        not_testable_reason=observation.not_testable_reason,
        negotiated_group="n/a",
        probe_method="native",
        handshake_errors=list(observation.errors),
        validation_failures=failures,
        rule_findings=findings,
    )


def _not_testable(errors: list[str], no_pq_probe: bool) -> str | None:
    if any(error.startswith("service_unavailable:") for error in errors):
        return "service_unavailable"
    if any(error.startswith("unsupported_protocol:") for error in errors):
        return "unsupported_protocol"
    if any("gaierror" in error for error in errors):
        return "dns_failure"
    if any("during TCP connect" in error for error in errors):
        return "tcp_connect_timeout"
    if any(error.startswith("timed out") for error in errors):
        return "timeout"
    return "no_pq_probe" if no_pq_probe else None


Probe = Callable[[Target, ProbeContext], Awaitable[HostFinding]]

PROBES: dict[str, Probe] = {
    "tls": probe_tls,
    "ssh": probe_ssh_target,
    "ipsec": probe_ipsec,
    "ikev2": probe_ipsec,
    "domain": probe_domain_target,
}


def probe_for(protocol: str | None) -> Probe:
    """Resolve a protocol name to its probe. STARTTLS variants are TLS with a prelude."""
    name = (protocol or "tls").split(":", 1)[0].lower()
    if name == "starttls":
        return PROBES["tls"]
    return PROBES.get(name, PROBES["tls"])

# Bytes a server sends unprompted, mapped to the protocol they identify. A TLS server never
# speaks first, so anything that arrives before we send a byte tells us we guessed wrong.
BANNER_SIGNATURES = (
    (b"SSH-", "ssh"),
    (b"220 ", "starttls:smtp"),
    (b"220-", "starttls:smtp"),
    (b"* OK", "starttls:imap"),
    (b"+OK", "starttls:pop3"),
)

# Errors that mean "this port is not speaking TLS", as opposed to "TLS here is broken".
WRONG_PROTOCOL_SIGNALS = (
    "wrong_version_number",
    "wrong version number",
    "unknown_protocol",
    "record layer failure",
    "packet length too long",
)


async def sniff_protocol(target: Target, timeout: float) -> str | None:
    """Read the greeting a server sends on connect and name the protocol it belongs to."""
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(target.hostname, target.port)
            try:
                greeting = await reader.read(64)
            finally:
                writer.close()
                await writer.wait_closed()
    except (TimeoutError, OSError):
        return None
    for signature, protocol in BANNER_SIGNATURES:
        if greeting.startswith(signature):
            return protocol
    return None


async def run_probe(target: Target, context: ProbeContext) -> HostFinding:
    """Probe one target within a single overall time budget."""
    budget = context.timeout * max(context.host_budget_multiplier, 1.0)
    try:
        async with asyncio.timeout(budget):
            return await _run_probe(target, context)
    except TimeoutError:
        return HostFinding(
            target=target,
            service=cast(Any, _service_of(target)),
            not_testable_reason="timeout",
            handshake_errors=[f"exceeded the {budget:.0f}s budget for this host"],
        )


def _service_of(target: Target) -> str:
    """The probe family a target belongs to, defaulting to TLS."""
    name = (target.protocol or "tls").split(":", 1)[0].lower()
    return name if name in PROBES else "tls"


async def _run_probe(target: Target, context: ProbeContext) -> HostFinding:
    """Probe a target, retrying under a different protocol if the port is not what we assumed.

    Port numbers are a guess, not a contract: ssh.github.com listens for SSH on 443 and a
    TLS probe there fails with a record-layer error that tells the operator nothing. Rather
    than making people annotate every non-standard port, we listen for the server's greeting
    and probe again with the protocol it names.
    """
    finding = await probe_for(target.protocol)(target, context)
    declared = (target.protocol or "tls").split(":", 1)[0].lower()
    if declared != "tls" or finding.negotiated_group not in (None, "unknown", ""):
        return finding
    blob = " ".join(finding.handshake_errors).lower()
    if not any(signal in blob for signal in WRONG_PROTOCOL_SIGNALS):
        return finding
    detected = await sniff_protocol(target, context.timeout)
    if not detected or detected.split(":", 1)[0].lower() == "tls":
        # We know this port is not speaking TLS but could not learn what it is speaking -
        # usually the server throttled the second connection. Reporting the failed TLS
        # finding as-is would state a verdict about a protocol that was never measured, so
        # say plainly that detection did not complete.
        if not finding.not_testable_reason:
            finding.not_testable_reason = "protocol_undetermined"
        return finding
    retried = target.model_copy(update={"protocol": detected})
    result = await probe_for(detected)(retried, context)
    # An informational note, not a failure: the Issues table is for things the operator has
    # to act on, and "we worked out what this port really is" is not one of them.
    result.observations["auto_detected_protocol"] = detected
    return result
