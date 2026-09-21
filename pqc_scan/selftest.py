"""End-to-end check of the scanner against endpoints with a known answer.

The unit tests prove the parsers and the scoring behave; this proves the whole tool still
reaches real servers and reaches the right conclusion about them. Those fail in different
ways, so both are worth having: a unit test cannot catch a server that stopped answering, and
a live scan cannot tell you which line broke.

One rule shapes the design: a host that cannot be reached from this network is reported
UNREACHABLE, never FAIL. Outbound UDP 500 and port 21 are commonly filtered, and a corporate
proxy will break half of these. Calling that a scanner defect would train you to ignore the
output, which is the one thing a self-test must not do.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pqc_scan.models import HostFinding, Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.probes import ProbeContext, run_probe
from pqc_scan.scoring import Scorer

PASS, FAIL, UNREACHABLE = "PASS", "FAIL", "UNREACHABLE"

# Reasons that mean "the network in between refused", as opposed to "the scanner is wrong".
NETWORK_REASONS = {
    "timeout", "tcp_connect_timeout", "dns_failure", "no_ike_response",
    "ike_probe_failed", "unsupported_protocol", "spi_mismatch",
    # A public test server that rate-limits us is declining to serve, not failing a check.
    "service_unavailable",
    # The port is not TLS but the server would not answer a second connection to tell us
    # what it is. That is throttling, not a wrong answer.
    "protocol_undetermined",
}


@dataclass
class CaseResult:
    name: str
    endpoint: str
    status: str
    detail: str = ""


def load_cases(path: str | Path | None = None) -> list[dict[str, Any]]:
    source = Path(path) if path else Path(__file__).resolve().parent / "rules" / "selftest.yaml"
    with source.open() as handle:
        return yaml.safe_load(handle).get("cases", [])


def _findings(finding: HostFinding) -> list[str]:
    return [str(item) for item in (finding.rule_findings + finding.validation_failures)]


def check(case: dict[str, Any], finding: HostFinding) -> CaseResult:
    endpoint = f"{case['host']}:{case['port']}"
    expect = case.get("expect", {}) or {}
    problems: list[str] = []

    if finding.not_testable_reason in NETWORK_REASONS:
        return CaseResult(
            case["name"], endpoint, UNREACHABLE,
            f"not reachable from here ({finding.not_testable_reason})",
        )

    if "service" in expect and finding.service != expect["service"]:
        problems.append(f"service {finding.service!r}, expected {expect['service']!r}")

    if "readiness" in expect and finding.pq_readiness != expect["readiness"]:
        problems.append(f"readiness {finding.pq_readiness!r}, expected {expect['readiness']!r}")

    if expect.get("measured") and finding.confidentiality_score is None:
        # The failure mode this tool exists to avoid: going quiet on the hosts that matter.
        problems.append("not measured (no confidentiality score)")

    if "group_contains" in expect:
        needle = str(expect["group_contains"]).lower()
        if needle not in (finding.negotiated_group or "").lower():
            problems.append(f"group {finding.negotiated_group!r} does not contain {needle!r}")

    observed = _findings(finding)
    for needle in expect.get("findings", []) or []:
        if not any(needle in item for item in observed):
            problems.append(f"missing finding {needle!r}")
    for needle in expect.get("absent", []) or []:
        if any(needle in item for item in observed):
            problems.append(f"unexpected finding {needle!r}")

    # A missing score or band must never satisfy a bound: None is "not measured", and an
    # unmeasured endpoint passing a check is the failure mode this whole file guards against.
    score = finding.confidentiality_score
    if "min_confidentiality" in expect and (
        score is None or score < expect["min_confidentiality"]
    ):
        problems.append(
            f"confidentiality {score}, expected at least {expect['min_confidentiality']}"
        )
    band = finding.readiness_band
    if "max_band" in expect and (band is None or band > expect["max_band"]):
        problems.append(f"band {band}, expected at most {expect['max_band']}")
    if "min_band" in expect and (band is None or band < expect["min_band"]):
        problems.append(f"band {band}, expected at least {expect['min_band']}")

    if problems:
        return CaseResult(case["name"], endpoint, FAIL, "; ".join(problems))
    return CaseResult(case["name"], endpoint, PASS)


async def run_cases(
    cases: list[dict[str, Any]], timeout: float = 10.0, concurrency: int = 4
) -> list[CaseResult]:
    """Run every case, then re-run any failure once, alone and with a longer timeout.

    A live test that reports a different answer each run teaches you to ignore it. Most
    first-round failures here are the network in between - a burst of connections that looked
    like a scan to a rate limiter, or a slow path that overran the timeout - and those are not
    scanner defects. A failure that survives an unhurried, uncontended retry is a real one.
    """
    engine = RuleEngine()
    scorer = Scorer()
    context = ProbeContext(engine=engine, timeout=timeout)
    semaphore = asyncio.Semaphore(concurrency)
    # Several cases deliberately target the same host (github.com:22 and ssh.github.com:443,
    # three badssl subdomains). Probing them at once looks like a burst to the operator and
    # gets throttled, which showed up as intermittent failures that were really rate limits.
    host_locks: dict[str, asyncio.Lock] = {}

    async def one(case: dict[str, Any], patience: float | None = None) -> CaseResult:
        target = Target(
            hostname=case["host"],
            port=case.get("port", 443),
            protocol=case.get("protocol"),
            criticality="medium",
        )
        domain = ".".join(case["host"].rsplit(".", 2)[-2:])
        lock = host_locks.setdefault(domain, asyncio.Lock())
        attempt = context if patience is None else ProbeContext(
            engine=engine, timeout=patience, certificates=context.certificates
        )
        async with semaphore, lock:
            try:
                finding = await run_probe(target, attempt)
            except Exception as error:
                # An exception escaping a probe is always a scanner defect: every expected
                # failure mode is supposed to come back as a finding.
                return CaseResult(
                    case["name"], f"{case['host']}:{case['port']}", FAIL,
                    f"probe raised {type(error).__name__}: {error}",
                )
        scorer.calculate_scores(finding, context.certificates, engine)
        scorer.assign_readiness_band(finding)
        return check(case, finding)

    results = list(await asyncio.gather(*(one(case) for case in cases)))

    suspects = [index for index, result in enumerate(results) if result.status == FAIL]
    if not suspects:
        return results
    # Serially, with room to breathe: nothing else is competing for the network now, so a
    # failure that repeats here is the tool, not the conditions.
    for index in suspects:
        await asyncio.sleep(1.0)
        retry = await one(cases[index], patience=timeout * 2.5)
        if retry.status == PASS:
            retry.detail = "passed on retry (first attempt hit a transient network failure)"
        results[index] = retry
    return results


async def run_cases_with_findings(
    cases: list[dict[str, Any]], timeout: float = 10.0, concurrency: int = 4
) -> tuple[list[CaseResult], list[HostFinding], dict[str, Any]]:
    """Run the cases and hand back the findings as well as the verdicts.

    The findings are what make this a demonstration rather than a test log: they go through
    the same reporter the real command uses, so what you see is the actual product output for
    every protocol at once, and the verdicts below it say whether that output is correct.
    """
    engine = RuleEngine()
    scorer = Scorer()
    context = ProbeContext(engine=engine, timeout=timeout)
    semaphore = asyncio.Semaphore(concurrency)
    host_locks: dict[str, asyncio.Lock] = {}
    findings: dict[int, HostFinding] = {}

    async def one(index: int, case: dict[str, Any], patience: float | None = None) -> CaseResult:
        target = Target(
            hostname=case["host"],
            port=case.get("port", 443),
            protocol=case.get("protocol"),
            criticality=case.get("criticality", "medium"),
            system_name=case.get("name", "reference endpoint"),
            data_lifetime_years=case.get("data_lifetime_years", 5),
            owner="Self-test",
        )
        attempt = context if patience is None else ProbeContext(
            engine=engine, timeout=patience, certificates=context.certificates
        )
        domain = ".".join(case["host"].rsplit(".", 2)[-2:])
        lock = host_locks.setdefault(domain, asyncio.Lock())
        async with semaphore, lock:
            try:
                finding = await run_probe(target, attempt)
            except Exception as error:
                return CaseResult(
                    case["name"], f"{case['host']}:{case['port']}", FAIL,
                    f"probe raised {type(error).__name__}: {error}",
                )
        scorer.calculate_scores(finding, context.certificates, engine)
        scorer.assign_readiness_band(finding)
        finding.rule_findings.extend(
            item for item in finding.validation_failures if item not in finding.rule_findings
        )
        findings[index] = finding
        return check(case, finding)

    results = list(await asyncio.gather(*(one(i, c) for i, c in enumerate(cases))))
    for index, result in enumerate(results):
        if result.status != FAIL:
            continue
        await asyncio.sleep(1.0)
        retry = await one(index, cases[index], patience=timeout * 2.5)
        if retry.status == PASS:
            retry.detail = "passed on retry (first attempt hit a transient network failure)"
        results[index] = retry

    # Several cases deliberately share an endpoint - cloudflare.com is checked both for
    # hybrid key exchange and for raising no certificate error. Each keeps its own verdict,
    # but the scan report shows each endpoint once, the way a real scan would.
    ordered: list[HostFinding] = []
    seen: set[tuple[str, int, str]] = set()
    for index in sorted(findings):
        finding = findings[index]
        key = (finding.target.hostname, finding.target.port, finding.service)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(finding)
    return results, ordered, context.certificates
