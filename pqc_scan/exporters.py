"""One registry of output formats, one way to add another.

    FORMATS[name] -> writer(path, findings, certificates, engine, metadata)

Mirrors the probe registry deliberately: a probe is "one protocol in, one HostFinding out",
an exporter is "findings in, one file out". Adding a format is a function and a dict entry,
and nothing else in the tool changes.
"""
from __future__ import annotations

import datetime
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqc_scan.cbom import build_cbom, write_cbom
from pqc_scan.models import CertificateData, HostFinding
from pqc_scan.remediation import consolidate

Writer = Callable[..., None]


@dataclass(frozen=True)
class Format:
    extension: str
    writer: Writer
    description: str


def _payload(findings: list[HostFinding], certificates: dict[str, CertificateData],
             metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "metadata": metadata,
        "findings": [json.loads(f.model_dump_json()) for f in findings],
        "certificates": {k: json.loads(v.model_dump_json()) for k, v in certificates.items()},
    }


def write_json(path: Path, findings, certificates, engine, metadata, reporter=None) -> None:
    path.write_text(json.dumps(_payload(findings, certificates, metadata), indent=2) + "\n",
                    encoding="utf-8")


def write_cbom_format(path: Path, findings, certificates, engine, metadata, reporter=None) -> None:
    write_cbom(str(path), build_cbom(
        findings, certificates,
        rules_version=str(metadata.get("rules_version")),
        operator=str(metadata.get("operator", "unknown")),
        engagement=str(metadata.get("engagement", "unknown")),
    ))


def write_html(path: Path, findings, certificates, engine, metadata, reporter=None) -> None:
    reporter.write_html(str(path))


def write_csv(path: Path, findings, certificates, engine, metadata, reporter=None) -> None:
    reporter.write_csv(str(path))


def write_markdown(path: Path, findings, certificates, engine, metadata, reporter=None) -> None:
    """A summary that pastes into a ticket, an email or a pull request comment."""
    lines = [
        f"# Post-quantum readiness: {metadata.get('engagement', 'scan')}",
        "",
        f"Profile `{metadata.get('profile', 'asd_ism')}`, rules `{metadata.get('rules_version')}`, "
        f"scanned {metadata.get('scan_time', '')} by {metadata.get('operator', 'unknown')}.",
        "",
        "| Endpoint | Service | Key exchange | Readiness | Band | Conf | Auth | Findings |",
        "|---|---|---|---|---:|---:|---:|---|",
    ]
    for finding in sorted(findings, key=lambda f: -(f.confidentiality_score or -1)):
        band = (
            f"{finding.readiness_band} {finding.readiness_band_name}"
            if finding.readiness_band is not None else "n/a"
        )
        items = ", ".join(finding.rule_findings[:3]) or "none"
        lines.append(
            f"| `{finding.target.hostname}:{finding.target.port}` | {finding.service} "
            f"| {finding.negotiated_group} | {finding.pq_readiness} | {band} "
            f"| {finding.confidentiality_score if finding.confidentiality_score is not None else 'n/a'} "
            f"| {finding.authentication_score if finding.authentication_score is not None else 'n/a'} "
            f"| {items} |"
        )
    lines += ["", "Risk 0 means the endpoint already meets the profile, 100 is the worst case.", ""]
    # A ticket needs the endpoints, not a count: an estate can hold several VPNs and a
    # dozen SSH hosts, and whoever picks the ticket up has to know which one to change.
    actions = consolidate(list(findings), engine) if engine is not None else []
    if actions:
        lines += ["## Recommendations", ""]
        for index, action in enumerate(actions, start=1):
            lines.append(f"{index}. **{action.action}** ({action.effort})")
            if action.why:
                lines.append(f"   - Why: {action.why}")
            lines.append("   - Applies to: " + ", ".join(f"`{host}`" for host in action.hosts))
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_sarif(path: Path, findings, certificates, engine, metadata, reporter=None) -> None:
    """SARIF 2.1.0, so findings appear natively in CI and code-scanning dashboards.

    Every finding becomes a result against the endpoint, and each distinct rule tag becomes a
    SARIF rule carrying its ISM control number - which is what makes the output useful in a
    dashboard that knows nothing about cryptography.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        endpoint = f"{finding.target.hostname}:{finding.target.port}"
        for tag in finding.rule_findings:
            rule_id = tag.split(" (")[0].split(":")[0].strip().replace(" ", "_") or "finding"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": rule_id.replace("_", " ")},
                    "fullDescription": {"text": tag},
                    "properties": {"tags": ["cryptography", "post-quantum", "ASD-ISM"]},
                }
            score = finding.confidentiality_score or 0
            results.append({
                "ruleId": rule_id,
                "level": "error" if score >= 75 else "warning" if score >= 40 else "note",
                "message": {"text": f"{endpoint} ({finding.service}): {tag}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"{finding.service}://{endpoint}"},
                        "region": {"startLine": 1},
                    }
                }],
                "properties": {
                    "confidentiality_score": finding.confidentiality_score,
                    "authentication_score": finding.authentication_score,
                    "pq_readiness": finding.pq_readiness,
                    "readiness_band": finding.readiness_band,
                },
            })
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pqscan",
                "informationUri": "https://github.com/nayefalharbi/pqscan",
                "version": str(metadata.get("tool_version", "0")),
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


FORMATS: dict[str, Format] = {
    "html": Format("report.html", write_html, "Styled report for a person to read"),
    "csv": Format("findings.csv", write_csv, "One row per endpoint, opens in Excel"),
    "json": Format("findings.json", write_json, "Everything the scan observed, for another tool"),
    "cbom": Format("cbom.json", write_cbom_format, "CycloneDX cryptographic bill of materials"),
    "sarif": Format("findings.sarif", write_sarif, "For CI and code-scanning dashboards"),
    "md": Format("summary.md", write_markdown, "Markdown table for a ticket or an email"),
}


def resolve(names: str | None) -> list[str]:
    """Turn a --format value into a list of format names, defaulting to all of them."""
    if not names or names.strip().lower() == "all":
        return list(FORMATS)
    chosen, unknown = [], []
    for raw in names.replace(" ", "").split(","):
        if not raw:
            continue
        if raw.lower() in FORMATS:
            chosen.append(raw.lower())
        else:
            unknown.append(raw)
    if unknown:
        raise ValueError(
            f"unknown format(s): {', '.join(unknown)}. Available: {', '.join(FORMATS)}"
        )
    return chosen


def run_directory(base: str, engagement: str, when: str | None = None) -> Path:
    """A dated subdirectory per run, so one scan never overwrites another.

    A compliance report is evidence, and evidence that a later run silently replaced is not
    evidence. The name carries the engagement and the timestamp so a directory listing is
    already an audit trail.
    """
    stamp = (when or datetime.datetime.now(datetime.UTC).isoformat())[:19]
    stamp = stamp.replace(":", "").replace("-", "").replace("T", "-")
    # The engagement name can come from a host file, so it is sanitised rather than trusted:
    # anything but letters, digits, dot, dash and underscore becomes a dash, and leading dots
    # are stripped so no name can contain a path segment or start with one.
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", engagement).strip("-.") or "scan"
    safe = safe.replace("..", "-")
    return Path(base) / f"{stamp}-{safe}"


def export(
    directory: str,
    names: str | None,
    findings: list[HostFinding],
    certificates: dict[str, CertificateData],
    engine: Any,
    metadata: dict[str, Any],
    reporter: Any,
) -> list[Path]:
    """Write the chosen formats into a directory and return what was written."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in resolve(names):
        fmt = FORMATS[name]
        path = target / fmt.extension
        fmt.writer(path, findings, certificates, engine, metadata, reporter)
        written.append(path)
    return written
