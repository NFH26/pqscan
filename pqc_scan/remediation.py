"""Turn findings into what to actually do about them.

A score tells someone how bad it is. An action tells them what to change. The advice lives in
the rule profile next to the classifications, so it stays with the control it came from and can
be edited without touching code.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pqc_scan.models import HostFinding
from pqc_scan.parsers import RuleEngine

EFFORT_ORDER = {"config": 0, "certificate": 1, "vendor": 2, "design": 3}


@dataclass
class Action:
    priority: int
    effort: str
    action: str
    why: str
    trigger: str
    hosts: list[str] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple:
        # Most urgent first, then the change that fixes the most hosts, then the easiest.
        return (self.priority, -len(self.hosts), EFFORT_ORDER.get(self.effort, 9))


def endpoint_label(finding: HostFinding) -> str:
    """How an endpoint is named in advice.

    An estate can hold three VPN concentrators and a dozen SSH hosts. "12 hosts need a
    config change" tells the reader nothing they can act on, so every action carries the
    endpoints it applies to, and each one says which service it means.
    """
    if finding.service == "domain" or finding.target.port == 0:
        return f"{finding.target.hostname} (domain)"
    # A STARTTLS port names its upgrade: "starttls:smtp" tells an administrator which
    # daemon's configuration to open, where a bare "tls" does not.
    protocol = finding.target.protocol or ""
    service = protocol if protocol.startswith("starttls:") else finding.service
    return f"{finding.target.hostname}:{finding.target.port} ({service})"


def _match(name: str, table: dict) -> dict | None:
    """Longest key first, so NOT_APPROVED_AFTER_2030 never falls through to NOT_APPROVED."""
    for key in sorted(table, key=len, reverse=True):
        if name.startswith(key):
            return table[key]
    return None


def actions_for(finding: HostFinding, engine: RuleEngine) -> list[Action]:
    """The actions this one endpoint needs, most urgent first."""
    rules = engine.rules.get("remediation", {})
    finding_table = rules.get("findings", {})
    readiness_table = rules.get("readiness", {})
    host = endpoint_label(finding)

    actions: list[Action] = []
    seen: set[str] = set()

    if finding.not_testable_reason:
        return actions

    readiness = readiness_table.get(finding.pq_readiness)
    if readiness:
        actions.append(Action(
            priority=readiness.get("priority", 3), effort=readiness.get("effort", "design"),
            action=readiness["action"], why=readiness.get("why", ""),
            trigger=finding.pq_readiness, hosts=[host],
        ))

    for name in finding.rule_findings:
        entry = _match(name, finding_table)
        if not entry or entry["action"] in seen:
            continue
        seen.add(entry["action"])
        actions.append(Action(
            priority=entry.get("priority", 3), effort=entry.get("effort", "config"),
            action=entry["action"], why=entry.get("why", ""), trigger=name, hosts=[host],
        ))

    return sorted(actions, key=lambda item: item.sort_key)


def consolidate(findings: list[HostFinding], engine: RuleEngine) -> list[Action]:
    """The same advice grouped across the estate.

    One configuration change usually fixes many endpoints, so the useful order is by how many
    hosts an action clears, not by walking the host list.
    """
    merged: dict[str, Action] = {}
    for finding in findings:
        for action in actions_for(finding, engine):
            existing = merged.get(action.action)
            if existing:
                existing.hosts.extend(action.hosts)
            else:
                merged[action.action] = action
    for action in merged.values():
        action.hosts = sorted(set(action.hosts))
    return sorted(merged.values(), key=lambda item: item.sort_key)
