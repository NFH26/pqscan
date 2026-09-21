import csv
import re
from typing import ClassVar

from jinja2 import Template
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pqc_scan.models import CertificateData, HostFinding
from pqc_scan.remediation import actions_for, consolidate, endpoint_label
from pqc_scan.report_template import REPORT_TEMPLATE


def _dedupe(items: list[str]) -> list[str]:
    """Order-preserving deduplication.

    A validation failure is copied into rule_findings by the scan loop, so without this
    no_tls_offered was printed twice on the same row.
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _anchor(finding: HostFinding) -> str:
    """A stable HTML id for one endpoint, so advice can link to its evidence."""
    raw = f"{finding.target.hostname}-{finding.target.port}-{finding.service}"
    return "ep-" + re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")


class Reporter:
    def __init__(self, findings: list[HostFinding], certs: dict[str, CertificateData], profile_name: str, explain: bool = False, metadata: dict | None = None, wide: bool = False, engine=None):
        self.findings = findings
        self.certs = certs
        self.profile_name = profile_name
        self.explain = explain
        self.metadata = metadata or {}
        self.wide = wide
        # Optional: without it the reports still render, just without advice.
        self.engine = engine

    # Presentation constants. Readiness and score bands are shown as short coloured tokens
    # because the full enum names are what pushed the table past the terminal width.
    READINESS_STYLE: ClassVar = {
        "pure_pq_approved": ("PQ", "bold green"),
        "hybrid_transitional": ("HYBRID", "yellow"),
        "classical_only": ("CLASSICAL", "red"),
        "unknown": ("UNKNOWN", "dim"),
    }
    # Worst first: the host needing attention is the first thing read.
    READINESS_ORDER: ClassVar = ("classical_only", "hybrid_transitional", "pure_pq_approved", "unknown")

    @staticmethod
    def _short_finding(name: str) -> str:
        """Table labels only. The control reference and the informational marker are kept in
        --explain and in every file report; in the table they crowd out the finding itself."""
        return (
            name.split(" (ISM-")[0]
            .replace(" (informational)", "")
            .replace("capability_exceeds_default_negotiation", "stronger group available")
            .replace("tls_version_not_approved", "TLS not 1.3")
            .replace("symmetric_not_approved_after_2030", "AES-128")
            .replace("key_size_below_preferred", "key < preferred")
            .replace("curve_below_preferred", "curve < preferred")
            .replace("incomplete_chain_or_unknown_issuer", "unknown issuer")
        )

    @staticmethod
    def _score_cell(score: int | None) -> str:
        if score is None:
            return "[dim]n/a[/dim]"
        if score <= 25:
            style = "green"
        elif score <= 50:
            style = "yellow"
        elif score <= 75:
            style = "dark_orange"
        else:
            style = "bold red"
        return f"[{style}]{score}[/{style}]"

    # Colour by band, so the column reads at a glance before anyone parses the words.
    BAND_STYLE: ClassVar = {
        5: "bold green", 4: "green", 3: "yellow", 2: "dark_orange", 1: "red", 0: "bold red",
    }

    def _status_cell(self, finding: HostFinding, fallback_style: str, fallback_label: str) -> str:
        """One cell carrying both the band and what it means."""
        if finding.readiness_band is None:
            return f"[{fallback_style}]{fallback_label}[/{fallback_style}]"
        style = self.BAND_STYLE.get(finding.readiness_band, "white")
        return f"[{style}]{finding.readiness_band} {finding.readiness_band_name}[/{style}]"

    def _summary_panel(self, stats: dict) -> Panel:
        grid = Table.grid(padding=(0, 3))
        grid.add_column(justify="right", style="dim")
        grid.add_column(justify="left")
        grid.add_column(justify="right", style="dim")
        grid.add_column(justify="left")
        for left, right in stats["tiles"]:
            grid.add_row(left[0], left[1], right[0] if right else "", right[1] if right else "")
        return Panel(grid, title=f"[bold]PQC Readiness[/bold]  [dim]profile {self.profile_name}[/dim]",
                     border_style="blue", padding=(1, 2))

    def write_terminal(self) -> None:
        # Auto-detect the terminal width. A hardcoded width is what made the borders interleave
        # with wrapped text on narrower terminals.
        console = Console()
        width = console.width
        measured = [f for f in self.findings if f.confidentiality_score is not None or f.authentication_score is not None]
        # Determinable means "we reached a readiness verdict", not "we read a group name".
        # A TLS 1.2 host has no key exchange group we can name and is still definitively
        # classical, so counting group names understated how much the scan actually resolved.
        determinable_groups = sum(f.pq_readiness != "unknown" for f in self.findings)
        conf_scores = [f.confidentiality_score for f in measured if f.confidentiality_score is not None]
        auth_scores = [f.authentication_score for f in measured if f.authentication_score is not None]
        conf_ready = sum(score == 0 for score in conf_scores)
        auth_ready = sum(score == 0 for score in auth_scores)
        readiness_counts = {
            readiness: sum(f.pq_readiness == readiness for f in self.findings)
            for readiness in self.READINESS_ORDER
        }
        certificate_hosts = [f for f in self.findings if f.certificate_fingerprints]
        classical_hosts = sum(
            all(
                (self.certs.get(fingerprint) is not None)
                and self.certs[fingerprint].pub_key_algo.upper() not in {"ML-DSA", "SLH-DSA"}
                for fingerprint in finding.certificate_fingerprints
            )
            for finding in certificate_hosts
        )

        def distribution(scores: list[int]) -> str:
            buckets = [0, 0, 0, 0]
            for score in scores:
                buckets[0 if score <= 25 else 1 if score <= 50 else 2 if score <= 75 else 3] += 1
            return "  ".join(
                f"[{style}]{label} {count}[/{style}]"
                for (label, count), style in zip(
                    zip(("0-25", "26-50", "51-75", "76-100"), buckets, strict=False),
                    ("green", "yellow", "dark_orange", "bold red"), strict=False,
                )
            )

        def percentage(part: int, whole: int) -> str:
            return f"{part / whole * 100:.1f}%" if whole else "n/a"

        average_conf = f"{sum(conf_scores) / len(conf_scores):.1f}" if conf_scores else "n/a"
        average_auth = f"{sum(auth_scores) / len(auth_scores):.1f}" if auth_scores else "n/a"
        readiness_summary = "  ".join(
            f"[{self.READINESS_STYLE[name][1]}]{self.READINESS_STYLE[name][0]} {count}[/{self.READINESS_STYLE[name][1]}]"
            for name, count in readiness_counts.items() if count
        ) or "[dim]none[/dim]"

        # The summary says only what is true at the scale you scanned. A distribution, an
        # average and a "100.0% determinable" are statements about a population; printed over
        # one host they repeat the row below them in a way that reads as noise, and noise in a
        # compliance tool trains people to skim past the part that matters.
        total = len(self.findings)
        unmeasured = total - determinable_groups
        tiles: list[tuple[tuple[str, str], tuple[str, str] | None]] = [
            (("Hosts scanned", str(total)), ("PQ readiness", readiness_summary)),
        ]
        if total >= 10:
            tiles += [
                (("Conf ready", percentage(conf_ready, len(conf_scores))),
                 ("Conf spread", distribution(conf_scores))),
                (("Auth ready", percentage(auth_ready, len(auth_scores))),
                 ("Auth spread", distribution(auth_scores))),
                (("Avg conf/auth", f"{average_conf} / {average_auth}"),
                 ("Classical certs", f"{classical_hosts} of {len(certificate_hosts)}")),
            ]
        elif total > 1:
            tiles.append(
                (("Avg conf/auth", f"{average_conf} / {average_auth}"),
                 ("Classical certs", f"{classical_hosts} of {len(certificate_hosts)}"))
            )
        # Only worth a line when something actually went unmeasured. "100% determinable" is
        # not news; "3 not measured" is.
        if unmeasured:
            tiles.append((("Not measured", f"[yellow]{unmeasured} of {total}[/yellow]"), None))
        # Provenance, so a verdict is attributable to the endpoint rather than to the scanner.
        tiles.append(
            (("Profile", f"{self.profile_name} [dim]{self.metadata.get('rules_version', '')}[/dim]"),
             ("OpenSSL", str(self.metadata.get("openssl_version", "not recorded"))))
        )
        if self.metadata.get("scope_file"):
            tiles.append((("Scope file", str(self.metadata.get("scope_file"))), None))

        self._summary_stats = {"tiles": tiles}
        console.print(self._summary_panel(self._summary_stats))

        # Narrow terminals drop the optional columns rather than wrapping into unreadable rows.
        compact = width < 100 and not self.wide
        table = Table(
            box=box.SIMPLE_HEAVY, header_style="bold", expand=True, pad_edge=False, padding=(0, 1),
        )
        table.add_column("Host", no_wrap=True, overflow="ellipsis", max_width=28, min_width=14)
        if not compact:
            table.add_column("Version", no_wrap=True, min_width=7)
        table.add_column("Key exchange", no_wrap=True, overflow="ellipsis", max_width=34, min_width=14)
        # One column, not two. The band subsumes readiness - 4 and 5 ARE post-quantum, 3 is
        # classical-but-capable, 2 and 1 are classical, 0 is broken - so printing both said
        # the same thing twice and made the reader check which one to trust.
        table.add_column("Status", no_wrap=True, min_width=17)
        table.add_column("Conf risk", justify="right", no_wrap=True, min_width=9)
        table.add_column("Auth risk", justify="right", no_wrap=True, min_width=9)
        if self.wide:
            table.add_column("Chain", no_wrap=True, overflow="ellipsis", max_width=24)
            table.add_column("Probe", no_wrap=True)
        if not compact:
            table.add_column("Findings", no_wrap=True, overflow="ellipsis", ratio=1, min_width=12)

        def sort_key(finding: HostFinding):
            readiness = finding.pq_readiness if finding.pq_readiness in self.READINESS_ORDER else "unknown"
            return (self.READINESS_ORDER.index(readiness), -(finding.confidentiality_score or -1))

        ordered = sorted(self.findings, key=sort_key)
        previous_readiness = None
        for finding in ordered:
            readiness = finding.pq_readiness if finding.pq_readiness in self.READINESS_ORDER else "unknown"
            if previous_readiness is not None and readiness != previous_readiness:
                table.add_section()
            previous_readiness = readiness

            tls = finding.version or finding.tls_version or (finding.max_supported_tls if finding.obsolete_tls_only else None) or "n/a"
            group = "obsolete TLS" if finding.obsolete_tls_only else finding.negotiated_group
            # Capability is shown inline rather than as its own column: what an endpoint COULD
            # do only matters where it differs from what it actually negotiates.
            if finding.capability_exceeds_default and finding.best_supported_group:
                group = f"{group} [dim](can: {finding.best_supported_group})[/dim]"
            # Deduplicated, preserving order: a validation failure is copied into
            # rule_findings by the scan loop, so no_tls_offered was printed twice.
            items = _dedupe(finding.rule_findings or finding.validation_failures)
            if finding.obsolete_tls_only and not any("obsolete_tls" in item for item in items):
                items.append(f"obsolete_tls ({finding.max_supported_tls})")
            labels: list[str] = []
            for item in items:
                label = self._short_finding(item)
                if label not in labels:
                    labels.append(label)
            shown = ", ".join(labels[:2]) + (f" [dim]+{len(labels) - 2}[/dim]" if len(labels) > 2 else "")
            label, style = self.READINESS_STYLE[readiness]

            row = [f"{finding.target.hostname}:{finding.target.port}"]
            if not compact:
                row.append(tls)
            row.extend([
                group,
                self._status_cell(finding, style, label),
                self._score_cell(finding.confidentiality_score),
                self._score_cell(finding.authentication_score),
            ])
            if self.wide:
                row.append(finding.chain_classification.value if finding.chain_classification else "[dim]none[/dim]")
                row.append(finding.probe_method or "[dim]n/a[/dim]")
            if not compact:
                row.append(shown or "[dim]none[/dim]")
            table.add_row(*row)

        console.print(table)
        console.print(
            "[dim]Status:[/dim] [bold green]5[/bold green] pure post-quantum, ASD-approved beyond 2030  "
            "[green]4[/green] post-quantum in use  [yellow]3[/yellow] supports it but does not use it  "
            "[dark_orange]2[/dark_orange] sound classical  [red]1[/red] dated  "
            "[bold red]0[/bold red] unprotected  [dim]UNKNOWN not measured[/dim]"
            "\n[dim]Risk 0 = already meets the profile, 100 = worst. Lower is better.[/dim]"
        )
        if compact:
            console.print("[dim]Narrow terminal: columns hidden. Use --wide or a wider window.[/dim]")

        if self.engine is not None:
            actions = consolidate(self.findings, self.engine)[:5]
            if actions:
                console.print()
                # A recommendation without the endpoint it applies to is not actionable:
                # an estate can hold several VPNs and a dozen SSH hosts, and "12 hosts" does
                # not tell anyone which box to log into. Every row names its endpoints, and
                # each endpoint names its service.
                action_table = Table(
                    box=box.SIMPLE, header_style="bold", title_justify="left",
                    title="[bold]Recommendations[/bold]",
                    expand=True, pad_edge=False,
                )
                action_table.add_column("#", justify="right", no_wrap=True, min_width=2)
                action_table.add_column("Effort", no_wrap=True, min_width=11)
                action_table.add_column("Do this", overflow="ellipsis", no_wrap=True, ratio=2)
                action_table.add_column("Applies to", overflow="ellipsis", no_wrap=True, ratio=1)
                for index, action in enumerate(actions, start=1):
                    style = "bold red" if action.priority == 1 else "yellow" if action.priority <= 3 else "dim"
                    endpoints = action.hosts[:2]
                    extra = len(action.hosts) - len(endpoints)
                    applies = ", ".join(endpoints) + (f" +{extra} more" if extra > 0 else "")
                    action_table.add_row(
                        str(index), action.effort, f"[{style}]{action.action}[/{style}]", applies,
                    )
                console.print(action_table)
                console.print(
                    "[dim]Every affected endpoint, per recommendation, is in the HTML report (-o DIR).[/dim]"
                )

        # Errors live below the table. Inline, a single long error exploded the row height and
        # made the borders interleave with wrapped text.
        issues = [f for f in self.findings if f.handshake_errors]
        if issues:
            console.print()
            issue_table = Table(box=box.SIMPLE, header_style="bold", title_justify="left",
                                title="[bold]Issues[/bold]")
            issue_table.add_column("Host", no_wrap=True, overflow="ellipsis", max_width=34)
            issue_table.add_column("Detail", overflow="fold")
            for finding in issues:
                issue_table.add_row(
                    f"{finding.target.hostname}:{finding.target.port}",
                    "\n".join(finding.handshake_errors),
                )
            console.print(issue_table)

        if self.explain:
            console.print("\n[bold]Score Explanations[/bold]")
            for finding in self.findings:
                console.print(Panel(
                    f"[bold]{finding.target.hostname}:{finding.target.port}[/bold]\n"
                    f"Confidentiality:\n{finding.confidentiality_explanation or 'n/a'}\n\n"
                    f"Authentication:\n{finding.authentication_explanation or 'n/a'}",
                    title="Host Details",
                ))


    def write_csv(self, filepath: str) -> None:
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Version", "Group", "PQ State", "Findings", "Conf Score", "Auth Score", "Chain Class", "Errors"])
            for f_obj in self.findings:
                tls_v = f_obj.tls_version or (f_obj.max_supported_tls if f_obj.obsolete_tls_only else "None")
                grp = f_obj.negotiated_group if not f_obj.obsolete_tls_only else "Obsolete TLS"
                finding_items = list(f_obj.validation_failures)
                if f_obj.obsolete_tls_only:
                    finding_items.append(f"obsolete_tls ({f_obj.max_supported_tls})")
                cc = f"{f_obj.chain_classification.value} ({f_obj.chain_classification_reason})" if f_obj.chain_classification else "None"
                writer.writerow([
                    f"{f_obj.target.hostname}:{f_obj.target.port}",
                    tls_v, grp, f_obj.pq_status,
                    ", ".join(finding_items) or "None",
                    f_obj.confidentiality_score, f_obj.authentication_score,
                    cc, "; ".join(f_obj.handshake_errors) or "None"
                ])

    # Status palette. Reserved for state, never reused as a series colour, and always
    # rendered beside a text label so meaning never rests on hue alone.
    STATUS: ClassVar = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a",
                        "critical": "#d03b3b", "muted": "#898781"}
    READINESS_HTML: ClassVar = {
        "pure_pq_approved": ("Post-quantum", "good"),
        "hybrid_transitional": ("Hybrid (transitional)", "warning"),
        "classical_only": ("Classical only", "critical"),
        "unknown": ("Not determined", "muted"),
    }

    @classmethod
    def _band_color(cls, score):
        if score is None:
            return cls.STATUS["muted"]
        if score <= 25:
            return cls.STATUS["good"]
        if score <= 50:
            return cls.STATUS["warning"]
        if score <= 75:
            return cls.STATUS["serious"]
        return cls.STATUS["critical"]

    def _html_context(self) -> dict:
        total = len(self.findings)
        conf = [f.confidentiality_score for f in self.findings if f.confidentiality_score is not None]
        auth = [f.authentication_score for f in self.findings if f.authentication_score is not None]

        readiness_rows = []
        for key, (label, status) in self.READINESS_HTML.items():
            count = sum(f.pq_readiness == key for f in self.findings)
            readiness_rows.append({
                "key": key, "label": label, "color": self.STATUS[status], "count": count,
                "pct": round(count / total * 100) if total else 0,
            })

        def buckets(scores):
            edges = [(0, 25, "0-25", "good"), (26, 50, "26-50", "warning"),
                     (51, 75, "51-75", "serious"), (76, 100, "76-100", "critical")]
            widest = 0
            out = []
            for low, high, label, status in edges:
                count = sum(low <= score <= high for score in scores)
                widest = max(widest, count)
                out.append({"label": label, "count": count, "color": self.STATUS[status]})
            for bucket in out:
                bucket["pct"] = round(bucket["count"] / widest * 100) if widest else 0
            return out

        distributions = [
            {"title": "Confidentiality risk", "buckets": buckets(conf), "measured": len(conf),
             "average": f"{sum(conf) / len(conf):.1f}" if conf else "n/a"},
            {"title": "Authentication risk", "buckets": buckets(auth), "measured": len(auth),
             "average": f"{sum(auth) / len(auth):.1f}" if auth else "n/a"},
        ]

        order = {key: index for index, key in enumerate(self.READINESS_ORDER)}
        ordered = sorted(
            self.findings,
            key=lambda f: (order.get(f.pq_readiness, 9), -(f.confidentiality_score or -1)),
        )
        rows = []
        for finding in ordered:
            key = finding.pq_readiness if finding.pq_readiness in self.READINESS_HTML else "unknown"
            label, status = self.READINESS_HTML[key]
            # Deduplicated, preserving order: a validation failure is copied into
            # rule_findings by the scan loop, so no_tls_offered was printed twice.
            items = _dedupe(finding.rule_findings or finding.validation_failures)
            if finding.obsolete_tls_only and not any("obsolete_tls" in item for item in items):
                items.append(f"obsolete_tls ({finding.max_supported_tls})")
            rows.append({
                "host": f"{finding.target.hostname}:{finding.target.port}",
                "service": finding.service,
                "anchor": _anchor(finding),
                "tls": finding.version or finding.tls_version or (finding.max_supported_tls if finding.obsolete_tls_only else "n/a"),
                "group": "obsolete TLS" if finding.obsolete_tls_only else finding.negotiated_group,
                "capability": finding.best_supported_group if finding.capability_exceeds_default else None,
                "readiness_key": key, "readiness_label": label, "readiness_color": self.STATUS[status],
                "conf": finding.confidentiality_score if finding.confidentiality_score is not None else "n/a",
                "auth": finding.authentication_score if finding.authentication_score is not None else "n/a",
                "conf_color": self._band_color(finding.confidentiality_score),
                "auth_color": self._band_color(finding.authentication_score),
                "findings": items,
                "conf_explanation": finding.confidentiality_explanation,
                "auth_explanation": finding.authentication_explanation,
                "actions": [
                    {"effort": item.effort, "action": item.action, "why": item.why}
                    for item in (actions_for(finding, self.engine) if self.engine else [])
                ],
            })

        issues = [
            {"host": f"{f.target.hostname}:{f.target.port}", "detail": "; ".join(f.handshake_errors)}
            for f in self.findings if f.handshake_errors
        ]
        anchor_by_label = {endpoint_label(f): _anchor(f) for f in self.findings}
        offered = sorted({group for f in self.findings for group in (f.pq_groups_offered or [])})
        return {
            "profile_name": self.profile_name,
            "rules_version": self.metadata.get("rules_version"),
            "meta": {
                "operator": self.metadata.get("operator"),
                "engagement": self.metadata.get("engagement"),
                "scan_time": self.metadata.get("scan_time"),
                "tool_version": self.metadata.get("tool_version"),
                "authorised": self.metadata.get("authorised", "unknown"),
                "scope_file": self.metadata.get("scope_file"),
                "probe_method": self.metadata.get("probe_method", "native"),
                "openssl_version": self.metadata.get("openssl_version"),
                "groups_offered": offered,
            },
            "summary": {
                "total": total,
                "conf_measured": len(conf),
                "auth_measured": len(auth),
                "readiness": {row["key"]: row["count"] for row in readiness_rows},
                "readiness_rows": readiness_rows,
                "distributions": distributions,
            },
            "rows": rows,
            "issues": issues,
            "actions": [
                {
                    "priority": action.priority, "effort": action.effort, "action": action.action,
                    "priority_color": self.STATUS["critical"] if action.priority == 1
                    else self.STATUS["warning"] if action.priority <= 3 else self.STATUS["muted"],
                    "why": action.why,
                    # Each affected endpoint links to its own row, so a reader can go from
                    # "do this" to the evidence for the exact service it applies to.
                    "hosts": [
                        {"label": label, "anchor": anchor_by_label.get(label)}
                        for label in action.hosts
                    ],
                }
                for action in (consolidate(self.findings, self.engine) if self.engine else [])
            ],
            "certs": sorted(self.certs.values(), key=lambda c: (c.subject_cn or "").lower()),
        }

    def write_html(self, filepath: str) -> None:
        with open(filepath, "w") as handle:
            handle.write(Template(REPORT_TEMPLATE, autoescape=True).render(**self._html_context()))

