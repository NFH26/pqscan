import asyncio
import csv
import datetime
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import typer
import yaml
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pqc_scan.cbom import build_cbom, write_cbom
from pqc_scan.checks import run_offline_checks
from pqc_scan.collectors import RateLimiter
from pqc_scan.discovery import candidate_ports, discover
from pqc_scan.exporters import FORMATS, export, run_directory
from pqc_scan.models import CertificateData, HostFinding, Target
from pqc_scan.parsers import RuleEngine
from pqc_scan.probes import ProbeContext, run_probe
from pqc_scan.reporters import Reporter
from pqc_scan.scoring import Scorer
from pqc_scan.selftest import FAIL, PASS, UNREACHABLE, load_cases, run_cases_with_findings
from pqc_scan.verify import independent_scores, load_scan, openssl_version, verify_hosts

app = typer.Typer(help="ASD PQC Readiness Scanner (LATICE - Locate Phase)")
console = Console()
def _tool_version() -> str:
    """The installed package version, so it cannot drift from pyproject.toml.

    It was hardcoded, and within one release it disagreed with the packaged version - which
    is a support problem forever, because every report carries this number.
    """
    try:
        from importlib.metadata import version

        return version("pqc-scan")
    except Exception:
        return "unknown (not installed as a package)"


TOOL_VERSION = _tool_version()


def _parse_target_spec(value: str, port_map: dict[int, str]) -> Target:
    value = value.strip()
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise ValueError("IPv6 target is missing closing bracket")
        hostname = value[1:closing]
        port_text = value[closing + 1:]
        port = int(port_text[1:]) if port_text.startswith(":") and port_text[1:] else 443
    elif value.count(":") == 1:
        hostname, port_text = value.rsplit(":", 1)
        port = int(port_text) if port_text else 443
    else:
        hostname, port = value, 443
    if not hostname:
        raise ValueError("target hostname is empty")
    return Target(hostname=hostname, port=port, protocol=port_map.get(port, "tls"), criticality="medium")


def openssl_status() -> tuple[str, tuple[int, int] | None]:
    """Report the local OpenSSL, without deciding anything about it."""
    try:
        proc = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=True)
        text = proc.stdout.strip()
        match = re.search(r"OpenSSL\s+(\d+)\.(\d+)", text)
        return text, ((int(match.group(1)), int(match.group(2))) if match else None)
    except Exception as error:
        return f"not found ({error})", None


def check_openssl_version(fatal: bool = True):
    """OpenSSL is OPTIONAL for scanning.

    Group detection is done by our own ClientHello (pqc_scan.tls_probe), so a scan runs on a
    machine with an old OpenSSL or none at all. Only `pqc verify`, which cross-checks results
    against the openssl binary, needs 3.5 or newer.
    """
    text, version = openssl_status()
    if version is None or version < (3, 5):
        console.print(
            f"[dim]OpenSSL 3.5+ not available ({text.split('(')[0].strip()}); "
            "scanning is unaffected, `pqc verify` is unavailable.[/dim]"
        )
        if fatal:
            sys.exit(3)


def _policy_failures(
    findings: list[HostFinding],
    fail_on_score: int | None,
    fail_on_class: str | None,
    require_hybrid_kex: bool,
) -> list[str]:
    failures = []
    for finding in findings:
        target_name = f"{finding.target.hostname}:{finding.target.port}"
        if fail_on_score is not None and any(
            score is not None and score > fail_on_score
            for score in (finding.confidentiality_score, finding.authentication_score)
        ):
            failures.append(f"{target_name}: score exceeds {fail_on_score}")
        if fail_on_class and finding.chain_classification and finding.chain_classification.value == fail_on_class:
            failures.append(f"{target_name}: class is {fail_on_class}")
        # Domain findings carry no key exchange at all, so a hybrid-KEX gate cannot apply to
        # them. It used to fire on every one, failing any CI pipeline with a domain row.
        if (
            require_hybrid_kex
            and finding.service != "domain"
            and finding.not_testable_reason is None
            and finding.pq_status != "supported"
        ):
            failures.append(f"{target_name}: hybrid KEX is not supported")
    return failures

def _write_parents(path: str) -> None:
    """Create the directory for an output file so --json reports/x.json just works."""
    parent = Path(path).parent
    if str(parent) not in ("", "."):
        os.makedirs(parent, exist_ok=True)


def _openssl_version() -> str:
    """Local OpenSSL, for the report header. Scanning does not need it; `pqc verify` does."""
    import subprocess

    try:
        text = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, check=False, timeout=5
        ).stdout.strip()
        # OpenSSL repeats itself when the binary and the library report separately:
        # "OpenSSL 3.6.4 ... (Library: OpenSSL 3.6.4 ...)". Keep the first half unless they
        # actually differ, which is the only case where the second half tells you anything.
        if "(Library: " in text:
            binary, _, library = text.partition("(Library: ")
            if binary.strip() == library.rstrip(") ").strip():
                text = binary.strip()
        return text or "not found"
    except Exception:
        return "not found"


@app.command()
def doctor():
    """Report what this installation can do."""
    console.print("[bold]pqc-scan preflight[/bold]")
    console.print(f"  Python                 {sys.version.split()[0]}  [green]ok[/green]")
    try:
        engine = RuleEngine()
    except Exception as error:
        console.print(f"  Rule profile           [bold red]failed to load: {error}[/bold red]")
        raise typer.Exit(4) from error
    profile = engine.rules.get("profile", {})
    console.print(
        f"  Rule profile           {engine.profile_name}"
        f" (rules {profile.get('rules_version', 'unversioned')},"
        f" reviewed {profile.get('last_reviewed', 'unknown')})  [green]ok[/green]"
    )
    console.print("  TLS group probe        native, no OpenSSL required  [green]ok[/green]")
    text, version = openssl_status()
    if version and version >= (3, 5):
        console.print(f"  OpenSSL (verify only)  {text}  [green]ok[/green]")
    else:
        console.print(f"  OpenSSL (verify only)  {text}")
        console.print("                         [yellow]scanning works; `pqc verify` is unavailable[/yellow]")
    console.print("\n[dim]Scores are risk: 0 means the endpoint already meets the profile, 100 is worst.[/dim]")


@app.command()
def scan(
    target: str = typer.Argument(None, help="Single host to scan (e.g. example.com.au)"),
    input_file: str = typer.Option(None, "--input", help="CSV or text file of hosts"),
    protocol: str = typer.Option(
        None, "--protocol", "-p",
        help="Force the protocol for the target: tls, ssh, ipsec, domain, or starttls:smtp",
    ),
    discover_services: bool = typer.Option(
        False, "--discover",
        help="Find which services each host is running, then measure every one",
    ),
    operator: str = typer.Option(None, "--operator", help="Who ran the scan (defaults to the OS user)"),
    engagement: str = typer.Option(None, "--engagement", help="Engagement or ticket reference (defaults to a dated one)"),
    profile: str = typer.Option("asd_ism", "--profile", help="Rule profile to load"),
    concurrency: int = 20,
    timeout: float = 10.0,
    rate_limit: float = typer.Option(10.0, "--rate-limit", help="Maximum scan requests per second"),
    no_pq_probe: bool = False,
    verbose: bool = typer.Option(False, "--verbose", help="Print full exception traces for failures"),
    explain: bool = typer.Option(False, "--explain", help="Print detailed score breakdowns"),
    wide: bool = typer.Option(False, "--wide", help="Show every column, for wide terminals"),
    deep: bool = typer.Option(False, "--deep", help="Also test which cipher suites each host ACCEPTS, not just prefers"),
    fail_on_score: int | None = typer.Option(None, "--fail-on-score", help="Exit 1 when either score exceeds N"),
    fail_on_class: str | None = typer.Option(None, "--fail-on-class", help="Exit 1 when a chain has this class"),
    require_hybrid_kex: bool = typer.Option(False, "--require-hybrid-kex", help="Exit 1 when hybrid KEX is not supported"),
    cache_dir: str = typer.Option(".pqc_cache", "--cache-dir", help="Directory for scan cache"),
    scope_file: str | None = typer.Option(None, "--scope-file", help="Allowed hostnames or domain suffixes"),
    confirm_authorised: bool = typer.Option(False, "--confirm-authorised", "-y", help="I confirm I am authorised to scan every target"),
    out_dir: str = typer.Option(None, "--out", "-o", help="Directory to write reports into"),
    flat: bool = typer.Option(
        False, "--flat", help="Write straight into --out instead of a dated subfolder per run"
    ),
    formats: str = typer.Option(
        None, "--format", "-f",
        help="Which formats to write: all (default), or a comma-separated subset of "
             "html, csv, json, cbom, sarif, md",
    ),
    report_dir: str = typer.Option(None, "--report", hidden=True, help="Deprecated alias for --out"),
    json_out: str = typer.Option(None, "--json", hidden=True, help="Deprecated: use --out with --format json"),
    cbom_out: str = typer.Option(None, "--cbom", hidden=True, help="Deprecated: use --out with --format cbom")
):
    """Scan endpoints for post-quantum readiness. Protocol is chosen by port, or by the
    protocol column in a CSV: TLS, STARTTLS and SSH are supported."""
    operator = operator or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    # UTC, so a scan run at 23:00 Brisbane and one at 09:00 UTC the next day do not land in
    # the same engagement by accident.
    engagement = engagement or (
        f"ad-hoc-{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d')}"
    )
    if not confirm_authorised:
        console.print("[bold red]Error: You must provide --confirm-authorised to scan these targets.[/bold red]")
        sys.exit(1)
    try:
        check_openssl_version(fatal=False)
    except TypeError:
        # Direct Python callers from tests may monkeypatch the legacy no-argument hook.
        check_openssl_version()
    if not isinstance(fail_on_score, int):
        fail_on_score = None
    if not isinstance(fail_on_class, str):
        fail_on_class = None
    if not isinstance(require_hybrid_kex, bool):
        require_hybrid_kex = False
    if not isinstance(scope_file, str):
        scope_file = None
    scan_time = datetime.datetime.now(datetime.UTC).isoformat()
    # Never let a missing openssl binary stop a scan. Scanning does not use it - only the
    # report header and `pqc verify` do - and an unguarded subprocess call here crashed the
    # tool outright on exactly the machine the README promises it runs on.
    openssl_runtime_version = _openssl_version()
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    targets = []

    with (Path(__file__).resolve().parent / "rules" / "port_map.yaml").open() as f:
        port_map = yaml.safe_load(f)["ports"]

    if target:
        try:
            targets.append(_parse_target_spec(target, port_map))
        except Exception as e:
            console.print(f"[bold red]Target Parse Error for target '{target}': {e}[/bold red]")
            sys.exit(2)
    elif input_file:
        with open(input_file) as f:
            if input_file.endswith(".csv"):
                reader = csv.DictReader(line for line in f if not line.lstrip().startswith("#"))
                for row_idx, row in enumerate(reader, start=2):
                    p = int((row.get("port") or "443").strip())
                    try:
                        t = Target(
                            hostname=row["hostname"],
                            port=p,
                            protocol=row.get("protocol") or port_map.get(p, "tls"),
                            owner=row.get("owner", "Unknown"),
                            system_name=row.get("system_name", "Unknown"),
                            criticality=cast(Any, row.get("criticality", "medium")),
                            classification=cast(Any, row.get("classification", "OS") or "OS"),
                            data_lifetime_years=int((row.get("data_lifetime_years") or "0").strip())
                        )
                        targets.append(t)
                    except Exception as e:
                        console.print(f"[bold red]CSV Parse Error on row {row_idx} (hostname: {row.get('hostname')}): {e}[/bold red]")
                        sys.exit(2)
            elif input_file.endswith(".txt"):
                for line_idx, line in enumerate(f, start=1):
                    value = line.split("#", 1)[0].strip()
                    if not value:
                        continue
                    try:
                        targets.append(_parse_target_spec(value, port_map))
                    except Exception as e:
                        console.print(f"[bold red]Target Parse Error on line {line_idx}: {e}[/bold red]")
                        sys.exit(2)

    unique_targets = {f"{t.hostname}:{t.port}": t for t in targets}
    targets = list(unique_targets.values())

    scope_entries = []
    skipped_scope = []
    if scope_file:
        with open(scope_file) as scope_handle:
            scope_entries = [line.strip().lower() for line in scope_handle if line.strip() and not line.lstrip().startswith("#")]
        allowed = []
        for candidate in targets:
            hostname = candidate.hostname.lower()
            if any(hostname == entry or hostname.endswith(entry if entry.startswith(".") else "." + entry) for entry in scope_entries):
                allowed.append(candidate)
            else:
                skipped_scope.append(candidate.hostname)
        targets = allowed

    if discover_services and targets:
        # Replace each host with whatever it is actually running. The ports an operator
        # forgets to list are the ones still running TLS 1.0 or an SSH daemon nobody owns,
        # so asking the host beats asking the person.
        console.print(
            f"[dim]Discovering services on {len(targets)} host(s) across "
            f"{len(candidate_ports())} ports the ISM covers ...[/dim]"
        )

        async def _discover_all() -> list[Target]:
            found: list[Target] = []
            for base in targets:
                for service in await discover(base.hostname, timeout=min(timeout, 4.0)):
                    found.append(base.model_copy(update={
                        "port": service.port, "protocol": service.protocol,
                        "system_name": f"{base.system_name} ({service.protocol} on {service.port})"
                        if base.system_name != "Unknown" else f"{service.protocol}:{service.port}",
                    }))
                # A domain's email and web controls have no port, so discovery would never
                # find them, but they are part of the picture for any real domain.
                if "." in base.hostname and not base.hostname.replace(".", "").isdigit():
                    found.append(base.model_copy(update={"port": 0, "protocol": "domain"}))
            return found

        discovered = asyncio.run(_discover_all())
        if not discovered:
            console.print("[bold red]Error: no services found on the given host(s).[/bold red]")
            sys.exit(2)
        console.print(
            "[dim]Found: " + ", ".join(
                f"{t.hostname}:{t.port} {t.protocol}" for t in discovered[:12]
            ) + (f" and {len(discovered) - 12} more" if len(discovered) > 12 else "") + "[/dim]\n"
        )
        targets = discovered

    if protocol and targets:
        # So a single target does not need a CSV. Checking a domain's email controls was
        # "write a two-column CSV to /tmp first", which is a step nobody should have to
        # learn to ask one question.
        targets = [t.model_copy(update={"protocol": protocol}) for t in targets]

    if not targets:
        if skipped_scope:
            # "No targets were provided" is wrong and confusing here: targets WERE provided
            # and the scope file excluded every one. Naming the file and the hosts is the
            # difference between a two-second fix and a puzzled ten minutes.
            console.print(
                f"[bold red]Error: the scope file {scope_file} excluded all "
                f"{len(skipped_scope)} target(s).[/bold red]\n"
                f"[dim]Excluded: {', '.join(skipped_scope[:8])}"
                + (f" and {len(skipped_scope) - 8} more" if len(skipped_scope) > 8 else "")
                + "\nA scope file lists hostnames or domain suffixes you are authorised to "
                "scan, one per line.[/dim]"
            )
        else:
            console.print("[bold red]Error: No targets were provided.[/bold red]")
        sys.exit(2)

    noun = "target" if len(targets) == 1 else "targets"
    console.print(
        f"[bold blue]Scope Notice:[/bold blue] Operator {operator} initiating scan for "
        f"Engagement {engagement} ({len(targets)} {noun})."
    )

    try:
        engine = RuleEngine(profile)
        scorer = Scorer()
    except (OSError, KeyError, ValueError, yaml.YAMLError) as e:
        console.print(f"[bold red]Rule/configuration error: {e}[/bold red]")
        sys.exit(4)

    async def process_batch():
        semaphore = asyncio.Semaphore(concurrency)
        limiter = RateLimiter(rate_limit)
        findings: list[HostFinding] = []
        global_certs: dict[str, CertificateData] = {}
        context = ProbeContext(
            engine=engine, timeout=timeout, verbose=verbose,
            no_pq_probe=no_pq_probe, certificates=global_certs,
            enumerate_ciphers=deep,
        )

        async def work(t: Target):
            async with semaphore, limiter.get_lock(t.hostname):
                await limiter.wait_for_slot()
                await asyncio.sleep(0.05)
                try:
                    # The only protocol-aware line in the scan loop.
                    finding = await run_probe(t, context)
                    scorer.calculate_scores(finding, global_certs, engine)
                    scorer.assign_readiness_band(finding)
                    finding.rule_findings.extend(
                        item for item in finding.validation_failures
                        if item not in finding.rule_findings
                    )
                    # The chain classification is NOT a finding. It already has its own
                    # column and the HTML report gives it with the reason that set it;
                    # appending the bare enum put an unexplained NOT_APPROVED_AFTER_2030
                    # in the Findings column next to readable text.
                except Exception as error:
                    finding = HostFinding(
                        target=t,
                        observations={"hostname": t.hostname, "port": t.port},
                        not_testable_reason=(
                            "dns_failure" if "gaierror" in str(error)
                            else "timeout" if "timed out" in str(error).lower()
                            else "probe_failure"
                        ),
                        handshake_errors=[
                            f"{type(error).__name__}: {str(error) or 'unknown host processing error'}"
                        ],
                    )
                findings.append(finding)
        await asyncio.gather(*(work(t) for t in targets))
        return findings, global_certs

    findings, global_certs = asyncio.run(process_batch())

    os.makedirs(cache_dir, exist_ok=True)
    with open(Path(cache_dir) / "last_run.json", "w") as f:
        json.dump({
            "profile": engine.profile_name,
            "scan_time": scan_time,
            "tool_version": TOOL_VERSION,
            "openssl_version": openssl_runtime_version,
            "operator": operator,
            "engagement": engagement,
            "rules_version": engine.rules.get("profile", {}).get("rules_version"),
            "authorised": confirm_authorised,
            "scope_file": scope_file,
            "scope_skipped": skipped_scope,
            "findings": [json.loads(f.model_dump_json()) for f in findings],
            "certs": {k: json.loads(v.model_dump_json()) for k, v in global_certs.items()}
        }, f)

    report_metadata = {
        "authorised": confirm_authorised,
        "scope_file": scope_file,
        "probe_method": "native",
        "openssl_version": openssl_runtime_version,
        "operator": operator,
        "engagement": engagement,
        "scan_time": scan_time,
        "tool_version": TOOL_VERSION,
        "profile": engine.profile_name,
        "rules_version": engine.rules.get("profile", {}).get("rules_version"),
    }
    reporter = Reporter(
        findings, global_certs, engine.profile_name, explain=explain, wide=wide, engine=engine,
        metadata=report_metadata,
    )
    reporter.write_terminal()

    # One directory, one --format list. The three separate output flags are still accepted so
    # existing commands and scripts keep working, but they are hidden from --help.
    destination = out_dir or report_dir
    chosen = formats
    legacy = [name for name, path in (("json", json_out), ("cbom", cbom_out)) if path]
    if legacy and not destination:
        # The old flags named a FILE; honour that exactly rather than guessing a directory.
        for name, path in (("json", json_out), ("cbom", cbom_out)):
            if not path:
                continue
            _write_parents(path)
            FORMATS[name].writer(
                Path(path), findings, global_certs, engine, report_metadata, reporter
            )
            console.print(f"[green]{name} written to {path}[/green]")
    elif legacy and destination and not chosen:
        chosen = ",".join(legacy + (["html", "csv"] if report_dir else []))

    if destination:
        # A dated subfolder per run by default, so a scan is never overwritten by the next
        # one. A report is evidence; evidence that quietly changed is not evidence.
        folder = str(destination) if flat else str(
            run_directory(destination, engagement, scan_time)
        )
        try:
            written = export(
                folder, chosen, findings, global_certs, engine, report_metadata, reporter
            )
        except ValueError as error:
            console.print(f"[bold red]{error}[/bold red]")
            raise typer.Exit(2) from error
        console.print(
            f"\n[green]Wrote {len(written)} file(s) to {folder}/[/green]  "
            + "[dim]" + ", ".join(p.name for p in written) + "[/dim]"
        )

    if json_out:
        _write_parents(json_out)
        with open(json_out, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "tool_version": TOOL_VERSION,
                    "profile": engine.profile_name,
                    "rules_version": engine.rules.get("profile", {}).get("rules_version"),
                    "scan_time": scan_time,
                    "operator": operator,
                    "engagement": engagement,
                    "findings": [json.loads(f.model_dump_json()) for f in findings],
                    "certificates": {k: json.loads(v.model_dump_json()) for k, v in global_certs.items()},
                },
                handle, indent=2,
            )
        console.print(f"[green]JSON written to {json_out}[/green]")

    if cbom_out:
        _write_parents(cbom_out)
        write_cbom(cbom_out, build_cbom(
            findings, global_certs,
            rules_version=str(engine.rules.get("profile", {}).get("rules_version")),
            operator=operator, engagement=engagement,
        ))
        console.print(f"[green]CBOM written to {cbom_out}[/green]")

    # An endpoint counts as measured if EITHER axis produced a score. ftp.gnu.org has no
    # certificate to judge, so it has no authentication score - but it was measured, and
    # scored 100 for refusing to encrypt. Counting only the authentication axis reported
    # "No endpoints could be measured" directly under a row full of measurements.
    measured_any = sum(
        1 for f in findings
        if f.confidentiality_score is not None or f.authentication_score is not None
    )
    policy_failures = _policy_failures(findings, fail_on_score, fail_on_class, require_hybrid_kex)
    if policy_failures:
        console.print("[bold red]Policy gate failed:[/bold red]")
        for failure in policy_failures:
            console.print(f"  {failure}")
        sys.exit(1)
    if measured_any == 0:
        console.print("[bold red]Error: No endpoints could be measured.[/bold red]")
        sys.exit(1)


@app.command()
def report(
    out_dir: str = typer.Option("./reports", "--out-dir", "--out", help="Output directory"),
    format: str = typer.Option("rich", "--format", help="rich, json, jsonl, cbom, csv, html"),
    explain: bool = typer.Option(False, "--explain", help="Include explanations in reports"),
    wide: bool = typer.Option(False, "--wide", help="Show every column, for wide terminals"),
):
    """Generate reports from the last scan."""
    try:
        with open(".pqc_cache/last_run.json") as f:
            data = json.load(f)
            findings = [HostFinding(**f) for f in data["findings"]]
            certs = {k: CertificateData(**v) for k, v in data["certs"].items()}
            prof = data.get("profile", "Unknown")
    except FileNotFoundError:
        console.print("[bold red]No scan data found. Run `scan` first.[/bold red]")
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "tool_version": data.get("tool_version"),
        "profile": prof,
        "scan_time": data.get("scan_time"),
        "openssl_version": data.get("openssl_version"),
        "probe_method": "native",
        "findings": [json.loads(f.model_dump_json()) for f in findings],
        "certs": {key: json.loads(value.model_dump_json()) for key, value in certs.items()},
    }
    if format == "json":
        with open(Path(out_dir) / "report.json", "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
    elif format == "jsonl":
        with open(Path(out_dir) / "report.jsonl", "w") as handle:
            for finding in payload["findings"]:
                handle.write(json.dumps(finding, sort_keys=True, default=str) + "\n")
            handle.write(json.dumps({"summary": {"count": len(findings), "probe_method": "native"}}, sort_keys=True) + "\n")
    elif format == "cbom":
        components = []
        for finding in findings:
            location = f"{finding.target.hostname}:{finding.target.port}"
            components.append({"type": "cryptographic-asset", "bom-ref": location, "name": finding.negotiated_group, "properties": [{"name": "usage_location", "value": location}, {"name": "quantum_safety", "value": finding.pq_readiness}, {"name": "probe_method", "value": finding.probe_method}]})
        with open(Path(out_dir) / "report.cbom.json", "w") as handle:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}, handle, indent=2, sort_keys=True)
    elif format not in {"rich", "csv", "html"}:
        console.print(f"[bold red]Unsupported report format: {format}[/bold red]")
        raise typer.Exit(code=2)
    reporter = Reporter(
        findings, certs, prof, explain=explain, wide=wide, engine=RuleEngine(prof),
        metadata={
            "authorised": data.get("authorised", "unknown"),
            "scope_file": data.get("scope_file"),
            "probe_method": "native",
            "openssl_version": data.get("openssl_version"),
            "operator": data.get("operator"),
            "engagement": data.get("engagement"),
            "scan_time": data.get("scan_time"),
            "tool_version": data.get("tool_version"),
            "rules_version": data.get("rules_version"),
        },
    )
    reporter.write_html(f"{out_dir}/report.html")
    reporter.write_csv(f"{out_dir}/findings.csv")
    console.print(f"[green]Reports generated in {out_dir}/[/green]")


@app.command()
def verify(
    input_file: str = typer.Option("hosts.csv", "--input"),
    scan_file: str = typer.Option(".pqc_cache/last_run.json", "--scan"),
    host: str | None = typer.Option(None, "--host"),
    pq: bool = typer.Option(False, "--pq"),
    timeout: float = typer.Option(15.0, "--timeout"),
    csv_out: str | None = typer.Option(None, "--csv-out"),
    run_scan: bool = typer.Option(False, "--run-scan"),
    scores: bool = typer.Option(False, "--scores"),
):
    """Compare scanner observations with independent OpenSSL observations."""
    if run_scan:
        subprocess.run(
            ["./pqc", "scan", "--input", input_file, "--operator", "verify", "--engagement", "verify", "--confirm-authorised"],
            check=True,
        )
    version_text, version = openssl_version(timeout)
    print(f"Local openssl: {version_text}")
    print(f"CA bundle: {__import__('ssl').get_default_verify_paths().cafile or 'system default'}")
    if pq and (version is None or version < (3, 5)):
        raise typer.Exit(code=3)
    results = verify_hosts(input_file, scan_file, host, timeout, pq)
    scan_entries = load_scan(scan_file) if scores else {}
    differences = 0
    rows = []
    for result in results:
        if scores and result.status != "NOT_TESTABLE" and "validation_failures" not in result.fields and isinstance(result.values.get("openssl"), dict):
            finding, _ = scan_entries.get(result.host, ({}, {}))
            expected_scores = (finding.get("confidentiality_score"), finding.get("authentication_score"))
            actual_scores = independent_scores(result.values.get("openssl", {}), finding.get("target", {}))
            if expected_scores != actual_scores:
                result.status = "DIFF"
                result.fields.append("scores")
                result.values["scan_scores"] = expected_scores
                result.values["openssl_scores"] = actual_scores
        if result.status == "DIFF":
            differences += 1
        print(f"{result.status:14} {result.host:40} {', '.join(result.fields) or result.reason or ''}")
        rows.append({"host": result.host, "status": result.status, "fields": ";".join(result.fields), "reason": result.reason or ""})
    print(f"{len(results)} hosts checked, {differences} with differences.")
    if csv_out and rows:
        with open(csv_out, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    raise typer.Exit(code=1 if differences else 0)

@app.command()
def selftest(
    timeout: float = typer.Option(10.0, "--timeout", help="Seconds per endpoint"),
    report_dir: str = typer.Option("reports/selftest", "--report", help="Where to write the reports"),
    strict: bool = typer.Option(
        False, "--strict", help="Treat unreachable endpoints as failures (CI with open egress)"
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Only the checks that need no network (about a second)"
    ),
) -> None:
    """Scan every protocol against known endpoints and check the answers.

    This is a real scan, not a simulation. It runs the same probes, the same scoring and the
    same reporter as `pqc scan`, over a bundled set of endpoints chosen to exercise every
    protocol and every awkward case - post-quantum TLS and SSH, an SSH server on a TLS port,
    ciphers OpenSSL refuses to negotiate, broken certificates, STARTTLS, a server that will
    not encrypt at all, DNS over TLS, an IKEv2 VPN gateway and domain email controls.

    You get the product's own output first, which is what to show someone who asks what the
    tool does, and then a verdict on whether every one of those results was correct.
    """
    engine = RuleEngine()
    scan_time = datetime.datetime.now(datetime.UTC).isoformat()

    if offline:
        # Rules, scoring invariants and output formats, with no network at all. Useful in a
        # pre-commit hook and on a machine with no egress.
        console.print("[bold]Self-test[/bold]  offline checks only\n")
        offline_only = run_offline_checks()
        table = Table(box=box.SIMPLE, header_style="bold", expand=True, pad_edge=False, show_header=False)
        table.add_column("", no_wrap=True, width=6)
        table.add_column("Check", no_wrap=True, overflow="ellipsis", max_width=46)
        table.add_column("Detail", overflow="fold", ratio=1)
        for item in offline_only:
            table.add_row(
                "[green]ok[/green]" if item.ok else "[bold red]FAIL[/bold red]",
                f"{item.suite}: {item.name}", item.detail or "",
            )
        console.print(table)
        failures = sum(not item.ok for item in offline_only)
        console.print(
            f"\n[bold]{len(offline_only) - failures} correct[/bold]"
            + (f"  [bold red]{failures} wrong[/bold red]" if failures else "")
        )
        raise typer.Exit(1 if failures else 0)

    cases = load_cases()

    console.print(Panel(
        "[bold]Scanning every supported protocol against endpoints with a known answer.[/bold]\n"
        f"[dim]{len(cases)} endpoints. Public reference services; nothing here needs credentials.\n"
        "What follows is the real scan output, then a check of whether each result was right.[/dim]",
        border_style="cyan", padding=(0, 2),
    ))

    results, findings, certificates = asyncio.run(
        run_cases_with_findings(cases, timeout=timeout)
    )

    # The product's own output, for every protocol at once.
    reporter = Reporter(
        findings, certificates, engine.profile_name, wide=True, engine=engine,
        metadata={
            "authorised": True, "scope_file": None, "probe_method": "native",
            "openssl_version": _openssl_version(), "operator": "selftest",
            "engagement": "selftest", "scan_time": scan_time, "tool_version": TOOL_VERSION,
            "rules_version": engine.rules.get("profile", {}).get("rules_version"),
        },
    )
    reporter.write_terminal()

    # Then whether the tool itself is behaving: the rule profile, the scoring invariants and
    # every output format. These need no network and take about a second.
    console.print("\n[bold]Checks[/bold]  [dim]rules, scoring invariants and output formats[/dim]")
    offline_results = run_offline_checks()
    checks = Table(box=box.SIMPLE, header_style="bold", expand=True, pad_edge=False, show_header=False)
    checks.add_column("", no_wrap=True, width=6)
    checks.add_column("Check", no_wrap=True, overflow="ellipsis", max_width=46)
    checks.add_column("Detail", overflow="fold", ratio=1)
    for item in offline_results:
        mark = "[green]ok[/green]" if item.ok else "[bold red]FAIL[/bold red]"
        checks.add_row(mark, f"{item.suite}: {item.name}", item.detail or "")
    console.print(checks)
    offline_failed = sum(not item.ok for item in offline_results)

    console.print("\n[bold]Were the results correct?[/bold]  [dim]each endpoint against its known answer[/dim]")
    verdicts = Table(box=box.SIMPLE, header_style="bold", expand=True, pad_edge=False, show_header=False)
    verdicts.add_column("", no_wrap=True, width=6)
    verdicts.add_column("Case", no_wrap=True, overflow="ellipsis", max_width=46)
    verdicts.add_column("Detail", overflow="fold", ratio=1)
    status_style = {PASS: "green", FAIL: "bold red", UNREACHABLE: "yellow"}
    status_mark = {PASS: "ok", FAIL: "FAIL", UNREACHABLE: "skip"}
    for result in sorted(results, key=lambda r: ({FAIL: 0, UNREACHABLE: 1, PASS: 2}[r.status], r.name)):
        verdicts.add_row(
            f"[{status_style[result.status]}]{status_mark[result.status]}"
            f"[/{status_style[result.status]}]",
            result.name, result.detail or "",
        )
    console.print(verdicts)

    if report_dir:
        written = export(
            report_dir, None, findings, certificates, engine,
            {
                "operator": "selftest", "engagement": "selftest", "authorised": True,
                "probe_method": "native", "profile": engine.profile_name,
                "tool_version": TOOL_VERSION, "scan_time": scan_time,
                "rules_version": engine.rules.get("profile", {}).get("rules_version"),
            },
            reporter,
        )
        console.print(
            f"\n[dim]Every output format written to {report_dir}/ - "
            + ", ".join(p.name for p in written) + "[/dim]"
        )

    passed = sum(r.status == PASS for r in results) + (len(offline_results) - offline_failed)
    failed = sum(r.status == FAIL for r in results) + offline_failed
    unreachable = sum(r.status == UNREACHABLE for r in results)
    console.print(
        f"\n[bold]{passed} correct[/bold]"
        + (f"  [bold red]{failed} wrong[/bold red]" if failed else "")
        + (f"  [yellow]{unreachable} unreachable[/yellow]" if unreachable else "")
    )
    if unreachable and not strict:
        console.print(
            "[dim]Unreachable endpoints were not counted against the tool: usually a firewall "
            "in between or a rate-limited public test server, not a defect. --strict requires them.[/dim]"
        )
    if failed:
        console.print(
            "\n[bold red]A wrong result means the scanner disagreed with a known answer.[/bold red]\n"
            "[dim]The detail says what was expected and what was found. If the endpoint itself "
            "changed configuration, update pqc_scan/rules/selftest.yaml.[/dim]"
        )
    raise typer.Exit(1 if failed or (strict and unreachable) else 0)


if __name__ == "__main__":
    try:
        app()
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Internal error: {e}[/bold red]")
        raise SystemExit(70) from e
