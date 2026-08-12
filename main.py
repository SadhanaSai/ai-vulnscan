#!/usr/bin/env python3
"""CLI entry point — cve-agent-spec.md §10.

Phase 1: known CVE pipeline (NVD/OSV/GHSA). Phase 2 adds the pre-CVE commit
scanner + Groq/Claude/Ollama triage — both run as part of `scan`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from hunter.scanner import run_pattern_hunt
from llm.router import missing_api_key, resolve_provider_model
from output.cve_drafter import run_cve_drafting
from output.reporter import generate_report, write_report
from patterns.extractor import run_pattern_extraction
from pipelines.known_cve import load_watchlist, run_known_cve_pipeline
from pipelines.pre_cve import run_pre_cve_pipeline, run_watch_queue
from state.db import (
    DEFAULT_DB_PATH,
    DynamicValidationRun,
    get_db,
    get_finding,
    list_patterns,
    log_scan,
    record_disclosure,
    record_validation_run,
    status_summary,
)
from validation._shared import ValidationOutcome
from validation.classify import HARNESS_CLASSES, class_matches_finding
from validation.harnesses import get_harness_runner
from validation.harnesses._shared import MissingTargetParams
from validation.pattern_confirmation import confirm_pattern
from validation.version_resolution import resolve_version

load_dotenv()
console = Console()


def _filter_packages(packages: list[dict], names: tuple[str, ...], layer: str | None) -> list[dict]:
    filtered = packages
    if names:
        wanted = set(names)
        filtered = [p for p in filtered if p["name"] in wanted]
    if layer:
        filtered = [p for p in filtered if p["layer"] == layer]
    return filtered


@click.group()
def cli() -> None:
    """AI/Agentic CVE Research Agent — static vulnerability research pipeline."""


@cli.command()
@click.option("--packages", "package_names", multiple=True, help="Scan specific packages only")
@click.option(
    "--layer",
    type=click.Choice(["framework", "sdk", "mcp", "infrastructure"]),
    default=None,
    help="Scan one layer only",
)
@click.option("--dry-run", is_flag=True, help="Run the pipeline but do not write findings to the database")
@click.option("--llm-provider", "llm_provider", default=None, help="Override the triage LLM provider for this run (groq|claude|ollama)")
@click.option("--llm-model", "llm_model", default=None, help="Override the triage LLM model for this run")
def scan(package_names: tuple[str, ...], layer: str | None, dry_run: bool, llm_provider: str | None, llm_model: str | None) -> None:
    """Run the known CVE pipeline (NVD + OSV.dev + GHSA), then the pre-CVE
    commit scanner + LLM triage, for watchlist packages."""
    watchlist = load_watchlist()
    targets = _filter_packages(watchlist, package_names, layer)
    if not targets:
        console.print("[yellow]No packages matched the given filters.[/yellow]")
        return
    _run_scan(targets, dry_run=dry_run, llm_provider=llm_provider, llm_model=llm_model)


@cli.command(name="scan-repo")
@click.option("--name", required=True, help="Package name — used for finding IDs, not persisted anywhere")
@click.option("--ecosystem", type=click.Choice(["pypi", "npm"]), required=True)
@click.option(
    "--layer",
    type=click.Choice(["framework", "sdk", "mcp", "infrastructure"]),
    required=True,
)
@click.option("--repo", required=True, help="GitHub org/repo, e.g. org/repo")
@click.option("--agentic-context", default=None, help="Optional free-text context for the LLM")
@click.option("--dry-run", is_flag=True, help="Run the pipeline but do not write findings to the database")
@click.option("--llm-provider", "llm_provider", default=None, help="Override the triage LLM provider for this run (groq|claude|ollama)")
@click.option("--llm-model", "llm_model", default=None, help="Override the triage LLM model for this run")
def scan_repo(
    name: str,
    ecosystem: str,
    layer: str,
    repo: str,
    agentic_context: str | None,
    dry_run: bool,
    llm_provider: str | None,
    llm_model: str | None,
) -> None:
    """One-off scan of a single package/repo. Does not read or write
    config/watchlist.yaml — the package is not persisted anywhere; this run
    is the only place it's scanned. Findings still land in the same
    database as watchlist scans, so re-running `scan-repo` on the same repo
    later won't re-report anything already seen."""
    target = {
        "name": name,
        "ecosystem": ecosystem,
        "layer": layer,
        "repo": repo,
        "agentic_context": agentic_context,
        "enabled": True,
    }
    _run_scan([target], dry_run=dry_run, llm_provider=llm_provider, llm_model=llm_model)


def _run_scan(targets: list[dict], *, dry_run: bool, llm_provider: str | None, llm_model: str | None) -> None:
    github_token = os.environ.get("GITHUB_TOKEN")
    nvd_api_key = os.environ.get("NVD_API_KEY")
    if not github_token:
        console.print(
            "[yellow]warning:[/yellow] GITHUB_TOKEN not set — GHSA source and the pre-CVE "
            "commit scan will both be skipped for this run."
        )
    if not nvd_api_key:
        console.print(
            "[yellow]warning:[/yellow] NVD_API_KEY not set — NVD queries run at the unauthenticated rate limit (slower)."
        )

    db = get_db()
    console.print(f"Scanning {len(targets)} package(s) against NVD, OSV.dev, and GHSA...")
    start = time.monotonic()
    known_result = asyncio.run(
        run_known_cve_pipeline(
            targets,
            db=db,
            github_token=github_token,
            nvd_api_key=nvd_api_key,
            dry_run=dry_run,
        )
    )

    pre_cve_result = None
    try:
        resolved_provider, _ = resolve_provider_model("triage", provider=llm_provider, model=llm_model)
    except ValueError as exc:
        console.print(f"[yellow]warning:[/yellow] {exc} — skipping pre-CVE commit scan.")
    else:
        missing_env = missing_api_key(resolved_provider)
        if missing_env:
            console.print(
                f"[yellow]warning:[/yellow] {missing_env} not set for triage provider {resolved_provider!r} "
                "— skipping pre-CVE commit scan."
            )
        elif github_token:
            console.print(f"Scanning commit history for pre-CVE signals (triage provider: {resolved_provider})...")
            pre_cve_result = asyncio.run(
                run_pre_cve_pipeline(
                    targets,
                    db=db,
                    github_token=github_token,
                    llm_provider=llm_provider,
                    llm_model=llm_model,
                    dry_run=dry_run,
                )
            )
    # Phase 4/5 — extract patterns from any new Lane 1 commit findings, then
    # immediately hunt those specific patterns across whatever was scanned
    # this run (§8.5: "or automatically after any new pattern is added to
    # the library"). Sibling-scan scope is bounded to `targets`, not the
    # full watchlist — `python main.py hunt` covers full-library, full-
    # watchlist runs on demand.
    new_patterns = []
    try:
        pe_provider, _ = resolve_provider_model("pattern_extraction", provider=llm_provider, model=llm_model)
    except ValueError as exc:
        console.print(f"[yellow]warning:[/yellow] {exc} — skipping pattern extraction.")
    else:
        missing_env = missing_api_key(pe_provider)
        if missing_env:
            console.print(
                f"[yellow]warning:[/yellow] {missing_env} not set for pattern_extraction provider {pe_provider!r} "
                "— skipping pattern extraction."
            )
        elif github_token:
            watchlist_for_extraction = load_watchlist()
            package_to_repo = {p["name"]: p["repo"] for p in watchlist_for_extraction if p.get("repo")}
            package_to_path_prefix = {p["name"]: p["path_prefix"] for p in watchlist_for_extraction if p.get("path_prefix")}
            new_patterns = asyncio.run(
                run_pattern_extraction(
                    db=db, github_token=github_token, package_to_repo=package_to_repo,
                    package_to_path_prefix=package_to_path_prefix,
                    llm_provider=llm_provider, llm_model=llm_model, dry_run=dry_run,
                )
            )
            if new_patterns:
                console.print(f"[green]{len(new_patterns)} new pattern(s) extracted.[/green] Hunting them across this run's packages...")
                asyncio.run(
                    run_pattern_hunt(
                        targets, new_patterns, db=db, github_token=github_token,
                        llm_provider=llm_provider, llm_model=llm_model, dry_run=dry_run,
                    )
                )

    duration = time.monotonic() - start

    findings_new = known_result.findings_new + (pre_cve_result.findings_new if pre_cve_result else 0)
    llm_calls = pre_cve_result.llm_calls if pre_cve_result else 0
    log_scan(
        db,
        mode="scan",
        packages_scanned=known_result.packages_scanned,
        findings_new=findings_new,
        llm_calls_by_provider={resolved_provider: llm_calls} if pre_cve_result else {},
        duration_seconds=duration,
    )

    suffix = " (dry run — not written to database)" if dry_run else ""
    console.print(
        f"[green]Done.[/green] {known_result.packages_scanned} package(s) scanned, "
        f"{findings_new} new finding(s){suffix} in {duration:.1f}s."
    )


@cli.command()
@click.option("--dry-run", is_flag=True, help="Run the re-check but do not write changes to the database")
@click.option("--llm-provider", "llm_provider", default=None, help="Override the triage LLM provider for this run (groq|claude|ollama)")
@click.option("--llm-model", "llm_model", default=None, help="Override the triage LLM model for this run")
def watch(dry_run: bool, llm_provider: str | None, llm_model: str | None) -> None:
    """Process the Lane 2 watch queue — re-triage findings whose 48h re-check is due."""
    db = get_db()
    watchlist = load_watchlist()
    github_token = os.environ.get("GITHUB_TOKEN")
    console.print("Processing watch queue (Lane 2 items due for re-check)...")
    start = time.monotonic()
    result = asyncio.run(
        run_watch_queue(
            watchlist, db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model, dry_run=dry_run
        )
    )
    duration = time.monotonic() - start
    log_scan(
        db,
        mode="watch",
        packages_scanned=0,
        findings_new=0,
        llm_calls_by_provider={llm_provider or "default": result.llm_calls} if result.llm_calls else {},
        duration_seconds=duration,
    )
    suffix = " (dry run — not written to database)" if dry_run else ""
    console.print(
        f"[green]Done.[/green] {result.items_checked} item(s) checked, {result.promoted} promoted out of Lane 2, "
        f"{result.still_watching} still watching{suffix} in {duration:.1f}s."
    )


@cli.command()
@click.option("--packages", "package_names", multiple=True, help="Hunt against specific packages only")
@click.option(
    "--layer",
    type=click.Choice(["framework", "sdk", "mcp", "infrastructure"]),
    default=None,
    help="Hunt one layer only",
)
@click.option("--dry-run", is_flag=True, help="Run the hunt but do not write findings to the database")
@click.option("--llm-provider", "llm_provider", default=None, help="Override the pattern_hunt LLM provider for this run")
@click.option("--llm-model", "llm_model", default=None, help="Override the pattern_hunt LLM model for this run")
def hunt(package_names: tuple[str, ...], layer: str | None, dry_run: bool, llm_provider: str | None, llm_model: str | None) -> None:
    """Run the pattern hunter: scan watchlist packages' source for every
    pattern currently in patterns/library.json."""
    db = get_db()
    watchlist = load_watchlist()
    targets = _filter_packages(watchlist, package_names, layer)
    if not targets:
        console.print("[yellow]No packages matched the given filters.[/yellow]")
        return
    patterns = list_patterns(db)
    if not patterns:
        console.print("[yellow]Pattern library is empty — nothing to hunt for yet.[/yellow] Run `scan` first to extract patterns from Lane 1 findings.")
        return
    github_token = os.environ.get("GITHUB_TOKEN")
    console.print(f"Hunting {len(patterns)} pattern(s) across {len(targets)} package(s)...")
    start = time.monotonic()
    result = asyncio.run(
        run_pattern_hunt(targets, patterns, db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model, dry_run=dry_run)
    )
    duration = time.monotonic() - start
    log_scan(
        db,
        mode="hunt",
        packages_scanned=result.scans_run,
        findings_new=result.findings_new,
        llm_calls_by_provider={llm_provider or "default": result.llm_calls} if result.llm_calls else {},
        duration_seconds=duration,
    )
    suffix = " (dry run — not written to database)" if dry_run else ""
    console.print(
        f"[green]Done.[/green] {result.patterns_checked} pattern(s) checked, {result.candidates_scanned} candidate(s) scanned, "
        f"{result.findings_new} new finding(s){suffix} in {duration:.1f}s."
    )


@cli.command()
@click.option("--finding-id", "finding_id", required=True)
@click.option("--to", "disclosed_to", required=True, help="Maintainer email or GitHub issue URL")
def disclose(finding_id: str, disclosed_to: str) -> None:
    """Mark a finding as disclosed — records who it was reported to; the
    90-day CVE filing deadline is whatever was already set on the finding
    when it was first triaged into Lane 1A."""
    db = get_db()
    finding = get_finding(db, finding_id)
    if finding is None:
        console.print(f"[red]error:[/red] no finding with id {finding_id!r}")
        raise SystemExit(1)
    record_disclosure(db, finding.id, disclosed_to, deadline=finding.disclosure_deadline)
    console.print(f"[green]Recorded.[/green] {finding.package} ({finding.id[:12]}) disclosed to {disclosed_to}.")
    if finding.disclosure_deadline:
        console.print(f"CVE filing deadline: {finding.disclosure_deadline}")


@cli.command()
@click.option("--output", "output_path", default=None, help="Report output path (default: reports/YYYY-MM-DD.md)")
@click.option("--llm-provider", "llm_provider", default=None, help="Override the cve_drafting LLM provider for this run")
@click.option("--llm-model", "llm_model", default=None, help="Override the cve_drafting LLM model for this run")
def report(output_path: str | None, llm_provider: str | None, llm_model: str | None) -> None:
    """Generate a Markdown report from the current database state. Before
    rendering, re-runs the §8.6 pre-file cross-check gate on every Lane 1
    finding not yet ready_to_file — a fresh CVE match bumps it into the
    CONFIRMED CVEs table instead; a clean check drafts the CVE text and
    marks it ready_to_file."""
    db = get_db()
    github_token = os.environ.get("GITHUB_TOKEN")
    try:
        cd_provider, _ = resolve_provider_model("cve_drafting", provider=llm_provider, model=llm_model)
    except ValueError as exc:
        console.print(f"[yellow]warning:[/yellow] {exc} — skipping the pre-file cross-check/draft gate for this report.")
    else:
        missing_env = missing_api_key(cd_provider)
        if missing_env:
            console.print(
                f"[yellow]warning:[/yellow] {missing_env} not set for cve_drafting provider {cd_provider!r} "
                "— skipping the pre-file cross-check/draft gate for this report."
            )
        else:
            console.print("Running pre-file cross-check gate on Lane 1 findings not yet ready to file...")
            asyncio.run(run_cve_drafting(db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model))

    summary = status_summary(db)
    content = generate_report(
        db,
        mode="report",
        packages_scanned=len(load_watchlist()),
        findings_new=summary["total_findings"],
    )
    path = write_report(content, output_path)
    console.print(f"[green]Report written to[/green] {path}")


@cli.command()
@click.option("--finding-id", "finding_id", required=True)
@click.option(
    "--class",
    "class_name",
    type=click.Choice(sorted(HARNESS_CLASSES)),
    default=None,
    help="Run one of the six fixed exploit harnesses instead of the default pattern-confirmation depth.",
)
@click.option("--target-module", default=None, help="--class only: dotted module path to import inside the sandbox")
@click.option("--target-callable", default=None, help="--class only: dot-separated attribute path to the vulnerable callable")
@click.option("--target-param", default=None, help="--class only: keyword arg the injected value goes in (omit for a positional call)")
@click.option(
    "--target-mode",
    type=click.Choice(["read", "write"]),
    default=None,
    help="--class arbitrary_file_rw only: which primitive to probe (default: write)",
)
@click.option("--version", "version_override", default=None, help="Exact affected version to install (default: auto-resolved)")
@click.option(
    "--force", is_flag=True, help="Required to run --class against a finding whose recorded CWE doesn't match that class"
)
def validate(
    finding_id: str,
    class_name: str | None,
    target_module: str | None,
    target_callable: str | None,
    target_param: str | None,
    target_mode: str | None,
    version_override: str | None,
    force: bool,
) -> None:
    """Phase 7 (cve-agent-spec.md §8.7) dynamic validation — strictly
    on-demand, one finding at a time, never part of scan/watch/hunt/report.
    Installs the affected version inside a hardened, single-use Docker
    sandbox (validation/sandbox.py), then either confirms the flagged code
    shape is present in the installed artifact (default depth) or runs one
    of six fixed, non-destructive exploit harnesses (--class). Every run —
    whatever the result — is appended to dynamic_validation_runs; this
    command never touches a finding's lane/status/ready_to_file. The
    researcher decides what a result means for their filing decision."""
    db = get_db()
    finding = get_finding(db, finding_id)
    if finding is None:
        console.print(f"[red]error:[/red] no finding with id {finding_id!r}")
        raise SystemExit(1)

    if shutil.which("docker") is None:
        console.print("[red]error:[/red] docker not found on PATH — Phase 7 requires a local Docker daemon.")
        raise SystemExit(1)

    depth = "class_exploit" if class_name else "pattern_confirmation"

    if class_name and not force and not class_matches_finding(class_name, finding):
        console.print(
            f"[red]error:[/red] --class {class_name} does not match this finding's recorded CWE(s) "
            f"({', '.join(finding.cwe) or 'none'}). Pass --force to run it anyway."
        )
        raise SystemExit(1)

    version, version_source = asyncio.run(resolve_version(finding, override_version=version_override))
    if version is None:
        outcome = ValidationOutcome(result="inconclusive", summary=version_source, log="")
    else:
        console.print(f"Installing {finding.package}=={version} ({version_source})...")
        if class_name is None:
            outcome = asyncio.run(
                confirm_pattern(finding, package=finding.package, ecosystem=finding.ecosystem, version=version)
            )
        else:
            try:
                runner = get_harness_runner(class_name)
                extra = {"target_mode": target_mode} if class_name == "arbitrary_file_rw" else {}
                outcome = asyncio.run(
                    runner(
                        finding,
                        package=finding.package,
                        ecosystem=finding.ecosystem,
                        version=version,
                        target_module=target_module,
                        target_callable=target_callable,
                        target_param=target_param,
                        **extra,
                    )
                )
            except MissingTargetParams as exc:
                outcome = ValidationOutcome(result="inconclusive", summary=str(exc), log="")

    run = DynamicValidationRun(
        finding_id=finding.id,
        depth=depth,
        vulnerability_class=class_name,
        result=outcome.result,
        summary=outcome.summary,
        log=outcome.log,
    )
    record_validation_run(db, run)

    color = {"confirmed": "red", "not_confirmed": "green", "inconclusive": "yellow", "error": "yellow"}.get(
        outcome.result, "white"
    )
    console.print(f"[{color}]{outcome.result}[/{color}]: {outcome.summary}")


@cli.command()
def status() -> None:
    """Print a summary of finding counts by lane and status."""
    db = get_db()
    summary = status_summary(db)

    console.print(f"Database: {DEFAULT_DB_PATH}")
    console.print(f"Total findings: {summary['total_findings']}")

    lane_table = Table(title="By lane")
    lane_table.add_column("Lane")
    lane_table.add_column("Count", justify="right")
    for lane, count in sorted(summary["by_lane"].items()):
        lane_table.add_row(lane, str(count))
    console.print(lane_table)

    status_table = Table(title="By status")
    status_table.add_column("Status")
    status_table.add_column("Count", justify="right")
    for status_name, count in sorted(summary["by_status"].items()):
        status_table.add_row(status_name, str(count))
    console.print(status_table)


@cli.command(name="watchlist")
def watchlist_cmd() -> None:
    """List all watchlist packages with their layer and enabled status."""
    table = Table(title="Watchlist")
    table.add_column("Name")
    table.add_column("Ecosystem")
    table.add_column("Layer")
    table.add_column("Repo")
    table.add_column("Enabled")
    for pkg in load_watchlist():
        table.add_row(
            pkg["name"],
            pkg["ecosystem"],
            pkg["layer"],
            pkg.get("repo") or "—",
            "yes" if pkg.get("enabled", True) else "no",
        )
    console.print(table)


if __name__ == "__main__":
    cli()
