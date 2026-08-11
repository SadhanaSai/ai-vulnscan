#!/usr/bin/env python3
"""CLI entry point — cve-agent-spec.md §10.

Phase 1: known CVE pipeline (NVD/OSV/GHSA). Phase 2 adds the pre-CVE commit
scanner + Groq/Claude/Ollama triage — both run as part of `scan`.
"""

from __future__ import annotations

import asyncio
import os
import time

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from llm.router import missing_api_key, resolve_provider_model
from output.reporter import generate_report, write_report
from pipelines.known_cve import load_watchlist, run_known_cve_pipeline
from pipelines.pre_cve import run_pre_cve_pipeline
from state.db import DEFAULT_DB_PATH, get_db, log_scan, status_summary

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
@click.option("--output", "output_path", default=None, help="Report output path (default: reports/YYYY-MM-DD.md)")
def report(output_path: str | None) -> None:
    """Generate a Markdown report from the current database state."""
    db = get_db()
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
