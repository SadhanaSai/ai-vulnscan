"""CVE drafter + pre-file cross-check gate — cve-agent-spec.md §8.6, §12 (Phase 6).

§8.2a runs once, when a signal first arrives. Time then passes before a
researcher reviews a Lane 1 finding, and a CVE can get assigned by someone
else in that window. So immediately before a finding is allowed to become
`ready_to_file`, this module re-runs `cross_check_existing_cve()` fresh — it
never trusts `last_cve_crosscheck`, no matter how recent (CLAUDE.md
constraint 6). `status` may only become `"ready_to_file"` in this exact code
path.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from llm.router import complete
from pipelines.http_utils import console, parse_github_commit_url
from pipelines.known_cve import cross_check_existing_cve
from state.db import Finding, list_findings, now_iso, upsert_finding

SYSTEM_PROMPT = (
    "You are a security researcher drafting formal CVE filing text for a confirmed vulnerability finding.\n"
    "Return only the filled-in template text below — no extra commentary, no markdown code fences."
)

DRAFT_TEMPLATE = """\
[PACKAGE] [VERSION RANGE] — [VULNERABILITY CLASS]

[PACKAGE] versions [X] through [Y] contain a [vulnerability class] vulnerability
in [specific component/function]. [One sentence describing the flaw technically.]

An attacker can [attack scenario]. This results in [impact].

In agentic AI deployments where [package] is used as [agentic_context],
this vulnerability is particularly severe because [agentic_uplift].

Discovered using automated static analysis of public repository commit history.
Verified by manual code review of the affected version.

Affected versions: [range]
Fixed version: [version] (commit: [url]) [OR: No fix available as of YYYY-MM-DD]
CWE: [CWE-XX]
CVSS 3.1: [score] ([vector])
MITRE ATLAS: [technique] [if applicable]

Researcher: [Your name]
Disclosure date: [date]
"""


def build_user_prompt(finding: Finding) -> str:
    return (
        "Fill in this CVE draft template using the finding details below. Keep the exact "
        "section structure and labels; replace only the bracketed placeholders. Leave "
        "'[Your name]' as a literal placeholder — the researcher fills that in before filing.\n\n"
        f"Template:\n{DRAFT_TEMPLATE}\n\n"
        "Finding details:\n"
        f"Package: {finding.package}\n"
        f"Ecosystem: {finding.ecosystem}\n"
        f"Layer: {finding.layer}\n"
        f"Vulnerability summary: {finding.summary}\n"
        f"CWE: {', '.join(finding.cwe) or 'unknown'}\n"
        f"CVSS: {finding.cvss if finding.cvss is not None else 'unknown'}\n"
        f"Severity: {finding.severity or 'unknown'}\n"
        f"MITRE ATLAS technique: {finding.atlas_technique or 'N/A'}\n"
        f"Agentic uplift: {finding.agentic_uplift or 'none noted'}\n"
        f"Signal / fix reference: {finding.signal_url}\n"
        f"Lane: {finding.lane} ({'unpatched, no fix available yet' if finding.lane == '1A' else 'patched, no CVE assigned yet'})\n"
        f"Disclosure date: {date.today().isoformat()}\n"
    )


async def draft_cve(finding: Finding, *, llm_provider: str | None = None, llm_model: str | None = None) -> str:
    user_prompt = build_user_prompt(finding)
    return await complete("cve_drafting", SYSTEM_PROMPT, user_prompt, provider=llm_provider, model=llm_model)


async def gate_and_draft_finding(
    finding: Finding,
    *,
    db: Any,
    github_token: str | None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    dry_run: bool = False,
) -> Finding:
    """§8.6 — the only path allowed to set status='ready_to_file'. Runs a
    fresh cross-check (never the cached last_cve_crosscheck) before
    drafting. `dry_run` still runs the gate — the point is to warn the
    researcher, not to save an API call (§8.6)."""
    if not finding.validation_steps:
        # CLAUDE.md constraint 3: "A finding without validation steps is
        # incomplete. Do not mark it ready_to_file." Every upstream path
        # (triage, watch re-triage, pattern hunter) already enforces this
        # before persisting a Lane 1 finding, but this is the last gate
        # before filing text is generated — defense in depth, same
        # reasoning as the manual OSV re-check in validation_steps step 7.
        console.print(
            f"[red]blocked:[/red] {finding.package} finding {finding.id[:12]} has no validation_steps "
            "— cannot be drafted or marked ready_to_file until populated."
        )
        return finding

    commit_sha = None
    if finding.source == "github_commit" and finding.signal_url:
        parsed = parse_github_commit_url(finding.signal_url)
        if parsed:
            _, commit_sha = parsed

    cve_id = await cross_check_existing_cve(
        finding.package, finding.ecosystem, commit_sha=commit_sha, github_token=github_token
    )
    finding.last_cve_crosscheck = now_iso()

    if cve_id:
        finding.cve_id = cve_id
        finding.status = "closed"
        console.print(
            f"[yellow]superseded:[/yellow] {finding.package} finding {finding.id[:12]} closed — "
            f"{cve_id} already covers this, no draft generated"
        )
        if not dry_run:
            upsert_finding(db, finding)
        return finding

    draft = await draft_cve(finding, llm_provider=llm_provider, llm_model=llm_model)
    finding.cve_draft = draft
    finding.status = "ready_to_file"
    if not dry_run:
        upsert_finding(db, finding)
    return finding


async def run_cve_drafting(
    *, db: Any, github_token: str | None, llm_provider: str | None = None, llm_model: str | None = None, dry_run: bool = False
) -> list[Finding]:
    """Runs the gate+draft for every Lane 1 finding not yet in a terminal
    status — backs `python main.py report`'s pre-render cross-check pass."""
    candidates = [
        f for f in list_findings(db) if f.lane in ("1A", "1B") and f.status not in ("ready_to_file", "filed", "closed")
    ]
    updated: list[Finding] = []
    for finding in candidates:
        try:
            result = await gate_and_draft_finding(
                finding, db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model, dry_run=dry_run
            )
        except Exception as exc:
            console.print(f"[yellow]warning:[/yellow] CVE drafting failed for finding {finding.id[:12]}: {exc}")
            continue
        updated.append(result)
    return updated
