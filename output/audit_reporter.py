"""Markdown audit report generator — cve-agent-spec.md §8.8, backs the
standalone `python main.py audit` command.

Distinct from output/reporter.py's CVE report: this only ever reads
audit_runs (state/db.py AuditRun) — never Finding/lane/status, matching
`audit`'s informational-only, standalone design.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Iterable

from state.db import PROJECT_ROOT, AuditRun

DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"

# Most actionable first: a real concern outranks an operational error, which
# outranks "reviewed, nothing found" style verdicts.
_VERDICT_ORDER = {"CONFIRMED_CONCERN": 0, "ERROR": 1, "LIKELY_BY_DESIGN": 2, "NOT_FOUND": 3, "OUT_OF_SCOPE": 4}


def _md_escape(text: str | None) -> str:
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\n", " ")


def _evidence_block(evidence: list[dict]) -> str:
    if not evidence:
        return "_No evidence cited._"
    lines: list[str] = []
    for e in evidence:
        loc = f"`{e.get('file', '?')}`" + (f":{e['lines']}" if e.get("lines") else "")
        note = e.get("note") or ""
        lines.append(f"- {loc} — {note}")
        if e.get("snippet"):
            lines.append(f"  ```\n  {e['snippet']}\n  ```")
    return "\n".join(lines)


def generate_audit_report(repo: str, ecosystem: str, runs: Iterable[AuditRun]) -> str:
    ordered = sorted(runs, key=lambda r: _VERDICT_ORDER.get(r.verdict, 9))
    sections = [
        f"# Agentic-Tooling Security Audit — {repo}",
        f"**Ecosystem:** {ecosystem}",
        f"**Date:** {date.today().isoformat()}",
        f"**Areas checked:** {len(ordered)}",
        "",
        "_Standalone, informational report (cve-agent-spec.md §8.8) — this audit never "
        "touches Finding/lane/status/disclosure. A CONFIRMED_CONCERN here is not "
        "automatically CVE-worthy; some are documented, opt-in tradeoffs._",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Area | Verdict | Impact |",
        "|---|---|---|",
    ]
    if not ordered:
        sections.append("| _(none)_ | — | — |")
    for run in ordered:
        sections.append(f"| {run.area} | {run.verdict} | {_md_escape(run.impact) or '—'} |")

    sections += ["", "---", "", "## Detail", ""]
    for run in ordered:
        sections.append(f"### {run.area} — {run.verdict}")
        sections.append("")
        if run.impact:
            sections.append(f"**Impact:** {run.impact}")
            sections.append("")
        sections.append(_evidence_block(run.evidence))
        sections.append("")

    return "\n".join(sections)


def _slugify_repo(repo: str) -> str:
    return repo.replace("/", "-").lower()


def write_audit_report(content: str, repo: str, path: str | Path | None = None) -> Path:
    if path is None:
        path = DEFAULT_REPORT_DIR / f"audit-{_slugify_repo(repo)}-{date.today().isoformat()}.md"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path
