"""Markdown report generator — cve-agent-spec.md §11.

All six sections are populated as of Phase 6: CONFIRMED CVEs, READY TO FILE
(Lane 1 findings with status="ready_to_file" — set only by
output/cve_drafter.py's pre-file cross-check gate, §8.6), WATCH QUEUE
(Lane 2, Phase 3), PATTERN LIBRARY DELTA (Phase 4/5), and DISCLOSURE TRACKER
(Phase 6, `python main.py disclose`).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable

import sqlite_utils

from state.db import PROJECT_ROOT, Finding, list_findings, list_patterns

DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"


def _md_escape(text: str | None) -> str:
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\n", " ")


def _table_section(
    title: str,
    rows: list[Any],
    *,
    empty_message: str,
    columns: list[str],
    row_fn: Callable[[Any], Iterable[Any]],
    preamble: str | None = None,
) -> str:
    lines = [f"## {title}", ""]
    if not rows:
        lines.append(f"_{empty_message}_")
        return "\n".join(lines)
    if preamble:
        lines.append(preamble)
        lines.append("")
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("|" + "|".join("---" for _ in columns) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row_fn(row)) + " |")
    return "\n".join(lines)


def _confirmed_cves_section(findings: list[Finding]) -> str:
    # Includes original known-CVE-feed findings (lane="known") *and* Lane 1
    # findings the §8.6 gate found already superseded by an existing CVE
    # (status="closed", lane still "1A"/"1B", cve_id attached) — spec §8.6:
    # "route the finding into the CONFIRMED CVEs report section".
    known = sorted(
        (f for f in findings if f.cve_id),
        key=lambda f: (-(f.cvss or 0), f.package),
    )
    return _table_section(
        "CONFIRMED CVEs (Known, from feeds)",
        known,
        empty_message="No known CVEs found in this run.",
        columns=["CVE ID", "Package", "Severity", "CVSS", "Summary", "Agentic Uplift?", "Source"],
        row_fn=lambda f: [
            f.cve_id,
            f.package,
            f.severity or "—",
            f.cvss if f.cvss is not None else "—",
            _md_escape(f.summary) + (" _(superseded pre-CVE finding)_" if f.lane != "known" else ""),
            _md_escape(f.agentic_uplift) or "—",
            f.source,
        ],
    )


def _ready_to_file_section(findings: list[Finding]) -> str:
    lines = ["## READY TO FILE (Lane 1 — Human review required)", ""]
    if not findings:
        lines.append("_No findings currently ready to file._")
        return "\n".join(lines)
    for f in findings:
        lines.append(f"### [{f.id[:12]}] Package: {f.package} | Severity: {f.severity or 'UNKNOWN'} | {', '.join(f.cwe) or 'CWE-?'}")
        lines.append(f"**Summary:** {f.summary}")
        lines.append(f"**Signal:** {f.signal_url}")
        lines.append(f"**Lane:** {f.lane}")
        lines.append(f"**CVSS estimate:** {f.cvss if f.cvss is not None else '—'}")
        lines.append(f"**Agentic uplift:** {f.agentic_uplift or '—'}")
        lines.append(f"**Disclosure deadline:** {f.disclosure_deadline or 'N/A'}")
        lines.append(f"**Cross-check:** {'clean as of ' + f.last_cve_crosscheck if f.last_cve_crosscheck else 'not yet run'}")
        if f.validation_steps:
            lines.append("**Validation steps:**")
            for step in f.validation_steps:
                lines.append(f"- {step}")
        if f.cve_draft:
            lines.append("")
            lines.append("**CVE DRAFT:**")
            lines.append(f.cve_draft)
        lines.append("")
    return "\n".join(lines)


def _watch_queue_section(db: sqlite_utils.Database, findings: list[Finding]) -> str:
    watch_by_id = {r["finding_id"]: r for r in db["watch_queue"].rows} if "watch_queue" in db.table_names() else {}
    return _table_section(
        "WATCH QUEUE (Lane 2 — revisit in 48h)",
        findings,
        empty_message="No Lane 2 findings currently in the watch queue.",
        columns=["ID", "Package", "Signal", "First Seen", "Next Check"],
        row_fn=lambda f: [
            f.id[:12],
            f.package,
            f.signal_url,
            f.first_seen,
            (watch_by_id.get(f.id) or {}).get("next_check", "— (not yet scheduled)"),
        ],
    )


def _pattern_library_section(db: sqlite_utils.Database) -> str:
    patterns = list_patterns(db)
    return _table_section(
        "PATTERN LIBRARY DELTA",
        patterns,
        empty_message="Pattern library is empty — no Lane 1 commit-sourced findings have been extracted yet.",
        preamble=f"Total patterns in library: {len(patterns)}",
        columns=["Pattern ID", "Class", "Source Finding", "Total Hits", "False Positives"],
        row_fn=lambda p: [
            p.id,
            p.vulnerability_class,
            (p.source_finding_id or "—")[:12],
            len(p.confirmed_hits),
            p.false_positives,
        ],
    )


def _disclosure_tracker_section(db: sqlite_utils.Database, findings_by_id: dict[str, Finding]) -> str:
    entries = list(db["disclosure_log"].rows) if "disclosure_log" in db.table_names() else []

    def _row(e: dict[str, Any]) -> list[Any]:
        f = findings_by_id.get(e["finding_id"])
        return [
            e["finding_id"][:12],
            f.package if f else "—",
            e["disclosed_to"] or "—",
            e["deadline"] or "—",
            f.status if f else "—",
        ]

    return _table_section(
        "DISCLOSURE TRACKER",
        entries,
        empty_message="No open disclosures yet.",
        columns=["Finding ID", "Package", "Disclosed To", "Deadline", "Status"],
        row_fn=_row,
    )


def generate_report(db: sqlite_utils.Database, *, mode: str, packages_scanned: int, findings_new: int) -> str:
    # One fetch of the findings table, partitioned in memory, instead of a
    # separate filtered query per section.
    all_findings = list_findings(db)
    findings_by_id = {f.id: f for f in all_findings}
    ready_to_file_findings = [f for f in all_findings if f.status == "ready_to_file"]
    lane2_findings = [f for f in all_findings if f.lane == "2"]

    sections = [
        "# AI/Agentic CVE Research Report",
        f"**Date:** {date.today().isoformat()}",
        f"**Run mode:** {mode}",
        f"**Packages scanned:** {packages_scanned}",
        f"**New findings:** {findings_new}",
        "",
        "---",
        "",
        _ready_to_file_section(ready_to_file_findings),
        "",
        "---",
        "",
        _watch_queue_section(db, lane2_findings),
        "",
        "---",
        "",
        _confirmed_cves_section(all_findings),
        "",
        "---",
        "",
        _pattern_library_section(db),
        "",
        "---",
        "",
        _disclosure_tracker_section(db, findings_by_id),
        "",
    ]
    return "\n".join(sections)


def write_report(content: str, path: str | Path | None = None) -> Path:
    if path is None:
        path = DEFAULT_REPORT_DIR / f"{date.today().isoformat()}.md"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path
