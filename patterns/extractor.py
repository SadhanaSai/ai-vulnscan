"""Pattern extractor — cve-agent-spec.md §8.4 (Phase 4).

Triggered for every Lane 1A/1B finding sourced from a GitHub commit (the
only signal type that carries a fix-commit URL in this pipeline's data
model — issues/PRs/HN stories/dependency signals don't). Fetches the commit
diff and extracts a structured, reusable vulnerability pattern via
`llm.router.complete(phase="pattern_extraction", ...)`. Patterns are stored
in the `patterns` SQLite table (state/db.py, the live/authoritative copy)
and exported to patterns/library.json (git-tracked) on every change.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from llm.router import complete
from pipelines.http_utils import console, parse_github_commit_url, request_with_retry
from state.db import (
    Finding,
    Pattern,
    export_pattern_library,
    list_findings,
    list_patterns,
    upsert_finding,
    upsert_pattern,
)

COMMIT_DIFF_ACCEPT = "application/vnd.github.v3.diff"
MAX_DIFF_CHARS = 8000  # bounds LLM prompt cost/context on large diffs

SYSTEM_PROMPT = (
    "You are a security researcher extracting a reusable vulnerability pattern from a confirmed fix.\n"
    "You return structured JSON only matching the Pattern schema.\n"
    "The pattern must be general enough to apply to other packages — not tied to this "
    "package's specific variable names or structure."
)

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
_REQUIRED_FIELDS = ("vulnerability_class", "trigger", "vulnerable_shape", "safe_shape")


class PatternSchemaError(ValueError):
    """Raised when a pattern-extraction response can't be parsed or is missing required fields."""


async def fetch_commit_diff(client: httpx.AsyncClient, repo: str, commit_sha: str, *, token: str) -> str:
    resp = await request_with_retry(
        client,
        "GET",
        f"https://api.github.com/repos/{repo}/commits/{commit_sha}",
        headers={"Authorization": f"Bearer {token}", "Accept": COMMIT_DIFF_ACCEPT},
    )
    if resp is None:
        return ""
    return resp.text[:MAX_DIFF_CHARS]


def _next_pattern_id(existing: list[Pattern], layer: str | None, vulnerability_class: str) -> str:
    """e.g. 'MCP-PATH-TRAVERSAL-001' (CLAUDE.md Pattern.id example) — one
    sequence per (layer, vulnerability_class) prefix."""
    prefix = f"{(layer or 'GEN').upper()}-{vulnerability_class.upper().replace(' ', '-').replace('_', '-')}"
    seqs = []
    for p in existing:
        if p.id.startswith(prefix + "-"):
            tail = p.id[len(prefix) + 1 :]
            if tail.isdigit():
                seqs.append(int(tail))
    return f"{prefix}-{(max(seqs) + 1) if seqs else 1:03d}"


def build_user_prompt(*, package: str, vulnerability_class: str, diff: str) -> str:
    return (
        f"Package: {package}\n"
        f"Vulnerability class identified: {vulnerability_class}\n"
        f"Fix commit diff:\n{diff}\n\n"
        "Extract a structured vulnerability pattern that can be used to find the same class of "
        "vulnerability in other packages. The pattern should describe the underlying flaw, not be "
        "tied to this package's specific variable names or structure.\n\n"
        "Respond in JSON only, matching this shape:\n"
        "{\n"
        '  "vulnerability_class": "...",\n'
        '  "layer": "framework|sdk|mcp|infrastructure",\n'
        '  "trigger": "...",\n'
        '  "vulnerable_shape": "...",\n'
        '  "safe_shape": "...",\n'
        '  "agentic_context": "...",\n'
        '  "cwe": ["CWE-XX"],\n'
        '  "atlas_technique": "AML.TXXXX|null"\n'
        "}"
    )


def _parse_json_response(raw: str) -> dict[str, Any]:
    cleaned = _FENCE_RE.sub("", raw.strip()).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise PatternSchemaError(f"pattern extraction response was not valid JSON: {exc}\nraw response: {raw[:500]}") from exc
    if not isinstance(data, dict):
        raise PatternSchemaError(f"pattern extraction response must be a JSON object, got {type(data).__name__}")
    missing = [f for f in _REQUIRED_FIELDS if not data.get(f)]
    if missing:
        raise PatternSchemaError(f"pattern extraction response missing required field(s) {missing}: {raw[:500]}")
    return data


async def extract_pattern_from_finding(
    finding: Finding,
    *,
    db: Any,
    github_token: str,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    library_path: str | None = None,
    dry_run: bool = False,
) -> Pattern | None:
    """Extract a pattern for one Lane 1A/1B, commit-sourced finding —
    persisted unless `dry_run`. Returns None (and does nothing) if the
    finding isn't eligible: not Lane 1, not a commit signal, no parseable
    commit URL, or already has a pattern."""
    if finding.lane not in ("1A", "1B"):
        return None
    if finding.source != "github_commit":
        return None
    if finding.pattern_id:
        return None

    parsed = parse_github_commit_url(finding.signal_url or "")
    if parsed is None:
        return None
    repo, commit_sha = parsed

    async with httpx.AsyncClient(timeout=30.0) as client:
        diff = await fetch_commit_diff(client, repo, commit_sha, token=github_token)
    if not diff:
        return None

    vulnerability_class = (finding.cwe[0] if finding.cwe else finding.summary) or "unknown"
    user_prompt = build_user_prompt(package=finding.package, vulnerability_class=vulnerability_class, diff=diff)
    raw = await complete("pattern_extraction", SYSTEM_PROMPT, user_prompt, provider=llm_provider, model=llm_model)
    data = _parse_json_response(raw)

    pattern = Pattern(
        id=_next_pattern_id(list_patterns(db), data.get("layer") or finding.layer, data["vulnerability_class"]),
        vulnerability_class=data["vulnerability_class"],
        layer=data.get("layer") or finding.layer,
        trigger=data["trigger"],
        vulnerable_shape=data["vulnerable_shape"],
        safe_shape=data["safe_shape"],
        agentic_context=data.get("agentic_context"),
        cwe=data.get("cwe") or finding.cwe or [],
        atlas_technique=data.get("atlas_technique"),
        source_finding_id=finding.id,
        source_commit_url=finding.signal_url,
        confirmed_hits=[finding.id],
    )
    if not dry_run:
        upsert_pattern(db, pattern)
        if library_path is None:
            export_pattern_library(db)
        else:
            export_pattern_library(db, library_path)
        finding.pattern_id = pattern.id
        upsert_finding(db, finding)

    return pattern


async def run_pattern_extraction(
    *,
    db: Any,
    github_token: str,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    library_path: str | None = None,
    dry_run: bool = False,
) -> list[Pattern]:
    """Extract patterns for every eligible Lane 1 commit-sourced finding
    that doesn't already have one — cve-agent-spec.md §8.4. Note: unlike
    other pipelines, dry_run here doesn't fully "re-run cleanly next time" —
    since nothing is persisted (no pattern_id written back), the same
    candidates will be re-extracted (and re-billed) on the next call,
    dry_run or not. That's intentional: dry_run exists to preview cost/
    output, not to be a free repeatable no-op."""
    candidates = [
        f for f in list_findings(db) if f.lane in ("1A", "1B") and f.source == "github_commit" and not f.pattern_id
    ]
    extracted: list[Pattern] = []
    for finding in candidates:
        try:
            pattern = await extract_pattern_from_finding(
                finding, db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model,
                library_path=library_path, dry_run=dry_run,
            )
        except Exception as exc:
            console.print(f"[yellow]warning:[/yellow] pattern extraction failed for finding {finding.id[:12]}: {exc}")
            continue
        if pattern:
            extracted.append(pattern)
    return extracted
