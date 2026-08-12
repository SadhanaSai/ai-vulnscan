"""Pattern extractor — cve-agent-spec.md §8.4 (Phase 4).

Two entry points, sharing one diff -> pattern core (`_build_and_persist_pattern`):

- `extract_pattern_from_finding` — Lane 1A/1B findings sourced from a GitHub
  commit (the only pre-CVE signal type that carries a fix-commit URL
  directly). The commit is already known, so this just fetches its diff.
- `extract_pattern_from_known_cve` — known-CVE findings (lane="known").
  These vastly outnumber Lane 1 findings (roughly 16x, in this project's own
  DB) but only ~1% of them have a fix-commit URL captured as their
  signal_url — the rest point at an advisory page instead. This path
  recovers the fix commit a different way: re-query OSV for the affected/
  fixed version range, resolve those versions to git tags, then `git log`
  between the tags filtered to security-relevant commit messages to narrow
  down to the actual fix — same target as the 1A/1B path, found via version
  history instead of an already-known commit URL.

Patterns are stored in the `patterns` SQLite table (state/db.py, the live/
authoritative copy) and exported to patterns/library.json (git-tracked) on
every change.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import httpx

from llm.router import complete
from pipelines.http_utils import console, parse_github_commit_url, request_with_retry
from pipelines.known_cve import query_osv
from pipelines.pre_cve import SECURITY_KEYWORDS
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
TAGS_URL = "https://api.github.com/repos/{repo}/tags"
MAX_DIFF_CHARS = 8000  # bounds LLM prompt cost/context on large diffs
MAX_KNOWN_CVE_EXTRACTIONS_PER_RUN = 15  # known-CVE candidates outnumber 1A/1B ~16x — bound clone+API cost per run

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


async def _build_and_persist_pattern(
    *,
    package: str,
    layer: str | None,
    repo: str,
    commit_sha: str,
    vulnerability_class: str,
    fallback_cwe: list[str],
    source_finding_id: str,
    db: Any,
    github_token: str,
    llm_provider: str | None,
    llm_model: str | None,
    library_path: str | None,
    dry_run: bool,
) -> Pattern | None:
    """Shared core: fetch one commit's diff, extract a pattern from it via
    the LLM, persist it (unless dry_run). Used by both entry points below —
    the only difference between them is *how* they arrive at (repo,
    commit_sha)."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        diff = await fetch_commit_diff(client, repo, commit_sha, token=github_token)
    if not diff:
        return None

    user_prompt = build_user_prompt(package=package, vulnerability_class=vulnerability_class, diff=diff)
    raw = await complete("pattern_extraction", SYSTEM_PROMPT, user_prompt, provider=llm_provider, model=llm_model)
    data = _parse_json_response(raw)

    pattern = Pattern(
        id=_next_pattern_id(list_patterns(db), data.get("layer") or layer, data["vulnerability_class"]),
        vulnerability_class=data["vulnerability_class"],
        layer=data.get("layer") or layer,
        trigger=data["trigger"],
        vulnerable_shape=data["vulnerable_shape"],
        safe_shape=data["safe_shape"],
        agentic_context=data.get("agentic_context"),
        cwe=data.get("cwe") or fallback_cwe or [],
        atlas_technique=data.get("atlas_technique"),
        source_finding_id=source_finding_id,
        source_commit_url=f"https://github.com/{repo}/commit/{commit_sha}",
        confirmed_hits=[source_finding_id],
    )
    if not dry_run:
        upsert_pattern(db, pattern)
        if library_path is None:
            export_pattern_library(db)
        else:
            export_pattern_library(db, library_path)

    return pattern


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

    vulnerability_class = (finding.cwe[0] if finding.cwe else finding.summary) or "unknown"
    pattern = await _build_and_persist_pattern(
        package=finding.package, layer=finding.layer, repo=repo, commit_sha=commit_sha,
        vulnerability_class=vulnerability_class, fallback_cwe=finding.cwe, source_finding_id=finding.id,
        db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model,
        library_path=library_path, dry_run=dry_run,
    )
    if pattern and not dry_run:
        finding.pattern_id = pattern.id
        upsert_finding(db, finding)

    return pattern


# --- known-CVE path: narrow-to-fix-commit via version history ----------------------


async def _resolve_affected_fixed_versions(
    client: httpx.AsyncClient, package: str, ecosystem: str, cve_id: str
) -> tuple[str | None, str | None]:
    """(affected_version, fixed_version) for this specific CVE, from OSV's
    structured affected[].ranges — re-queried fresh rather than reading from
    the Finding, since known-CVE findings don't persist this (same reasoning
    as cross_check_existing_cve() always re-querying).

    OSV events come in two flavors here: `fixed` (the exact version where it
    was patched) or `last_affected` (the last known-vulnerable version, used
    when the advisory doesn't pin down an exact fix version — common in
    practice, not an edge case). When only `last_affected` is present,
    fixed_version comes back None — the caller treats that as "search
    forward to HEAD" instead of to a specific fixed tag."""
    vulns = await query_osv(client, package, ecosystem)
    for v in vulns:
        if v.get("cve_id") != cve_id:
            continue
        for entry in v.get("affected", []):
            for rng in entry.get("ranges", []):
                events = rng.get("events", [])
                introduced = next((e["introduced"] for e in events if "introduced" in e), None)
                introduced = introduced if introduced and introduced != "0" else None
                fixed = next((e["fixed"] for e in events if "fixed" in e), None)
                if fixed:
                    return introduced, fixed
                last_affected = next((e["last_affected"] for e in events if "last_affected" in e), None)
                if last_affected:
                    return last_affected, None
    return None, None


async def _find_matching_tag(client: httpx.AsyncClient, repo: str, version: str, *, token: str) -> str | None:
    """Best-effort version -> git tag resolution. Tries the two overwhelmingly
    common conventions first (`v{version}`, `{version}`), then falls back to
    a substring scan of the repo's most recent 100 tags. Repos with tagging
    conventions further from these (or where the release predates the most
    recent 100 tags) simply won't resolve — that finding is skipped, not
    guessed at."""
    resp = await request_with_retry(
        client, "GET", TAGS_URL.format(repo=repo),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        params={"per_page": 100},
    )
    if resp is None:
        return None
    tag_names = [t["name"] for t in resp.json() if t.get("name")]
    for candidate in (f"v{version}", version):
        if candidate in tag_names:
            return candidate
    normalized_target = version.lstrip("v")
    for name in tag_names:
        normalized_name = name.lstrip("v")
        if normalized_name == normalized_target or normalized_name.endswith(f"-{normalized_target}"):
            return name
    return None


MAX_HEAD_SEARCH_COMMITS = 200  # bounds the "no known fixed tag, search to HEAD" case below


async def _find_fix_commit_via_version_range(
    repo: str, affected_tag: str | None, fixed_tag: str, *, path_prefix: str | None = None
) -> str | None:
    """Clone (full history — `git log` over a tag range needs it, unlike the
    pattern hunter's shallow clones), then narrow the commits between the
    affected and fixed tags to the first one matching a security keyword.
    CLAUDE.md: clone -> read -> delete.

    `fixed_tag == "HEAD"` signals OSV only gave a `last_affected` bound (no
    exact fix version) — in that case, walk forward from the affected tag in
    chronological order (oldest-first, via --reverse) rather than backward
    from HEAD, since the actual fix is more likely soon after the last
    known-bad version than somewhere in the arbitrarily long tail of commits
    since. Capped to MAX_HEAD_SEARCH_COMMITS either way — an unbounded walk
    to HEAD on an active repo could mean thousands of unrelated commits."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="cve-extract-"))
    try:
        clone_proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--quiet", f"https://github.com/{repo}.git", str(tmp_dir),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await clone_proc.communicate()
        if clone_proc.returncode != 0:
            console.print(f"[yellow]warning:[/yellow] git clone failed for {repo}: {stderr.decode(errors='replace')[:200]}")
            return None

        range_spec = f"{affected_tag}..{fixed_tag}" if affected_tag else fixed_tag
        searching_to_head = fixed_tag == "HEAD"
        log_args = ["git", "-C", str(tmp_dir), "log", range_spec, "--oneline", "--no-merges"]
        if searching_to_head:
            log_args.append("--reverse")
        if path_prefix:
            # Monorepo scoping (watchlist.yaml path_prefix) — without this, a
            # commit anywhere in the repo's history can match, including in
            # an entirely unrelated sibling package.
            log_args += ["--", path_prefix]
        log_proc = await asyncio.create_subprocess_exec(
            *log_args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await log_proc.communicate()
        lines = out.decode(errors="replace").splitlines()
        if searching_to_head:
            # Note: intentionally sliced in Python, not via `git log -n`,
            # which combined with --reverse takes the N *newest* commits
            # then reverses just those — not the oldest N in the range.
            lines = lines[:MAX_HEAD_SEARCH_COMMITS]

        lowered_keywords = [k.lower() for k in SECURITY_KEYWORDS]
        for line in lines:
            sha, _, message = line.partition(" ")
            if any(kw in message.lower() for kw in lowered_keywords):
                return sha
        return None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def extract_pattern_from_known_cve(
    finding: Finding,
    *,
    repo: str,
    path_prefix: str | None = None,
    db: Any,
    github_token: str,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    library_path: str | None = None,
    dry_run: bool = False,
) -> Pattern | None:
    """Known-CVE counterpart to extract_pattern_from_finding(). `repo` must
    be resolved by the caller (a known-CVE Finding doesn't carry its repo —
    only package/ecosystem — so this needs a watchlist lookup upstream).
    Returns None if not eligible, or if any resolution step (version range,
    tag, fix commit) comes up empty — no guessing."""
    if finding.lane != "known" or not finding.cve_id or finding.pattern_id:
        return None

    async with httpx.AsyncClient(timeout=30.0) as client:
        affected_version, fixed_version = await _resolve_affected_fixed_versions(
            client, finding.package, finding.ecosystem, finding.cve_id
        )
        if not affected_version and not fixed_version:
            return None

        # affected_version is required to anchor the search window — without
        # it we'd either need a fixed_tag with no lower bound (git log
        # <tag> alone means "everything reachable from tag", not a narrow
        # window) or search all of history to HEAD, neither of which is
        # precise enough to trust the "first keyword match" heuristic.
        if not affected_version:
            return None
        affected_tag = await _find_matching_tag(client, repo, affected_version, token=github_token)
        if affected_tag is None:
            return None

        if fixed_version:
            fixed_tag = await _find_matching_tag(client, repo, fixed_version, token=github_token)
            if fixed_tag is None:
                return None
        else:
            fixed_tag = "HEAD"  # OSV only gave last_affected — search forward, bounded (see _find_fix_commit_via_version_range)

    commit_sha = await _find_fix_commit_via_version_range(repo, affected_tag, fixed_tag, path_prefix=path_prefix)
    if commit_sha is None:
        return None

    vulnerability_class = (finding.cwe[0] if finding.cwe else finding.summary) or "unknown"
    pattern = await _build_and_persist_pattern(
        package=finding.package, layer=finding.layer, repo=repo, commit_sha=commit_sha,
        vulnerability_class=vulnerability_class, fallback_cwe=finding.cwe, source_finding_id=finding.id,
        db=db, github_token=github_token, llm_provider=llm_provider, llm_model=llm_model,
        library_path=library_path, dry_run=dry_run,
    )
    if pattern and not dry_run:
        finding.pattern_id = pattern.id
        upsert_finding(db, finding)

    return pattern


async def run_pattern_extraction(
    *,
    db: Any,
    github_token: str,
    package_to_repo: dict[str, str] | None = None,
    package_to_path_prefix: dict[str, str] | None = None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    library_path: str | None = None,
    dry_run: bool = False,
) -> list[Pattern]:
    """Extract patterns for every eligible Lane 1 commit-sourced finding
    that doesn't already have one (cve-agent-spec.md §8.4), plus — if
    `package_to_repo` is given — up to MAX_KNOWN_CVE_EXTRACTIONS_PER_RUN
    known-CVE findings via the narrow-to-fix-commit path, highest CVSS
    first. `package_to_repo` is a watchlist name->repo lookup; known-CVE
    findings don't carry their own repo, so without it that path is skipped
    entirely. `package_to_path_prefix` (watchlist.yaml `path_prefix`, for
    monorepo-hosted packages) is optional and only needed for entries where
    it's actually set — omitted entries get no path scoping, same as before.

    Note: unlike other pipelines, dry_run here doesn't fully "re-run cleanly
    next time" — since nothing is persisted (no pattern_id written back),
    the same candidates will be re-extracted (and re-billed) on the next
    call, dry_run or not. That's intentional: dry_run exists to preview
    cost/output, not to be a free repeatable no-op."""
    all_findings = list_findings(db)
    commit_candidates = [
        f for f in all_findings if f.lane in ("1A", "1B") and f.source == "github_commit" and not f.pattern_id
    ]
    extracted: list[Pattern] = []
    for finding in commit_candidates:
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

    if package_to_repo:
        known_candidates = sorted(
            (f for f in all_findings if f.lane == "known" and f.cve_id and not f.pattern_id and f.package in package_to_repo),
            key=lambda f: -(f.cvss or 0),
        )[:MAX_KNOWN_CVE_EXTRACTIONS_PER_RUN]
        path_prefixes = package_to_path_prefix or {}
        for finding in known_candidates:
            try:
                pattern = await extract_pattern_from_known_cve(
                    finding, repo=package_to_repo[finding.package], path_prefix=path_prefixes.get(finding.package),
                    db=db, github_token=github_token,
                    llm_provider=llm_provider, llm_model=llm_model, library_path=library_path, dry_run=dry_run,
                )
            except Exception as exc:
                console.print(f"[yellow]warning:[/yellow] known-CVE pattern extraction failed for finding {finding.id[:12]}: {exc}")
                continue
            if pattern:
                extracted.append(pattern)

    return extracted
