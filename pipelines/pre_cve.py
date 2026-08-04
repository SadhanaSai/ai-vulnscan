"""Pre-CVE commit scanner — cve-agent-spec.md §8.2 (commit scan only; Phase 2).

For each watchlist package's repo: search recent commits for security-
relevant keywords, cross-check each hit against the CVE registries (§8.2a,
`cross_check_existing_cve()`) before anything reaches the LLM, and triage
whatever's left via `triage/classifier.py`. Issue/PR/HN scanning and the
dependency cross-reference are Phase 3+ — not implemented here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from pipelines.http_utils import RateLimiter, console, request_with_retry
from pipelines.known_cve import cross_check_existing_cve
from state.db import Finding, make_finding_id, now_iso, upsert_finding
from triage.classifier import build_finding, triage_signal

COMMIT_SEARCH_URL = "https://api.github.com/search/commits"

SECURITY_KEYWORDS = [
    "fix injection",
    "sanitize input",
    "path traversal",
    "escape",
    "validate",
    "security",
    "arbitrary",
    "RCE",
    "XSS",
    "SQLi",
    "deserialization",
]

DEFAULT_LOOKBACK_HOURS = 72
MAX_COMMIT_SIGNALS_PER_PACKAGE = 25  # keeps triage LLM cost bounded per run

# GitHub's search API rejects a query with more than 5 AND/OR/NOT operators
# ("422 More than five AND / OR / NOT operators were used"), so the 11
# security keywords can't fit in one OR'd query — split into batches of 6
# (5 ORs each) and issue one search per batch, deduped by commit sha.
_MAX_KEYWORDS_PER_QUERY = 6


def _keyword_batches() -> list[list[str]]:
    return [SECURITY_KEYWORDS[i : i + _MAX_KEYWORDS_PER_QUERY] for i in range(0, len(SECURITY_KEYWORDS), _MAX_KEYWORDS_PER_QUERY)]


def _build_commit_query(repo: str, since: datetime, keywords: list[str]) -> str:
    terms = " OR ".join(f'"{kw}"' if " " in kw else kw for kw in keywords)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"repo:{repo} ({terms}) committer-date:>={since_str}"


async def search_commits(
    client: httpx.AsyncClient,
    repo: str,
    *,
    token: str,
    rate_limiter: RateLimiter,
    since: datetime,
) -> list[dict[str, Any]]:
    """GitHub commit search — cve-agent-spec.md §8.2. Requires a token; the
    Search API's commit endpoint doesn't serve unauthenticated requests."""
    seen_shas: set[str] = set()
    items: list[dict[str, Any]] = []
    for keywords in _keyword_batches():
        await rate_limiter.wait()
        resp = await request_with_retry(
            client,
            "GET",
            COMMIT_SEARCH_URL,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            params={"q": _build_commit_query(repo, since, keywords), "per_page": MAX_COMMIT_SIGNALS_PER_PACKAGE},
        )
        if resp is None:
            continue
        for item in resp.json().get("items", []):
            sha = item.get("sha")
            if sha and sha not in seen_shas:
                seen_shas.add(sha)
                items.append(item)
    return items


def _commit_to_signal_content(item: dict[str, Any]) -> str:
    message = (item.get("commit") or {}).get("message", "")
    return message.strip()[:2000]


@dataclass
class PreCveScanResult:
    packages_scanned: int = 0
    commits_seen: int = 0
    findings_new: int = 0
    known_cve_matches: int = 0
    llm_calls: int = 0


async def run_pre_cve_pipeline(
    packages: list[dict[str, Any]],
    *,
    db: Any,
    github_token: str | None,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    concurrency: int = 4,
    dry_run: bool = False,
) -> PreCveScanResult:
    result = PreCveScanResult()
    if not github_token:
        console.print(
            "[yellow]warning:[/yellow] GITHUB_TOKEN not set — pre-CVE commit scan skipped "
            "entirely (the commit Search API requires authentication)."
        )
        return result

    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    search_limiter = RateLimiter(min_interval=2.0)  # GitHub Search API: 30 req/min authenticated
    semaphore = asyncio.Semaphore(concurrency)
    # Batch-loaded once, same reasoning as run_known_cve_pipeline(): dedup by
    # finding_id also does double duty as the "already scanned" check, since
    # the lookback window is re-searched in full on every run.
    existing_ids = {row["id"] for row in db["findings"].rows_where(select="id")}

    targets = [p for p in packages if p.get("enabled", True) and p.get("repo")]

    async def process_commit(client: httpx.AsyncClient, pkg: dict[str, Any], item: dict[str, Any]) -> None:
        sha = item.get("sha")
        signal_url = item.get("html_url")
        if not sha or not signal_url:
            return
        finding_id = make_finding_id(pkg["name"], "github_commit", signal_url)
        if finding_id in existing_ids:
            return

        # §8.2a — mandatory, before this signal is allowed anywhere near triage.
        cve_id = await cross_check_existing_cve(
            pkg["name"],
            pkg["ecosystem"],
            repo=pkg["repo"],
            commit_sha=sha,
            client=client,
            github_token=github_token,
        )
        existing_ids.add(finding_id)
        if cve_id:
            result.known_cve_matches += 1
            finding = Finding(
                id=finding_id,
                package=pkg["name"],
                ecosystem=pkg["ecosystem"],
                layer=pkg["layer"],
                source="github_commit",
                signal_url=signal_url,
                summary=(item.get("commit") or {}).get("message", "")[:280],
                lane="known",
                cve_id=cve_id,
                agentic_uplift=pkg.get("agentic_context"),
                last_cve_crosscheck=now_iso(),
            )
            if not dry_run:
                upsert_finding(db, finding)
            result.findings_new += 1
            return

        triage_result = await triage_signal(
            package=pkg["name"],
            layer=pkg["layer"],
            agentic_context=pkg.get("agentic_context"),
            signal_type="commit",
            signal_url=signal_url,
            signal_content=_commit_to_signal_content(item),
            provider=llm_provider,
            model=llm_model,
        )
        result.llm_calls += 1
        if triage_result["lane"] == "3":
            return  # noise — discarded, not persisted (CLAUDE.md lane table)

        finding = build_finding(
            package=pkg["name"],
            ecosystem=pkg["ecosystem"],
            layer=pkg["layer"],
            source="github_commit",
            signal_url=signal_url,
            triage_result=triage_result,
            raw_signal=_commit_to_signal_content(item),
        )
        if not dry_run:
            upsert_finding(db, finding)
        result.findings_new += 1

    async with httpx.AsyncClient(timeout=30.0) as client:

        async def process(pkg: dict[str, Any]) -> None:
            async with semaphore:
                items = await search_commits(
                    client, pkg["repo"], token=github_token, rate_limiter=search_limiter, since=since
                )
                result.commits_seen += len(items)
                for item in items:
                    # A single signal's cross-check/triage failure (LLM
                    # provider unreachable, malformed response, etc.) must
                    # not abort the rest of the scan — it isn't persisted, so
                    # it's simply retried on the next run.
                    try:
                        await process_commit(client, pkg, item)
                    except Exception as exc:
                        console.print(
                            f"[yellow]warning:[/yellow] skipping commit signal "
                            f"{item.get('html_url', item.get('sha', '?'))} for {pkg['name']!r}: {exc}"
                        )

                result.packages_scanned += 1

        await asyncio.gather(*(process(p) for p in targets))

    return result
