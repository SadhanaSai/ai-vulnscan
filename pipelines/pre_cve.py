"""Pre-CVE signal pipeline — cve-agent-spec.md §8.2 (full: Phase 2 commits +
Phase 3 issues/PRs/HackerNews/dependency cross-reference + watch queue).

For each watchlist package: search recent commits, security-labeled/titled
issues, and security-flavored PRs on its repo; search HackerNews for stories
mentioning it alongside a security term; and check its direct dependencies
for CVEs already on file. Every signal is cross-checked against the CVE
registries (§8.2a, `cross_check_existing_cve()`) before anything reaches the
LLM, and triaged via `triage/classifier.py`. Lane 2 results are scheduled
onto the watch queue (`state/db.py`); `run_watch_queue()` re-triages queue
items whose 48h re-check is due.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from pipelines.http_utils import RateLimiter, console, request_with_retry
from pipelines.known_cve import cross_check_existing_cve, query_osv
from state.db import (
    Finding,
    ScanProgress,
    bump_watch_check,
    due_watch_items,
    get_finding,
    make_finding_id,
    now_iso,
    record_scan_progress,
    remove_from_watch_queue,
    schedule_watch_check,
    upsert_finding,
)
from triage.classifier import build_finding, triage_signal

COMMIT_SEARCH_URL = "https://api.github.com/search/commits"
ISSUE_SEARCH_URL = "https://api.github.com/search/issues"
HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}/latest"

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

HN_SECURITY_TERMS = ["vulnerability", "cve", "exploit", "rce", "security flaw", "0day", "zero-day"]

DEFAULT_LOOKBACK_HOURS = 72
HN_LOOKBACK_HOURS = 24 * 7  # spec §8.2: HN scan filters to last 7 days
MAX_SIGNALS_PER_QUERY = 25  # keeps triage LLM cost bounded per run
MAX_DEPENDENCIES_CHECKED = 40  # bounds OSV fan-out per package's dependency list

# GitHub's search API rejects a query with more than 5 AND/OR/NOT operators
# ("422 More than five AND / OR / NOT operators were used"), so the 11
# security keywords can't fit in one OR'd query — split into batches of 6
# (5 ORs each) and issue one search per batch, deduped by item id.
_MAX_KEYWORDS_PER_QUERY = 6

_DEP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


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
            params={"q": _build_commit_query(repo, since, keywords), "per_page": MAX_SIGNALS_PER_QUERY},
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


async def _search_issues_endpoint(
    client: httpx.AsyncClient, queries: list[str], *, token: str, rate_limiter: RateLimiter
) -> list[dict[str, Any]]:
    """Shared GET against GitHub's /search/issues endpoint, deduped by
    issue/PR number — used by both the issue scan and the PR scan since
    GitHub serves both through the same search endpoint (`is:issue`/`is:pr`)."""
    seen_numbers: set[int] = set()
    items: list[dict[str, Any]] = []
    for q in queries:
        await rate_limiter.wait()
        resp = await request_with_retry(
            client,
            "GET",
            ISSUE_SEARCH_URL,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            params={"q": q, "per_page": MAX_SIGNALS_PER_QUERY},
        )
        if resp is None:
            continue
        for item in resp.json().get("items", []):
            number = item.get("number")
            if number is not None and number not in seen_numbers:
                seen_numbers.add(number)
                items.append(item)
    return items


async def search_security_issues(
    client: httpx.AsyncClient, repo: str, *, token: str, rate_limiter: RateLimiter, since: datetime
) -> list[dict[str, Any]]:
    """GitHub issue search — cve-agent-spec.md §8.2 issue scan: `label:security`
    issues, plus issues with a security keyword in the title regardless of label."""
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    queries = [f"repo:{repo} is:issue label:security created:>={since_str}"]
    for keywords in _keyword_batches():
        terms = " OR ".join(f'"{kw}"' if " " in kw else kw for kw in keywords)
        queries.append(f"repo:{repo} is:issue in:title ({terms}) created:>={since_str}")
    return await _search_issues_endpoint(client, queries, token=token, rate_limiter=rate_limiter)


async def search_security_prs(
    client: httpx.AsyncClient, repo: str, *, token: str, rate_limiter: RateLimiter, since: datetime
) -> list[dict[str, Any]]:
    """GitHub PR search — cve-agent-spec.md §8.2 PR scan: PRs whose title/body
    matches a security keyword (e.g. adds sanitization/validation/escaping)."""
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    queries = []
    for keywords in _keyword_batches():
        terms = " OR ".join(f'"{kw}"' if " " in kw else kw for kw in keywords)
        queries.append(f"repo:{repo} is:pr ({terms}) created:>={since_str}")
    return await _search_issues_endpoint(client, queries, token=token, rate_limiter=rate_limiter)


def _issue_to_signal_content(item: dict[str, Any]) -> str:
    title = item.get("title", "")
    body = item.get("body") or ""
    return f"{title}\n\n{body}".strip()[:2000]


async def _fetch_commit_files(client: httpx.AsyncClient, repo: str, sha: str, *, token: str) -> list[dict[str, Any]]:
    """For monorepo-hosted packages (watchlist.yaml `path_prefix`) — commit
    search results don't include changed files, so this fetches them
    separately. Without this, a commit search scoped to `repo:{repo}` alone
    can match an unrelated sibling package in the same monorepo (e.g. Azure
    SDK's shared repo) and misattribute it here. Also backs the test-only-
    change detection below (both need the same file list)."""
    resp = await request_with_retry(
        client, "GET", f"https://api.github.com/repos/{repo}/commits/{sha}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
    )
    return resp.json().get("files", []) if resp is not None else []


async def _fetch_pr_files(client: httpx.AsyncClient, repo: str, number: int, *, token: str) -> list[dict[str, Any]]:
    """PR counterpart to _fetch_commit_files() — same reasoning."""
    resp = await request_with_retry(
        client, "GET", f"https://api.github.com/repos/{repo}/pulls/{number}/files",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        params={"per_page": 100},
    )
    return resp.json() if resp is not None else []


def _files_touch_path(files: list[dict[str, Any]], path_prefix: str) -> bool:
    return any(f.get("filename", "").startswith(path_prefix) for f in files)


# A change whose diff is entirely under a test/spec path is weak evidence of
# a live, currently-exploitable vulnerability — it's often either a fix
# regression-guard on code that already behaves safely, or a demonstration
# with no accompanying production fix. Triage was seeing these read as
# strong evidence purely from the PR/commit *prose* (which can talk at
# length about "vulnerabilities" and "probes" while the diff itself touches
# nothing but tests/) — see the langflow SQL-logging false positive this
# guards against. Matches "tests/"/"test/" path segments and common
# test-file-naming conventions (test_x.py, x_test.py, x.test.ts, x.spec.ts).
_TEST_PATH_RE = re.compile(r"(^|/)tests?(/|_|$)|_test\.|\.test\.|\.spec\.", re.IGNORECASE)


def _looks_like_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path))


def _files_are_test_only(files: list[dict[str, Any]]) -> bool:
    return bool(files) and all(_looks_like_test_path(f.get("filename", "")) for f in files)


def _pipeline_verified_context(
    *, files: list[dict[str, Any]] | None = None, pr_merged: bool | None = None
) -> str | None:
    """Facts the pipeline itself fetched and can vouch for — passed to
    triage_signal() separately from the signal's own (untrusted) prose, so
    the LLM can weigh a signal's self-description against what's actually
    true of the change. None of this is optional context for the model to
    take or leave; build_user_prompt() frames it as authoritative."""
    notes: list[str] = []
    if pr_merged is not None:
        notes.append(f"PR merge status: {'merged' if pr_merged else 'still open/unmerged'}.")
    if files:
        test_only = _files_are_test_only(files)
        notes.append(
            f"Changed files ({len(files)}): {', '.join(f.get('filename', '?') for f in files[:15])}"
            f"{' …and more' if len(files) > 15 else ''}. "
            f"{'All changed files are under a test/spec path — this diff does not modify production code.' if test_only else ''}"
        )
    return " ".join(n for n in notes if n) or None


def _issue_mentions_path_component(item: dict[str, Any], path_prefix: str) -> bool:
    """Issues have no "changed files" to check — a lighter heuristic:
    confirm the path_prefix's own directory name (usually the package name)
    appears in the issue text. Weaker than the commit/PR check, but issues
    carry no file-level ground truth to check against at all."""
    component = path_prefix.rstrip("/").rsplit("/", 1)[-1].lower()
    if not component:
        return True
    text = f"{item.get('title', '')} {item.get('body') or ''}".lower()
    return component in text


def _hn_mentions_security(hit: dict[str, Any], package_name: str) -> bool:
    """Algolia's search is relevance-ranked, not a strict boolean filter, so
    confirm the package name and a security term both actually appear before
    treating a hit as a signal — spec §8.2: 'flag stories mentioning the
    package alongside security terms.'"""
    text = f"{hit.get('title', '')} {hit.get('story_text') or ''}".lower()
    if package_name.lower() not in text:
        return False
    return any(term in text for term in HN_SECURITY_TERMS)


def _hn_to_signal_content(hit: dict[str, Any]) -> str:
    title = hit.get("title", "")
    story_text = hit.get("story_text") or ""
    return f"{title}\n\n{story_text}".strip()[:2000]


def _hn_signal_url(hit: dict[str, Any]) -> str:
    object_id = hit.get("objectID")
    return f"https://news.ycombinator.com/item?id={object_id}" if object_id else hit.get("url", "")


async def search_hackernews(
    client: httpx.AsyncClient, package_name: str, *, rate_limiter: RateLimiter, since: datetime
) -> list[dict[str, Any]]:
    """HackerNews Algolia search — cve-agent-spec.md §8.2 HN scan. No auth;
    HN Algolia is a public API. Filtered to the last 7 days per spec."""
    await rate_limiter.wait()
    resp = await request_with_retry(
        client,
        "GET",
        HN_SEARCH_URL,
        params={
            "query": f"{package_name} vulnerability",
            "tags": "story",
            "numericFilters": f"created_at_i>{int(since.timestamp())}",
        },
    )
    if resp is None:
        return []
    hits = resp.json().get("hits", [])
    return [h for h in hits if _hn_mentions_security(h, package_name)]


def _parse_pypi_requires(requires_dist: list[str]) -> list[str]:
    """Direct dependency names from a PyPI `requires_dist` list. Skips
    extra-gated deps (`; extra == "..."`), since those aren't installed by
    default consumers of the package."""
    names = []
    for req in requires_dist:
        if "extra ==" in req:
            continue
        match = _DEP_NAME_RE.match(req.strip())
        if match:
            names.append(match.group(0))
    return names


async def _fetch_direct_dependencies(client: httpx.AsyncClient, package: str, ecosystem: str) -> list[str]:
    """cve-agent-spec.md §8.2 dependency cross-reference: direct dependency
    names only, via the PyPI JSON API or npm registry (both approved,
    unauthenticated APIs — CLAUDE.md)."""
    if ecosystem == "pypi":
        resp = await request_with_retry(client, "GET", PYPI_JSON_URL.format(package=package))
        if resp is None:
            return []
        requires = resp.json().get("info", {}).get("requires_dist") or []
        return _parse_pypi_requires(requires)
    if ecosystem == "npm":
        resp = await request_with_retry(client, "GET", NPM_REGISTRY_URL.format(package=package))
        if resp is None:
            return []
        return list((resp.json().get("dependencies") or {}).keys())
    return []


async def scan_dependency_exposure(client: httpx.AsyncClient, pkg: dict[str, Any]) -> list[dict[str, Any]]:
    """cve-agent-spec.md §8.2 dependency cross-reference: a direct dependency
    that already has a CVE is a pre-CVE exposure *signal for the parent*
    package (which may not have updated/pinned around it yet), not a known
    CVE of the parent itself — so these still go through triage rather than
    being written straight to the 'known' lane.

    A popular dependency can carry years of accumulated CVEs — query_osv()
    returns its *entire* history, unfiltered by version. Surfacing all of
    them per dependency would flood triage with mostly-irrelevant old
    advisories (a 4-dependency package can easily produce 40+ hits), so only
    the most-recently-modified advisory per dependency is kept as the signal.
    """
    deps = await _fetch_direct_dependencies(client, pkg["name"], pkg["ecosystem"])
    signals: list[dict[str, Any]] = []
    for dep_name in deps[:MAX_DEPENDENCIES_CHECKED]:
        vulns = [v for v in await query_osv(client, dep_name, pkg["ecosystem"]) if v.get("cve_id")]
        if not vulns:
            continue
        most_recent = max(vulns, key=lambda v: v.get("modified") or "")
        signals.append({"dependency": dep_name, **most_recent})
    return signals


def _dependency_signal_url(pkg: dict[str, Any], signal: dict[str, Any]) -> str:
    return signal.get("signal_url") or f"https://osv.dev/vulnerability/{signal.get('cve_id')}"


def _dependency_signal_content(pkg: dict[str, Any], signal: dict[str, Any]) -> str:
    return (
        f"{pkg['name']} depends directly on {signal['dependency']}, which has an existing "
        f"advisory {signal.get('cve_id')}: {signal.get('summary') or '(no summary available)'}. "
        f"This does not confirm {pkg['name']} itself is exploitable — it depends on which "
        f"version of {signal['dependency']} is pinned/resolved and whether the vulnerable "
        f"code path is reachable through {pkg['name']}'s usage of it."
    )[:2000]


@dataclass
class PreCveScanResult:
    packages_scanned: int = 0
    commits_seen: int = 0
    issues_seen: int = 0
    prs_seen: int = 0
    hn_hits_seen: int = 0
    dependency_signals_seen: int = 0
    findings_new: int = 0
    known_cve_matches: int = 0
    llm_calls: int = 0


@dataclass
class WatchScanResult:
    items_checked: int = 0
    promoted: int = 0
    still_watching: int = 0
    llm_calls: int = 0


async def _guarded(coro: Any, pkg_name: str, description: str) -> bool | None:
    """A single signal's cross-check/triage failure (LLM provider
    unreachable, malformed response, etc.) must not abort the rest of the
    scan — it isn't persisted, so it's simply retried on the next run.
    Returns the wrapped coroutine's result (whether it persisted a new
    finding) on success, or None if it was caught and skipped."""
    try:
        return await coro
    except Exception as exc:
        console.print(f"[yellow]warning:[/yellow] skipping signal {description} for {pkg_name!r}: {exc}")
        return None


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
    run_id: int | None = None,
) -> PreCveScanResult:
    result = PreCveScanResult()
    if not github_token:
        console.print(
            "[yellow]warning:[/yellow] GITHUB_TOKEN not set — pre-CVE signal scan skipped "
            "entirely (the commit/issue/PR Search API requires authentication)."
        )
        return result

    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    hn_since = datetime.now(timezone.utc) - timedelta(hours=HN_LOOKBACK_HOURS)
    search_limiter = RateLimiter(min_interval=2.0)  # GitHub Search API: 30 req/min authenticated
    hn_limiter = RateLimiter(min_interval=0.5)  # HN Algolia — generous public limits, still polite
    semaphore = asyncio.Semaphore(concurrency)
    # Batch-loaded once, same reasoning as run_known_cve_pipeline(): dedup by
    # finding_id also does double duty as the "already scanned" check, since
    # the lookback window is re-searched in full on every run.
    existing_ids = {row["id"] for row in db["findings"].rows_where(select="id")}

    targets = [p for p in packages if p.get("enabled", True) and p.get("repo")]

    async def handle_signal(
        client: httpx.AsyncClient,
        pkg: dict[str, Any],
        *,
        source: str,
        signal_url: str,
        summary_text: str,
        signal_type: str,
        signal_content: str,
        commit_sha: str | None = None,
        extra_context: str | None = None,
    ) -> bool:
        """Returns True iff a new finding was persisted — lets callers count
        per-package findings without racing the shared result.findings_new
        counter across concurrently-running packages."""
        finding_id = make_finding_id(pkg["name"], source, signal_url)
        if finding_id in existing_ids:
            return False

        # §8.2a — mandatory, before this signal is allowed anywhere near triage.
        cve_id = await cross_check_existing_cve(
            pkg["name"],
            pkg["ecosystem"],
            repo=pkg["repo"],
            commit_sha=commit_sha,
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
                source=source,
                signal_url=signal_url,
                summary=summary_text[:280],
                lane="known",
                cve_id=cve_id,
                agentic_uplift=pkg.get("agentic_context"),
                last_cve_crosscheck=now_iso(),
            )
            if not dry_run:
                upsert_finding(db, finding)
            result.findings_new += 1
            return True

        triage_result = await triage_signal(
            package=pkg["name"],
            layer=pkg["layer"],
            agentic_context=pkg.get("agentic_context"),
            signal_type=signal_type,
            signal_url=signal_url,
            signal_content=signal_content,
            extra_context=extra_context,
            provider=llm_provider,
            model=llm_model,
        )
        result.llm_calls += 1
        if triage_result["lane"] == "3":
            return False  # noise — discarded, not persisted (CLAUDE.md lane table)

        finding = build_finding(
            package=pkg["name"],
            ecosystem=pkg["ecosystem"],
            layer=pkg["layer"],
            source=source,
            signal_url=signal_url,
            triage_result=triage_result,
            raw_signal=signal_content,
        )
        if not dry_run:
            upsert_finding(db, finding)
            if finding.lane == "2":
                schedule_watch_check(db, finding.id)
        result.findings_new += 1
        return True

    async def process_commit(client: httpx.AsyncClient, pkg: dict[str, Any], item: dict[str, Any]) -> bool:
        sha = item.get("sha")
        signal_url = item.get("html_url")
        if not sha or not signal_url:
            return False
        files = await _fetch_commit_files(client, pkg["repo"], sha, token=github_token)
        path_prefix = pkg.get("path_prefix")
        if path_prefix and not _files_touch_path(files, path_prefix):
            return False
        return await handle_signal(
            client,
            pkg,
            source="github_commit",
            signal_url=signal_url,
            summary_text=(item.get("commit") or {}).get("message", ""),
            signal_type="commit",
            signal_content=_commit_to_signal_content(item),
            commit_sha=sha,
            extra_context=_pipeline_verified_context(files=files),
        )

    async def process_issue(client: httpx.AsyncClient, pkg: dict[str, Any], item: dict[str, Any]) -> bool:
        signal_url = item.get("html_url")
        if not signal_url:
            return False
        path_prefix = pkg.get("path_prefix")
        if path_prefix and not _issue_mentions_path_component(item, path_prefix):
            return False
        return await handle_signal(
            client,
            pkg,
            source="github_issue",
            signal_url=signal_url,
            summary_text=item.get("title", ""),
            signal_type="issue",
            signal_content=_issue_to_signal_content(item),
        )

    async def process_pr(client: httpx.AsyncClient, pkg: dict[str, Any], item: dict[str, Any]) -> bool:
        signal_url = item.get("html_url")
        number = item.get("number")
        if not signal_url or not number:
            return False
        files = await _fetch_pr_files(client, pkg["repo"], number, token=github_token)
        path_prefix = pkg.get("path_prefix")
        if path_prefix and not _files_touch_path(files, path_prefix):
            return False
        pr_merged = (item.get("pull_request") or {}).get("merged_at") is not None
        return await handle_signal(
            client,
            pkg,
            source="github_pr",
            signal_url=signal_url,
            summary_text=item.get("title", ""),
            signal_type="pull_request",
            signal_content=_issue_to_signal_content(item),
            extra_context=_pipeline_verified_context(files=files, pr_merged=pr_merged),
        )

    async def process_hn(client: httpx.AsyncClient, pkg: dict[str, Any], hit: dict[str, Any]) -> bool:
        signal_url = _hn_signal_url(hit)
        if not signal_url:
            return False
        return await handle_signal(
            client,
            pkg,
            source="hackernews",
            signal_url=signal_url,
            summary_text=hit.get("title", ""),
            signal_type="hackernews_story",
            signal_content=_hn_to_signal_content(hit),
        )

    async def process_dependency(client: httpx.AsyncClient, pkg: dict[str, Any], signal: dict[str, Any]) -> bool:
        return await handle_signal(
            client,
            pkg,
            source="dependency_cve",
            signal_url=_dependency_signal_url(pkg, signal),
            summary_text=f"{pkg['name']} depends on {signal['dependency']} ({signal.get('cve_id')})",
            signal_type="dependency_exposure",
            signal_content=_dependency_signal_content(pkg, signal),
        )

    async with httpx.AsyncClient(timeout=30.0) as client:

        async def process(pkg: dict[str, Any]) -> None:
            async with semaphore:
                pkg_new = 0
                try:
                    commit_items = await search_commits(
                        client, pkg["repo"], token=github_token, rate_limiter=search_limiter, since=since
                    )
                    result.commits_seen += len(commit_items)
                    for item in commit_items:
                        if await _guarded(
                            process_commit(client, pkg, item), pkg["name"], item.get("html_url", item.get("sha", "?"))
                        ):
                            pkg_new += 1

                    issue_items = await search_security_issues(
                        client, pkg["repo"], token=github_token, rate_limiter=search_limiter, since=since
                    )
                    result.issues_seen += len(issue_items)
                    for item in issue_items:
                        if await _guarded(process_issue(client, pkg, item), pkg["name"], item.get("html_url", "?")):
                            pkg_new += 1

                    pr_items = await search_security_prs(
                        client, pkg["repo"], token=github_token, rate_limiter=search_limiter, since=since
                    )
                    result.prs_seen += len(pr_items)
                    for item in pr_items:
                        if await _guarded(process_pr(client, pkg, item), pkg["name"], item.get("html_url", "?")):
                            pkg_new += 1

                    hn_hits = await search_hackernews(client, pkg["name"], rate_limiter=hn_limiter, since=hn_since)
                    result.hn_hits_seen += len(hn_hits)
                    for hit in hn_hits:
                        if await _guarded(process_hn(client, pkg, hit), pkg["name"], hit.get("objectID", "?")):
                            pkg_new += 1

                    try:
                        dep_signals = await scan_dependency_exposure(client, pkg)
                    except Exception as exc:
                        console.print(f"[yellow]warning:[/yellow] dependency scan failed for {pkg['name']!r}: {exc}")
                        dep_signals = []
                    result.dependency_signals_seen += len(dep_signals)
                    for sig in dep_signals:
                        if await _guarded(process_dependency(client, pkg, sig), pkg["name"], sig.get("dependency", "?")):
                            pkg_new += 1

                    result.packages_scanned += 1
                except Exception as exc:
                    # Mirrors run_known_cve_pipeline(): one package's unhandled
                    # failure (e.g. search_commits/search_hackernews itself
                    # raising — the per-item _guarded() calls above only cover
                    # per-signal failures, not the search calls themselves)
                    # must not abort asyncio.gather() for the other packages.
                    if run_id is not None and not dry_run:
                        record_scan_progress(
                            db,
                            ScanProgress(
                                run_id=run_id, package=pkg["name"], phase="pre_cve",
                                status="error", error=str(exc)[:500],
                            ),
                        )
                    return
                if run_id is not None and not dry_run:
                    record_scan_progress(
                        db,
                        ScanProgress(
                            run_id=run_id, package=pkg["name"], phase="pre_cve",
                            status="done", findings_new=pkg_new,
                        ),
                    )

        await asyncio.gather(*(process(p) for p in targets))

    return result


async def run_watch_queue(
    packages: list[dict[str, Any]],
    *,
    db: Any,
    github_token: str | None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    dry_run: bool = False,
) -> WatchScanResult:
    """Re-triage Lane 2 findings whose watch_queue re-check is due —
    cve-agent-spec.md §13 Phase 3 ('watch queue daemon'), CLAUDE.md lane
    table (Lane 2: revisit in 48h). Backs `python main.py watch`.

    Every item still runs the mandatory §8.2a cross-check before triage —
    a CVE may have been assigned for this package in the days since it was
    first queued."""
    result = WatchScanResult()
    context_by_name = {p["name"]: p for p in packages}
    due = due_watch_items(db)
    if not due:
        return result

    async with httpx.AsyncClient(timeout=30.0) as client:
        for row in due:
            finding = get_finding(db, row["finding_id"])
            if finding is None or finding.lane != "2":
                # Already promoted/removed by some other path — stale queue entry.
                if not dry_run:
                    remove_from_watch_queue(db, row["finding_id"])
                continue
            result.items_checked += 1
            pkg_context = context_by_name.get(finding.package, {})

            cve_id = await cross_check_existing_cve(
                finding.package, finding.ecosystem, client=client, github_token=github_token
            )
            if cve_id:
                finding.lane = "known"
                finding.cve_id = cve_id
                finding.last_cve_crosscheck = now_iso()
                if not dry_run:
                    upsert_finding(db, finding)
                    remove_from_watch_queue(db, finding.id)
                result.promoted += 1
                continue

            triage_result = await triage_signal(
                package=finding.package,
                layer=finding.layer,
                agentic_context=pkg_context.get("agentic_context"),
                signal_type=(finding.source or "signal").removeprefix("github_"),
                signal_url=finding.signal_url or "",
                signal_content=finding.raw_signal or finding.summary or "",
                provider=llm_provider,
                model=llm_model,
            )
            result.llm_calls += 1
            new_lane = triage_result["lane"]

            if new_lane == "3":
                if not dry_run:
                    remove_from_watch_queue(db, finding.id)
                    db["findings"].delete(finding.id)  # noise — discarded per CLAUDE.md lane table
                result.promoted += 1
                continue

            if new_lane == "2":
                if not dry_run:
                    bump_watch_check(db, finding.id)
                result.still_watching += 1
                continue

            updated = build_finding(
                package=finding.package,
                ecosystem=finding.ecosystem,
                layer=finding.layer,
                source=finding.source,
                signal_url=finding.signal_url,
                triage_result=triage_result,
                raw_signal=finding.raw_signal,
            )
            if not dry_run:
                upsert_finding(db, updated)
                remove_from_watch_queue(db, finding.id)
            result.promoted += 1

    return result
