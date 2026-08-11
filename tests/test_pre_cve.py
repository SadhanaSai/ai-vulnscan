"""Tests for pipelines/pre_cve.py — cve-agent-spec.md §8.2 (full pipeline: Phase 2
commits + Phase 3 issues/PRs/HackerNews/dependency cross-reference + watch queue).

No real network calls: search_commits/cross_check_existing_cve/triage_signal
(and the Phase 3 signal sources, stubbed empty by default below) are
monkeypatched at the names pre_cve imported them under, same pattern as
tests/test_known_cve.py's pipeline tests.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from pipelines import pre_cve
from state import db

# Captured at import time, before any test's autouse fixture runs, so unit
# tests exercising these functions directly can bypass the stub below
# (monkeypatch.setattr on the pre_cve module attribute doesn't affect a
# reference already held here).
_real_search_security_issues = pre_cve.search_security_issues
_real_search_security_prs = pre_cve.search_security_prs
_real_search_hackernews = pre_cve.search_hackernews
_real_scan_dependency_exposure = pre_cve.scan_dependency_exposure


@pytest.fixture(autouse=True)
def _stub_phase3_signal_sources(monkeypatch):
    """Existing commit-only tests shouldn't need to know about the Phase 3
    signal sources — default them to empty so run_pre_cve_pipeline exercises
    only what each test actually sets up. Tests targeting these sources
    directly use the _real_* references above instead of pre_cve.<name>."""

    async def _empty(*args, **kwargs):
        return []

    monkeypatch.setattr(pre_cve, "search_security_issues", _empty)
    monkeypatch.setattr(pre_cve, "search_security_prs", _empty)
    monkeypatch.setattr(pre_cve, "search_hackernews", _empty)
    monkeypatch.setattr(pre_cve, "scan_dependency_exposure", _empty)


def _commit_item(sha: str, message: str = "fix: sanitize path input") -> dict:
    return {
        "sha": sha,
        "html_url": f"https://github.com/org/repo/commit/{sha}",
        "commit": {"message": message},
    }


def _issue_item(number: int, title: str = "Path traversal in file loader", body: str = "details here") -> dict:
    return {
        "number": number,
        "html_url": f"https://github.com/org/repo/issues/{number}",
        "title": title,
        "body": body,
    }


def _hn_hit(object_id: str = "12345", title: str = "somepkg vulnerability disclosed") -> dict:
    return {"objectID": object_id, "title": title, "story_text": None, "url": "https://example.com/story"}


def _package(name="somepkg", **overrides) -> dict:
    pkg = {
        "name": name,
        "ecosystem": "pypi",
        "layer": "mcp",
        "repo": "org/repo",
        "agentic_context": "used as a tool server",
        "enabled": True,
    }
    pkg.update(overrides)
    return pkg


# --- keyword batching / query building --------------------------------------


def test_keyword_batches_cover_all_keywords_within_operator_limit():
    batches = pre_cve._keyword_batches()
    # flatten back out and compare against the source list, order preserved
    assert [kw for batch in batches for kw in batch] == pre_cve.SECURITY_KEYWORDS
    for batch in batches:
        assert len(batch) <= pre_cve._MAX_KEYWORDS_PER_QUERY  # <=5 OR operators per batch


def test_build_commit_query_quotes_multiword_terms_and_sets_qualifiers():
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    query = pre_cve._build_commit_query("org/repo", since, ["security", "fix injection"])
    assert "repo:org/repo" in query
    assert '"fix injection"' in query
    assert "security" in query
    assert "committer-date:>=2026-01-01T00:00:00Z" in query


@pytest.mark.asyncio
async def test_search_commits_dedupes_shas_across_batches(monkeypatch):
    monkeypatch.setattr(pre_cve, "_keyword_batches", lambda: [["security"], ["escape"]])
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        # both batches happen to surface the same commit — must be deduped
        return httpx.Response(200, json={"items": [_commit_item("sha1")]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = pre_cve.RateLimiter(min_interval=0.0)
    items = await pre_cve.search_commits(
        client, "org/repo", token="x", rate_limiter=limiter, since=datetime.now(timezone.utc)
    )
    await client.aclose()

    assert call_count["n"] == 2
    assert len(items) == 1
    assert items[0]["sha"] == "sha1"


# --- run_pre_cve_pipeline() end-to-end ---------------------------------------


@pytest.mark.asyncio
async def test_pipeline_skips_entirely_without_github_token(tmp_path, monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError("search_commits should not be called without a token")

    monkeypatch.setattr(pre_cve, "search_commits", fail_if_called)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token=None)

    assert result.packages_scanned == 0
    assert result.findings_new == 0


@pytest.mark.asyncio
async def test_pipeline_known_cve_match_writes_known_lane_and_skips_triage(tmp_path, monkeypatch):
    async def fake_search(*args, **kwargs):
        return [_commit_item("sha1")]

    async def fake_crosscheck(*args, **kwargs):
        return "CVE-2024-1234"

    async def fail_triage(*args, **kwargs):
        raise AssertionError("triage_signal should not be called on a known-CVE match")

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fail_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert result.known_cve_matches == 1
    assert result.findings_new == 1
    findings = db.list_findings(database, lane="known")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_pipeline_lane3_is_discarded_not_persisted(tmp_path, monkeypatch):
    async def fake_search(*args, **kwargs):
        return [_commit_item("sha1")]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "3", "summary": "noise", "validation_steps": []}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert result.findings_new == 0
    assert len(db.list_findings(database)) == 0


@pytest.mark.asyncio
async def test_pipeline_lane1b_is_persisted(tmp_path, monkeypatch):
    async def fake_search(*args, **kwargs):
        return [_commit_item("sha1")]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {
            "lane": "1B",
            "summary": "Path traversal fix",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": ["CWE-22"],
            "atlas_technique": None,
            "agentic_uplift": "agent reads arbitrary files",
            "validation_steps": ["1. reproduce", "2. confirm fix"],
        }

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert result.findings_new == 1
    findings = db.list_findings(database, lane="1B")
    assert len(findings) == 1
    assert findings[0].validation_steps == ["1. reproduce", "2. confirm fix"]


@pytest.mark.asyncio
async def test_pipeline_dry_run_does_not_persist(tmp_path, monkeypatch):
    async def fake_search(*args, **kwargs):
        return [_commit_item("sha1")]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "1B", "summary": "x", "validation_steps": ["1. step"]}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok", dry_run=True)

    assert result.findings_new == 1
    assert len(db.list_findings(database)) == 0


@pytest.mark.asyncio
async def test_pipeline_one_failing_commit_does_not_abort_the_rest(tmp_path, monkeypatch):
    """Regression test: a single signal's cross-check/triage failure (LLM
    provider unreachable, etc.) must not crash the whole scan — it's simply
    skipped and retried on the next run."""

    async def fake_search(*args, **kwargs):
        return [_commit_item("bad-sha"), _commit_item("good-sha")]

    call_count = {"n": 0}

    async def flaky_crosscheck(package, ecosystem, *, repo=None, commit_sha=None, version=None, client=None, github_token=None):
        call_count["n"] += 1
        if commit_sha == "bad-sha":
            raise ConnectionError("simulated network failure")
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "1B", "summary": "x", "validation_steps": ["1. step"]}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", flaky_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert result.packages_scanned == 1
    assert result.findings_new == 1  # only the good commit made it through
    findings = db.list_findings(database, lane="1B")
    assert len(findings) == 1
    assert findings[0].signal_url.endswith("good-sha")


@pytest.mark.asyncio
async def test_pipeline_dedups_on_second_run(tmp_path, monkeypatch):
    async def fake_search(*args, **kwargs):
        return [_commit_item("sha1")]

    async def fake_crosscheck(*args, **kwargs):
        return None

    calls = {"n": 0}

    async def fake_triage(*args, **kwargs):
        calls["n"] += 1
        return {"lane": "1B", "summary": "x", "validation_steps": ["1. step"]}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    first = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")
    second = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert first.findings_new == 1
    assert second.findings_new == 0
    assert calls["n"] == 1  # triage never re-invoked for an already-known finding
    assert len(db.list_findings(database)) == 1


@pytest.mark.asyncio
async def test_pipeline_skips_disabled_and_repo_less_packages(tmp_path, monkeypatch):
    called = []

    async def fake_search(client, repo, **kwargs):
        called.append(repo)
        return []

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)

    database = db.get_db(tmp_path / "test.db")
    packages = [
        _package(name="enabled-pkg", repo="org/a", enabled=True),
        _package(name="disabled-pkg", repo="org/b", enabled=False),
        _package(name="no-repo-pkg", repo=None, enabled=True),
    ]
    await pre_cve.run_pre_cve_pipeline(packages, db=database, github_token="tok")

    assert called == ["org/a"]


# --- issue / PR search --------------------------------------------------------


@pytest.mark.asyncio
async def test_search_security_issues_dedupes_by_number_across_queries():
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        # the label:security query and every keyword-batch query happen to
        # surface the same issue — must be deduped by issue number
        return httpx.Response(200, json={"items": [_issue_item(1)]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = pre_cve.RateLimiter(min_interval=0.0)
    items = await _real_search_security_issues(
        client, "org/repo", token="x", rate_limiter=limiter, since=datetime.now(timezone.utc)
    )
    await client.aclose()

    assert call_count["n"] > 1  # label query + keyword batches
    assert len(items) == 1
    assert items[0]["number"] == 1


@pytest.mark.asyncio
async def test_search_security_prs_hits_issue_search_endpoint_with_is_pr():
    seen_queries = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_queries.append(request.url.params["q"])
        return httpx.Response(200, json={"items": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = pre_cve.RateLimiter(min_interval=0.0)
    await _real_search_security_prs(
        client, "org/repo", token="x", rate_limiter=limiter, since=datetime.now(timezone.utc)
    )
    await client.aclose()

    assert seen_queries  # at least one query issued
    assert all("is:pr" in q for q in seen_queries)


# --- HackerNews scan -----------------------------------------------------------


def test_hn_mentions_security_requires_both_package_name_and_security_term():
    hit_both = {"title": "somepkg vulnerability found", "story_text": None}
    hit_pkg_only = {"title": "somepkg 2.0 released", "story_text": None}
    hit_term_only = {"title": "a new RCE vulnerability", "story_text": None}

    assert pre_cve._hn_mentions_security(hit_both, "somepkg") is True
    assert pre_cve._hn_mentions_security(hit_pkg_only, "somepkg") is False
    assert pre_cve._hn_mentions_security(hit_term_only, "somepkg") is False


@pytest.mark.asyncio
async def test_search_hackernews_filters_out_non_security_hits():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "hits": [
                    _hn_hit("1", "somepkg vulnerability disclosed"),
                    {"objectID": "2", "title": "somepkg 3.0 release notes", "story_text": None, "url": "https://x"},
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = pre_cve.RateLimiter(min_interval=0.0)
    hits = await _real_search_hackernews(client, "somepkg", rate_limiter=limiter, since=datetime.now(timezone.utc))
    await client.aclose()

    assert len(hits) == 1
    assert hits[0]["objectID"] == "1"


# --- dependency cross-reference -------------------------------------------------


def test_parse_pypi_requires_skips_extra_gated_deps():
    requires = ["requests>=2.0", 'pytest; extra == "dev"', "pydantic (>=2.0,<3.0)"]
    names = pre_cve._parse_pypi_requires(requires)
    assert names == ["requests", "pydantic"]


@pytest.mark.asyncio
async def test_scan_dependency_exposure_flags_dependency_with_existing_cve(monkeypatch):
    async def fake_fetch_deps(client, package, ecosystem):
        return ["vulnerable-dep", "clean-dep"]

    async def fake_query_osv(client, package, ecosystem):
        if package == "vulnerable-dep":
            return [{"cve_id": "CVE-2024-9999", "summary": "bad stuff", "signal_url": "https://osv.dev/x"}]
        return []

    monkeypatch.setattr(pre_cve, "_fetch_direct_dependencies", fake_fetch_deps)
    monkeypatch.setattr(pre_cve, "query_osv", fake_query_osv)

    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    signals = await _real_scan_dependency_exposure(client, _package())
    await client.aclose()

    assert len(signals) == 1
    assert signals[0]["dependency"] == "vulnerable-dep"
    assert signals[0]["cve_id"] == "CVE-2024-9999"


@pytest.mark.asyncio
async def test_scan_dependency_exposure_keeps_only_most_recently_modified_per_dependency(monkeypatch):
    """A popular dependency can carry years of historical CVEs — only the
    freshest one per dependency should surface as a signal, not all of them
    (regression test for the 4-dep-package -> 41-signal blowup)."""

    async def fake_fetch_deps(client, package, ecosystem):
        return ["chatty-dep"]

    async def fake_query_osv(client, package, ecosystem):
        return [
            {"cve_id": "CVE-2019-0001", "summary": "old", "modified": "2019-01-01T00:00:00Z"},
            {"cve_id": "CVE-2026-0002", "summary": "new", "modified": "2026-06-01T00:00:00Z"},
            {"cve_id": "CVE-2022-0003", "summary": "mid", "modified": "2022-03-01T00:00:00Z"},
        ]

    monkeypatch.setattr(pre_cve, "_fetch_direct_dependencies", fake_fetch_deps)
    monkeypatch.setattr(pre_cve, "query_osv", fake_query_osv)

    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    signals = await _real_scan_dependency_exposure(client, _package())
    await client.aclose()

    assert len(signals) == 1
    assert signals[0]["cve_id"] == "CVE-2026-0002"


# --- pipeline integration for Phase 3 signal types ------------------------------


@pytest.mark.asyncio
async def test_pipeline_persists_issue_signal_and_schedules_watch_queue_on_lane2(tmp_path, monkeypatch):
    async def fake_search_commits(*args, **kwargs):
        return []

    async def fake_search_issues(*args, **kwargs):
        return [_issue_item(7)]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "2", "summary": "ambiguous", "validation_steps": []}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search_commits)
    monkeypatch.setattr(pre_cve, "search_security_issues", fake_search_issues)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert result.findings_new == 1
    findings = db.list_findings(database, lane="2")
    assert len(findings) == 1
    assert findings[0].source == "github_issue"
    # Lane 2 findings must be scheduled onto the watch queue (Phase 3).
    due = db.due_watch_items(database, now="9999-01-01T00:00:00+00:00")
    assert due[0]["finding_id"] == findings[0].id


@pytest.mark.asyncio
async def test_pipeline_persists_dependency_exposure_signal(tmp_path, monkeypatch):
    async def fake_search_commits(*args, **kwargs):
        return []

    async def fake_dep_scan(client, pkg):
        return [{"dependency": "vulnerable-dep", "cve_id": "CVE-2024-1111", "summary": "bad", "signal_url": "https://osv.dev/x"}]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "1B", "summary": "transitive exposure", "validation_steps": ["1. check pinned version"]}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search_commits)
    monkeypatch.setattr(pre_cve, "scan_dependency_exposure", fake_dep_scan)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert result.findings_new == 1
    findings = db.list_findings(database, lane="1B")
    assert len(findings) == 1
    assert findings[0].source == "dependency_cve"


# --- watch queue processing -----------------------------------------------------


def _lane2_finding(package="somepkg", **overrides) -> db.Finding:
    source = overrides.get("source", "github_issue")
    signal_url = overrides.get("signal_url", "https://github.com/org/repo/issues/1")
    # Real findings always get their id from make_finding_id(package, source,
    # signal_url) — build_finding() recomputes it the same way on re-triage,
    # so a re-triaged finding must start with a matching id or the watch-queue
    # "update in place" would silently insert a second row instead.
    f = db.Finding(
        id=db.make_finding_id(package, source, signal_url),
        package=package,
        ecosystem="pypi",
        layer="mcp",
        source=source,
        signal_url=signal_url,
        summary="ambiguous signal",
        lane="2",
        raw_signal="issue body content",
    )
    for k, v in overrides.items():
        setattr(f, k, v)
    return f


@pytest.mark.asyncio
async def test_watch_queue_promotes_to_known_on_fresh_crosscheck_match(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return "CVE-2024-5555"

    async def fail_triage(*args, **kwargs):
        raise AssertionError("triage_signal should not be called on a known-CVE match")

    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fail_triage)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane2_finding()
    db.upsert_finding(database, finding)
    db.schedule_watch_check(database, finding.id, hours=-1)  # already due

    result = await pre_cve.run_watch_queue([_package()], db=database, github_token="tok")

    assert result.promoted == 1
    updated = db.get_finding(database, finding.id)
    assert updated.lane == "known"
    assert updated.cve_id == "CVE-2024-5555"
    assert db.due_watch_items(database, now="9999-01-01T00:00:00+00:00") == []


@pytest.mark.asyncio
async def test_watch_queue_promotes_to_lane1_and_removes_from_queue(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {
            "lane": "1B",
            "summary": "confirmed",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": ["CWE-22"],
            "validation_steps": ["1. reproduce"],
        }

    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane2_finding()
    db.upsert_finding(database, finding)
    db.schedule_watch_check(database, finding.id, hours=-1)

    result = await pre_cve.run_watch_queue([_package()], db=database, github_token="tok")

    assert result.promoted == 1
    updated = db.get_finding(database, finding.id)
    assert updated.lane == "1B"
    assert updated.validation_steps == ["1. reproduce"]
    assert db.due_watch_items(database, now="9999-01-01T00:00:00+00:00") == []


@pytest.mark.asyncio
async def test_watch_queue_still_ambiguous_bumps_check_count_and_stays_queued(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "2", "summary": "still ambiguous", "validation_steps": []}

    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane2_finding()
    db.upsert_finding(database, finding)
    db.schedule_watch_check(database, finding.id, hours=-1)

    result = await pre_cve.run_watch_queue([_package()], db=database, github_token="tok")

    assert result.still_watching == 1
    row = list(database["watch_queue"].rows_where("finding_id = ?", [finding.id]))[0]
    assert row["check_count"] == 1
    updated = db.get_finding(database, finding.id)
    assert updated.lane == "2"


@pytest.mark.asyncio
async def test_watch_queue_lane3_discards_finding_and_queue_entry(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "3", "summary": "noise", "validation_steps": []}

    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane2_finding()
    db.upsert_finding(database, finding)
    db.schedule_watch_check(database, finding.id, hours=-1)

    result = await pre_cve.run_watch_queue([_package()], db=database, github_token="tok")

    assert result.promoted == 1
    assert db.get_finding(database, finding.id) is None
    assert db.due_watch_items(database, now="9999-01-01T00:00:00+00:00") == []
