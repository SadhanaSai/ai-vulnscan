"""Tests for pipelines/pre_cve.py — cve-agent-spec.md §8.2 (commit scan only; Phase 2).

No real network calls: search_commits/cross_check_existing_cve/triage_signal
are monkeypatched at the names pre_cve imported them under, same pattern as
tests/test_known_cve.py's pipeline tests.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from pipelines import pre_cve
from state import db


def _commit_item(sha: str, message: str = "fix: sanitize path input") -> dict:
    return {
        "sha": sha,
        "html_url": f"https://github.com/org/repo/commit/{sha}",
        "commit": {"message": message},
    }


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
