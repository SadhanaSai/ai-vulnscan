"""Tests for per-package scan checkpointing (state/db.py ScanRun/ScanProgress,
pipelines/known_cve.py + pipelines/pre_cve.py `run_id` param, main.py
`scan-status`). See the "Per-package scan checkpointing" design: `scan`
previously only wrote one `scan_log` row at the very end of the whole run —
if the process died mid-run, nothing was recorded at all. This adds a
checkpoint row per package as it completes (or errors), so a crash only
loses the packages still in flight.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import main as main_module
from pipelines import known_cve, pre_cve
from state import db

# --- state/db.py CRUD round-trip ---------------------------------------------


def test_scan_run_lifecycle(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=3, llm_provider="groq"))
    assert run.id is not None
    assert run.status == "running"

    fetched = db.get_scan_run(database, run.id)
    assert fetched.status == "running"
    assert fetched.packages_total == 3

    db.finish_scan_run(database, run.id, status="complete")
    fetched = db.get_scan_run(database, run.id)
    assert fetched.status == "complete"
    assert fetched.finished_at is not None


def test_latest_scan_run_returns_most_recent(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    second = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    assert db.latest_scan_run(database).id == second.id


def test_latest_scan_run_none_when_no_runs(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    assert db.latest_scan_run(database) is None


def test_record_and_list_scan_progress(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    db.record_scan_progress(
        database, db.ScanProgress(run_id=run.id, package="foo", phase="known_cve", status="done", findings_new=2)
    )
    db.record_scan_progress(
        database, db.ScanProgress(run_id=run.id, package="bar", phase="known_cve", status="error", error="boom")
    )

    progress = db.list_scan_progress(database, run.id)
    assert len(progress) == 2
    by_package = {p.package: p for p in progress}
    assert by_package["foo"].status == "done"
    assert by_package["foo"].findings_new == 2
    assert by_package["bar"].status == "error"
    assert by_package["bar"].error == "boom"


# --- run_known_cve_pipeline(run_id=...) --------------------------------------


@pytest.mark.asyncio
async def test_known_cve_pipeline_checkpoints_each_package(tmp_path, monkeypatch):
    async def fake_osv(client, package, ecosystem):
        return [{"source": "osv", "cve_id": f"CVE-2024-{package}", "summary": "s", "severity": "HIGH", "cvss": 7.1, "cwe": [], "signal_url": "https://x"}]

    async def fake_empty(*args, **kwargs):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_nvd", fake_empty)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_empty)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    packages = [{"name": "somepkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/somepkg", "enabled": True}]

    result = await known_cve.run_known_cve_pipeline(packages, db=database, github_token="x", nvd_api_key=None, run_id=run.id)

    assert result.packages_scanned == 1
    progress = db.list_scan_progress(database, run.id)
    assert len(progress) == 1
    assert progress[0].package == "somepkg"
    assert progress[0].phase == "known_cve"
    assert progress[0].status == "done"
    assert progress[0].findings_new == 1


@pytest.mark.asyncio
async def test_known_cve_pipeline_one_package_failure_is_isolated(tmp_path, monkeypatch):
    """One package's query raising must not abort the whole gather — it
    should get an 'error' checkpoint, other packages still get 'done'."""

    async def flaky_osv(client, package, ecosystem):
        if package == "bad-pkg":
            raise ConnectionError("simulated failure")
        return [{"source": "osv", "cve_id": "CVE-2024-good", "summary": "s", "severity": None, "cvss": None, "cwe": [], "signal_url": "https://x"}]

    async def fake_empty(*args, **kwargs):
        return []

    monkeypatch.setattr(known_cve, "query_osv", flaky_osv)
    monkeypatch.setattr(known_cve, "query_nvd", fake_empty)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_empty)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    packages = [
        {"name": "bad-pkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/bad", "enabled": True},
        {"name": "good-pkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/good", "enabled": True},
    ]

    result = await known_cve.run_known_cve_pipeline(packages, db=database, github_token="x", nvd_api_key=None, run_id=run.id)

    # Only the successful package counted.
    assert result.packages_scanned == 1
    progress = {p.package: p for p in db.list_scan_progress(database, run.id)}
    assert progress["bad-pkg"].status == "error"
    assert "simulated failure" in progress["bad-pkg"].error
    assert progress["good-pkg"].status == "done"
    assert progress["good-pkg"].findings_new == 1


@pytest.mark.asyncio
async def test_known_cve_pipeline_without_run_id_writes_no_checkpoints(tmp_path, monkeypatch):
    """Backward compatibility: run_id defaults to None, so existing callers
    (and existing tests) that don't pass it get no checkpoint writes."""

    async def fake_osv(client, package, ecosystem):
        return [{"source": "osv", "cve_id": "CVE-2024-x", "summary": "s", "severity": None, "cvss": None, "cwe": [], "signal_url": "https://x"}]

    async def fake_empty(*args, **kwargs):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_nvd", fake_empty)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_empty)

    database = db.get_db(tmp_path / "test.db")
    packages = [{"name": "somepkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/somepkg", "enabled": True}]

    await known_cve.run_known_cve_pipeline(packages, db=database, github_token="x", nvd_api_key=None)

    assert db.list_scan_progress(database, run_id=1) == []


# --- run_pre_cve_pipeline(run_id=...) ----------------------------------------


def _package(name="somepkg", **overrides) -> dict:
    pkg = {"name": name, "ecosystem": "pypi", "layer": "mcp", "repo": "org/repo", "agentic_context": "ctx", "enabled": True}
    pkg.update(overrides)
    return pkg


def _commit_item(sha: str) -> dict:
    return {"sha": sha, "html_url": f"https://github.com/org/repo/commit/{sha}", "commit": {"message": "fix: sanitize input"}}


@pytest.fixture(autouse=True)
def _stub_phase3_signal_sources(monkeypatch):
    async def _empty(*args, **kwargs):
        return []

    monkeypatch.setattr(pre_cve, "search_security_issues", _empty)
    monkeypatch.setattr(pre_cve, "search_security_prs", _empty)
    monkeypatch.setattr(pre_cve, "search_hackernews", _empty)
    monkeypatch.setattr(pre_cve, "scan_dependency_exposure", _empty)


@pytest.mark.asyncio
async def test_pre_cve_pipeline_checkpoints_with_correct_findings_count(tmp_path, monkeypatch):
    async def fake_search(*args, **kwargs):
        return [_commit_item("sha1"), _commit_item("sha2")]

    call_n = {"n": 0}

    async def fake_crosscheck(*args, **kwargs):
        call_n["n"] += 1
        # First commit already has a CVE (persisted, known-CVE branch);
        # second is a genuinely new pre-CVE signal (goes through triage).
        return "CVE-2024-9999" if call_n["n"] == 1 else None

    async def fake_triage(*args, **kwargs):
        return {"lane": "1B", "summary": "x", "validation_steps": ["1. step"]}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))

    result = await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok", run_id=run.id)

    assert result.findings_new == 2
    progress = db.list_scan_progress(database, run.id)
    assert len(progress) == 1
    assert progress[0].package == "somepkg"
    assert progress[0].phase == "pre_cve"
    assert progress[0].status == "done"
    assert progress[0].findings_new == 2  # both signals persisted


@pytest.mark.asyncio
async def test_pre_cve_pipeline_package_level_failure_is_isolated(tmp_path, monkeypatch):
    """search_commits itself raising (not a per-item failure — those are
    already guarded by _guarded()) must not abort the other package."""

    async def flaky_search(client, repo, *, token, rate_limiter, since):
        if repo == "org/bad":
            raise ConnectionError("simulated search failure")
        return [_commit_item("sha1")]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "1B", "summary": "x", "validation_steps": ["1. step"]}

    monkeypatch.setattr(pre_cve, "search_commits", flaky_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    packages = [_package(name="bad-pkg", repo="org/bad"), _package(name="good-pkg", repo="org/good")]

    result = await pre_cve.run_pre_cve_pipeline(packages, db=database, github_token="tok", run_id=run.id)

    assert result.packages_scanned == 1
    progress = {p.package: p for p in db.list_scan_progress(database, run.id)}
    assert progress["bad-pkg"].status == "error"
    assert "simulated search failure" in progress["bad-pkg"].error
    assert progress["good-pkg"].status == "done"
    assert progress["good-pkg"].findings_new == 1


@pytest.mark.asyncio
async def test_pre_cve_pipeline_concurrent_packages_have_accurate_counts(tmp_path, monkeypatch):
    """Regression guard for the race a naive `before/after` snapshot of the
    shared result.findings_new counter would hit under concurrency=4: each
    package's checkpoint count must reflect only its own findings, not
    whatever other concurrently-running packages incremented in between."""

    async def fake_search(client, repo, *, token, rate_limiter, since):
        # org/a produces 2 new signals, org/b produces 1.
        return [_commit_item("sha1"), _commit_item("sha2")] if repo == "org/a" else [_commit_item("sha3")]

    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_triage(*args, **kwargs):
        return {"lane": "1B", "summary": "x", "validation_steps": ["1. step"]}

    monkeypatch.setattr(pre_cve, "search_commits", fake_search)
    monkeypatch.setattr(pre_cve, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(pre_cve, "triage_signal", fake_triage)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    packages = [_package(name="pkg-a", repo="org/a"), _package(name="pkg-b", repo="org/b")]

    await pre_cve.run_pre_cve_pipeline(packages, db=database, github_token="tok", run_id=run.id, concurrency=4)

    progress = {p.package: p for p in db.list_scan_progress(database, run.id)}
    assert progress["pkg-a"].findings_new == 2
    assert progress["pkg-b"].findings_new == 1


@pytest.mark.asyncio
async def test_pre_cve_pipeline_without_run_id_writes_no_checkpoints(tmp_path, monkeypatch):
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
    await pre_cve.run_pre_cve_pipeline([_package()], db=database, github_token="tok")

    assert db.list_scan_progress(database, run_id=1) == []


# --- main.py scan-status (CliRunner) -----------------------------------------


def test_scan_status_no_runs_yet(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)

    result = CliRunner().invoke(main_module.cli, ["scan-status"])
    assert result.exit_code == 0
    assert "No scan runs recorded yet" in result.output


def test_scan_status_shows_latest_run_with_mixed_done_and_error(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)

    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2, llm_provider="groq"))
    db.record_scan_progress(database, db.ScanProgress(run_id=run.id, package="foo", phase="known_cve", status="done", findings_new=3))
    db.record_scan_progress(database, db.ScanProgress(run_id=run.id, package="bar", phase="known_cve", status="error", error="boom"))
    db.finish_scan_run(database, run.id, status="failed")

    result = CliRunner().invoke(main_module.cli, ["scan-status"])
    assert result.exit_code == 0
    assert f"Run #{run.id}" in result.output
    assert "failed" in result.output
    assert "1 done, 1 errored" in result.output
    assert "bar" in result.output
    assert "boom" in result.output


def test_scan_status_with_explicit_run_id_targets_older_run(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)

    first = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    db.finish_scan_run(database, first.id, status="complete")
    second = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    db.finish_scan_run(database, second.id, status="complete")

    result = CliRunner().invoke(main_module.cli, ["scan-status", "--run-id", str(first.id)])
    assert result.exit_code == 0
    assert f"Run #{first.id}" in result.output
    assert f"Run #{second.id}" not in result.output
