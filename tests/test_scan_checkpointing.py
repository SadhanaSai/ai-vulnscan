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
from hunter import scanner
from patterns import extractor
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


# --- run_pattern_extraction(run_id=...) ---------------------------------------


def _commit_finding(**overrides) -> db.Finding:
    defaults = dict(
        id="f1",
        package="somepkg",
        ecosystem="pypi",
        layer="mcp",
        source="github_commit",
        signal_url="https://github.com/org/repo/commit/abcdef1234567890",
        summary="fix: sanitize path input",
        lane="1B",
        cwe=["CWE-22"],
    )
    defaults.update(overrides)
    return db.Finding(**defaults)


@pytest.mark.asyncio
async def test_pattern_extraction_checkpoints_each_package(tmp_path, monkeypatch):
    # Note: the real extract_pattern_from_finding() signature names its DB
    # handle `db` too, shadowing the module-level `db` import inside this
    # fake's own body — use extractor.Pattern (not db.Pattern) to build the
    # return value here.
    async def fake_extract(finding, *, db, github_token, llm_provider=None, llm_model=None, library_path=None, dry_run=False):
        return extractor.Pattern(id="MCP-X-001", vulnerability_class="x", source_finding_id=finding.id)

    monkeypatch.setattr(extractor, "extract_pattern_from_finding", fake_extract)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    db.upsert_finding(database, _commit_finding(id="f1", package="somepkg"))

    extracted = await extractor.run_pattern_extraction(db=database, github_token="tok", run_id=run.id)

    assert len(extracted) == 1
    progress = db.list_scan_progress(database, run.id)
    assert len(progress) == 1
    assert progress[0].package == "somepkg"
    assert progress[0].phase == "pattern_extraction"
    assert progress[0].status == "done"
    assert progress[0].findings_new == 1  # one pattern extracted for this package


@pytest.mark.asyncio
async def test_pattern_extraction_package_level_failure_is_isolated(tmp_path, monkeypatch):
    async def flaky_extract(finding, *, db, github_token, llm_provider=None, llm_model=None, library_path=None, dry_run=False):
        if finding.package == "bad-pkg":
            raise ConnectionError("simulated failure")
        return None

    monkeypatch.setattr(extractor, "extract_pattern_from_finding", flaky_extract)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    db.upsert_finding(database, _commit_finding(id="f-bad", package="bad-pkg"))
    db.upsert_finding(database, _commit_finding(id="f-good", package="good-pkg", signal_url="https://github.com/org/repo/commit/1111111111111111"))

    await extractor.run_pattern_extraction(db=database, github_token="tok", run_id=run.id)

    progress = {p.package: p for p in db.list_scan_progress(database, run.id)}
    assert progress["bad-pkg"].status == "error"
    assert "simulated failure" in progress["bad-pkg"].error
    assert progress["good-pkg"].status == "done"


@pytest.mark.asyncio
async def test_pattern_extraction_without_run_id_writes_no_checkpoints(tmp_path, monkeypatch):
    async def fake_extract(finding, *, db, github_token, llm_provider=None, llm_model=None, library_path=None, dry_run=False):
        return None

    monkeypatch.setattr(extractor, "extract_pattern_from_finding", fake_extract)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_finding(database, _commit_finding())

    await extractor.run_pattern_extraction(db=database, github_token="tok")

    assert db.list_scan_progress(database, run_id=1) == []


# --- run_pattern_hunt(run_id=...) ----------------------------------------------


def _hunt_pattern(**overrides) -> db.Pattern:
    defaults = dict(id="MCP-PATH-TRAVERSAL-001", vulnerability_class="path_traversal", layer="mcp")
    defaults.update(overrides)
    return db.Pattern(**defaults)


def _hunt_package(name="somepkg", **overrides) -> dict:
    pkg = {"name": name, "ecosystem": "pypi", "layer": "mcp", "repo": "org/repo", "agentic_context": None, "enabled": True}
    pkg.update(overrides)
    return pkg


@pytest.mark.asyncio
async def test_pattern_hunt_checkpoints_each_touched_package(tmp_path, monkeypatch):
    async def fake_hunt_in_package(pattern, pkg, **kwargs):
        return []

    monkeypatch.setattr(scanner, "hunt_pattern_in_package", fake_hunt_in_package)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    packages = [_hunt_package(name="somepkg")]

    await scanner.run_pattern_hunt(packages, [_hunt_pattern()], db=database, github_token="tok", run_id=run.id)

    progress = db.list_scan_progress(database, run.id)
    assert len(progress) == 1
    assert progress[0].package == "somepkg"
    assert progress[0].phase == "pattern_hunt"
    assert progress[0].status == "done"


@pytest.mark.asyncio
async def test_pattern_hunt_package_level_failure_is_isolated(tmp_path, monkeypatch):
    """One package's hunt_pattern_in_package raising must not abort the
    gather for the other in-flight package — same guarantee as
    known_cve.py/pre_cve.py's per-package isolation."""

    async def flaky_hunt_in_package(pattern, pkg, **kwargs):
        if pkg["name"] == "bad-pkg":
            raise ConnectionError("simulated clone failure")
        return []

    monkeypatch.setattr(scanner, "hunt_pattern_in_package", flaky_hunt_in_package)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    packages = [_hunt_package(name="bad-pkg"), _hunt_package(name="good-pkg")]

    result = await scanner.run_pattern_hunt(packages, [_hunt_pattern()], db=database, github_token="tok", run_id=run.id)

    assert result.scans_run == 1  # only the successful package counted
    progress = {p.package: p for p in db.list_scan_progress(database, run.id)}
    assert progress["bad-pkg"].status == "error"
    assert "simulated clone failure" in progress["bad-pkg"].error
    assert progress["good-pkg"].status == "done"


@pytest.mark.asyncio
async def test_pattern_hunt_checkpoints_sibling_triggered_package(tmp_path, monkeypatch):
    """A package only reached via the §8.5 Step 3 sibling-scan trigger
    (never in the pattern's initial `applicable` list) still gets its own
    checkpoint row."""

    async def fake_hunt_in_package(pattern, pkg, **kwargs):
        result = kwargs["result"]
        if pkg["name"] == "origin-pkg":
            finding = db.Finding(id="f1", package=pkg["name"], ecosystem="pypi", layer="mcp", source="pattern_hunt", lane="1A")
            return [finding]
        return []

    monkeypatch.setattr(scanner, "hunt_pattern_in_package", fake_hunt_in_package)

    database = db.get_db(tmp_path / "test.db")
    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=2))
    packages = [_hunt_package(name="origin-pkg", layer="mcp"), _hunt_package(name="sibling-pkg", layer="mcp")]

    await scanner.run_pattern_hunt(packages, [_hunt_pattern(layer="mcp")], db=database, github_token="tok", run_id=run.id)

    progress = {p.package: p for p in db.list_scan_progress(database, run.id)}
    assert set(progress) == {"origin-pkg", "sibling-pkg"}
    assert progress["sibling-pkg"].status == "done"


@pytest.mark.asyncio
async def test_pattern_hunt_without_run_id_writes_no_checkpoints(tmp_path, monkeypatch):
    async def fake_hunt_in_package(pattern, pkg, **kwargs):
        return []

    monkeypatch.setattr(scanner, "hunt_pattern_in_package", fake_hunt_in_package)

    database = db.get_db(tmp_path / "test.db")
    await scanner.run_pattern_hunt([_hunt_package()], [_hunt_pattern()], db=database, github_token="tok")

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


def test_scan_status_shows_pattern_extraction_and_pattern_hunt_phases(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)

    run = db.start_scan_run(database, db.ScanRun(mode="scan", packages_total=1))
    db.record_scan_progress(database, db.ScanProgress(run_id=run.id, package="somepkg", phase="pattern_hunt", status="done"))
    db.record_scan_progress(
        database, db.ScanProgress(run_id=run.id, package="otherpkg", phase="pattern_extraction", status="error", error="boom")
    )
    db.finish_scan_run(database, run.id, status="complete")

    result = CliRunner().invoke(main_module.cli, ["scan-status"])
    assert result.exit_code == 0
    assert "pattern_hunt: 1 done, 0 errored" in result.output
    assert "pattern_extraction: 0 package(s) done, 1 errored" in result.output
    assert "otherpkg" in result.output  # shows up in the Errored packages table too


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
