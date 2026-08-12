"""Tests for output/cve_drafter.py — cve-agent-spec.md §8.6, §12 (Phase 6).

No real network calls: cross_check_existing_cve/llm.router.complete are
monkeypatched, same pattern as tests/test_pre_cve.py.
"""

from __future__ import annotations

import pytest

from output import cve_drafter
from state import db


def _lane1_finding(**overrides) -> db.Finding:
    defaults = dict(
        id="f1",
        package="somepkg",
        ecosystem="pypi",
        layer="mcp",
        source="github_commit",
        signal_url="https://github.com/org/repo/commit/abcdef1234567890",
        summary="Path traversal via unsanitized filename",
        lane="1B",
        severity="HIGH",
        cvss=7.5,
        cwe=["CWE-22"],
        validation_steps=["1. clone the repo", "2. reproduce the bug"],
        status="new",
    )
    defaults.update(overrides)
    return db.Finding(**defaults)


# --- gate_and_draft_finding() ---------------------------------------------------


@pytest.mark.asyncio
async def test_gate_closes_finding_when_fresh_crosscheck_finds_existing_cve(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return "CVE-2024-5555"

    async def fail_draft(*args, **kwargs):
        raise AssertionError("draft_cve should not be called when the gate finds an existing CVE")

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fail_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane1_finding()

    result = await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok")

    assert result.status == "closed"
    assert result.cve_id == "CVE-2024-5555"
    assert result.cve_draft is None
    stored = db.get_finding(database, finding.id)
    assert stored.status == "closed"


@pytest.mark.asyncio
async def test_gate_drafts_and_marks_ready_to_file_on_clean_crosscheck(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_draft(finding, *, llm_provider=None, llm_model=None):
        return "DRAFT TEXT"

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fake_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane1_finding()

    result = await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok")

    assert result.status == "ready_to_file"
    assert result.cve_draft == "DRAFT TEXT"
    assert result.cve_id is None
    stored = db.get_finding(database, finding.id)
    assert stored.status == "ready_to_file"
    assert stored.cve_draft == "DRAFT TEXT"


@pytest.mark.asyncio
async def test_gate_dry_run_does_not_persist_but_still_runs(tmp_path, monkeypatch):
    calls = {"crosscheck": 0}

    async def fake_crosscheck(*args, **kwargs):
        calls["crosscheck"] += 1
        return None

    async def fake_draft(finding, *, llm_provider=None, llm_model=None):
        return "DRAFT TEXT"

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fake_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane1_finding()
    db.upsert_finding(database, finding)

    result = await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok", dry_run=True)

    assert calls["crosscheck"] == 1  # §8.6: dry-run still runs the gate
    assert result.status == "ready_to_file"  # returned object reflects the outcome
    stored = db.get_finding(database, finding.id)
    assert stored.status == "new"  # but nothing was written


@pytest.mark.asyncio
async def test_gate_passes_commit_sha_from_signal_url_for_commit_sourced_findings(tmp_path, monkeypatch):
    seen_kwargs = {}

    async def fake_crosscheck(package, ecosystem, *, commit_sha=None, github_token=None):
        seen_kwargs["commit_sha"] = commit_sha
        return None

    async def fake_draft(finding, *, llm_provider=None, llm_model=None):
        return "DRAFT"

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fake_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane1_finding(signal_url="https://github.com/org/repo/commit/deadbeef1234")

    await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok")

    assert seen_kwargs["commit_sha"] == "deadbeef1234"


@pytest.mark.asyncio
async def test_gate_no_commit_sha_for_non_commit_sourced_findings(tmp_path, monkeypatch):
    seen_kwargs = {}

    async def fake_crosscheck(package, ecosystem, *, commit_sha=None, github_token=None):
        seen_kwargs["commit_sha"] = commit_sha
        return None

    async def fake_draft(finding, *, llm_provider=None, llm_model=None):
        return "DRAFT"

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fake_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = _lane1_finding(source="github_issue", signal_url="https://github.com/org/repo/issues/9")

    await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok")

    assert seen_kwargs["commit_sha"] is None


# --- run_cve_drafting() ----------------------------------------------------------


@pytest.mark.asyncio
async def test_run_cve_drafting_skips_terminal_status_findings(tmp_path, monkeypatch):
    processed = []

    async def fake_gate(finding, *, db, github_token, llm_provider=None, llm_model=None, dry_run=False):
        processed.append(finding.id)
        finding.status = "ready_to_file"
        return finding

    monkeypatch.setattr(cve_drafter, "gate_and_draft_finding", fake_gate)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_finding(database, _lane1_finding(id="new-1b", lane="1B", status="new"))
    db.upsert_finding(database, _lane1_finding(id="already-ready", lane="1A", status="ready_to_file"))
    db.upsert_finding(database, _lane1_finding(id="already-filed", lane="1B", status="filed"))
    db.upsert_finding(database, _lane1_finding(id="already-closed", lane="1A", status="closed"))
    db.upsert_finding(database, _lane1_finding(id="known-lane", lane="known", status="new"))

    updated = await cve_drafter.run_cve_drafting(db=database, github_token="tok")

    assert processed == ["new-1b"]
    assert len(updated) == 1


@pytest.mark.asyncio
async def test_run_cve_drafting_one_failure_does_not_abort_the_rest(tmp_path, monkeypatch):
    async def flaky_gate(finding, *, db, github_token, llm_provider=None, llm_model=None, dry_run=False):
        if finding.id == "bad":
            raise ConnectionError("simulated failure")
        finding.status = "ready_to_file"
        return finding

    monkeypatch.setattr(cve_drafter, "gate_and_draft_finding", flaky_gate)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_finding(database, _lane1_finding(id="bad", lane="1B"))
    db.upsert_finding(database, _lane1_finding(id="good", lane="1B", signal_url="https://github.com/org/repo/commit/1111111111"))

    updated = await cve_drafter.run_cve_drafting(db=database, github_token="tok")

    assert [f.id for f in updated] == ["good"]


# --- draft prompt shape ----------------------------------------------------------


def test_build_user_prompt_includes_key_finding_fields():
    finding = _lane1_finding()
    prompt = cve_drafter.build_user_prompt(finding)
    assert "somepkg" in prompt
    assert "CWE-22" in prompt
    assert "7.5" in prompt
    assert finding.signal_url in prompt
