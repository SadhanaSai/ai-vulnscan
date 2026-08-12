"""Cross-cutting validation_steps enforcement — CLAUDE.md constraint 3:
"Every Lane 1 finding (1A or 1B) must include a validation_steps field...
A finding without validation steps is incomplete. Do not mark it
ready_to_file."

Per-path enforcement (triage re-prompt/downgrade, pattern-hunt re-prompt/
discard) is already covered by tests/test_classifier.py and
tests/test_pattern_hunter.py. This file covers the cross-cutting guarantee:
no finding without validation_steps can reach status="ready_to_file", no
matter which upstream path produced it — and the Finding schema itself
defaults to "missing" (empty list), not "not required".
"""

from __future__ import annotations

import pytest

from output import cve_drafter
from state import db


def test_finding_validation_steps_defaults_to_empty_not_optional():
    """The dataclass default is an empty list, not None — "missing" and
    "not yet checked" must be distinguishable, and every Lane 1 write path
    is expected to fill this in explicitly before persisting."""
    finding = db.Finding(id="f1", package="pkg", ecosystem="pypi", layer="mcp", source="github_commit")
    assert finding.validation_steps == []


@pytest.mark.asyncio
async def test_gate_refuses_to_mark_ready_to_file_without_validation_steps(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fail_draft(*args, **kwargs):
        raise AssertionError("draft_cve must not be called for a finding missing validation_steps")

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fail_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = db.Finding(
        id="f1", package="pkg", ecosystem="pypi", layer="mcp", source="github_commit",
        signal_url="https://github.com/org/repo/commit/abc123", lane="1B", validation_steps=[],
    )
    db.upsert_finding(database, finding)

    result = await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok")

    assert result.status != "ready_to_file"
    stored = db.get_finding(database, finding.id)
    assert stored.status != "ready_to_file"
    assert stored.cve_draft is None


@pytest.mark.asyncio
async def test_gate_proceeds_normally_once_validation_steps_are_populated(tmp_path, monkeypatch):
    async def fake_crosscheck(*args, **kwargs):
        return None

    async def fake_draft(finding, *, llm_provider=None, llm_model=None):
        return "DRAFT"

    monkeypatch.setattr(cve_drafter, "cross_check_existing_cve", fake_crosscheck)
    monkeypatch.setattr(cve_drafter, "draft_cve", fake_draft)

    database = db.get_db(tmp_path / "test.db")
    finding = db.Finding(
        id="f1", package="pkg", ecosystem="pypi", layer="mcp", source="github_commit",
        signal_url="https://github.com/org/repo/commit/abc123", lane="1B",
        validation_steps=["1. clone the repo", "2. reproduce the bug"],
    )
    db.upsert_finding(database, finding)

    result = await cve_drafter.gate_and_draft_finding(finding, db=database, github_token="tok")

    assert result.status == "ready_to_file"


def test_no_ready_to_file_finding_in_db_lacks_validation_steps(tmp_path):
    """DB-level invariant check: scan every status="ready_to_file" finding
    and assert none are missing validation_steps — the property the gate
    above is specifically there to guarantee, checked independently of how
    it got there."""
    database = db.get_db(tmp_path / "test.db")
    good = db.Finding(
        id="good", package="pkg", ecosystem="pypi", layer="mcp", source="github_commit",
        lane="1B", status="ready_to_file", validation_steps=["1. step"],
    )
    db.upsert_finding(database, good)

    ready = db.list_findings(database, status="ready_to_file")
    assert all(f.validation_steps for f in ready)
