"""Tests for patterns/extractor.py — cve-agent-spec.md §8.4 (Phase 4).

No real network calls: fetch_commit_diff/llm.router.complete are
monkeypatched at the names patterns.extractor imported them under, same
pattern as tests/test_pre_cve.py.
"""

from __future__ import annotations

import json

import pytest

from patterns import extractor
from state import db


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


_VALID_LLM_RESPONSE = json.dumps(
    {
        "vulnerability_class": "path_traversal",
        "layer": "mcp",
        "trigger": "unsanitized filename reaches os.path.join",
        "vulnerable_shape": "os.path.join(base, user_input)",
        "safe_shape": "os.path.realpath and prefix check before join",
        "agentic_context": "MCP filesystem tool servers",
        "cwe": ["CWE-22"],
        "atlas_technique": None,
    }
)


# --- pure helpers --------------------------------------------------------------


def test_next_pattern_id_starts_at_one_for_new_prefix():
    assert extractor._next_pattern_id([], "mcp", "path_traversal") == "MCP-PATH-TRAVERSAL-001"


def test_next_pattern_id_increments_within_same_prefix():
    existing = [
        db.Pattern(id="MCP-PATH-TRAVERSAL-001", vulnerability_class="path_traversal"),
        db.Pattern(id="MCP-PATH-TRAVERSAL-003", vulnerability_class="path_traversal"),
    ]
    assert extractor._next_pattern_id(existing, "mcp", "path_traversal") == "MCP-PATH-TRAVERSAL-004"


def test_next_pattern_id_is_independent_per_prefix():
    existing = [db.Pattern(id="MCP-PATH-TRAVERSAL-001", vulnerability_class="path_traversal")]
    assert extractor._next_pattern_id(existing, "sdk", "deserialization") == "SDK-DESERIALIZATION-001"


def test_parse_json_response_rejects_missing_required_fields():
    with pytest.raises(extractor.PatternSchemaError):
        extractor._parse_json_response(json.dumps({"vulnerability_class": "x"}))


def test_parse_json_response_strips_markdown_fences():
    data = extractor._parse_json_response("```json\n" + _VALID_LLM_RESPONSE + "\n```")
    assert data["vulnerability_class"] == "path_traversal"


# --- extract_pattern_from_finding() eligibility gates ---------------------------


@pytest.mark.asyncio
async def test_extract_skips_non_lane1_finding(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding(lane="known")
    result = await extractor.extract_pattern_from_finding(finding, db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_skips_non_commit_source(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding(source="github_issue")
    result = await extractor.extract_pattern_from_finding(finding, db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_skips_finding_that_already_has_a_pattern(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding(pattern_id="MCP-PATH-TRAVERSAL-001")
    result = await extractor.extract_pattern_from_finding(finding, db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_skips_unparseable_signal_url(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding(signal_url="https://github.com/org/repo/issues/1")
    result = await extractor.extract_pattern_from_finding(finding, db=database, github_token="tok")
    assert result is None


# --- extract_pattern_from_finding() happy path ----------------------------------


@pytest.mark.asyncio
async def test_extract_persists_pattern_and_marks_finding(tmp_path, monkeypatch):
    async def fake_fetch_diff(client, repo, sha, *, token):
        return "--- a/foo.py\n+++ b/foo.py\n- os.path.join(base, name)\n+ os.path.realpath(...)\n"

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        return _VALID_LLM_RESPONSE

    monkeypatch.setattr(extractor, "fetch_commit_diff", fake_fetch_diff)
    monkeypatch.setattr(extractor, "complete", fake_complete)
    library_path = tmp_path / "library.json"

    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding()
    db.upsert_finding(database, finding)

    pattern = await extractor.extract_pattern_from_finding(finding, db=database, github_token="tok", library_path=library_path)

    assert pattern is not None
    assert pattern.id == "MCP-PATH-TRAVERSAL-001"
    assert pattern.source_finding_id == finding.id
    assert pattern.confirmed_hits == [finding.id]

    stored = db.get_pattern(database, pattern.id)
    assert stored is not None
    assert stored.vulnerable_shape == "os.path.join(base, user_input)"

    updated_finding = db.get_finding(database, finding.id)
    assert updated_finding.pattern_id == pattern.id

    library = json.loads(library_path.read_text())
    assert len(library) == 1
    assert library[0]["id"] == pattern.id


@pytest.mark.asyncio
async def test_extract_dry_run_does_not_persist(tmp_path, monkeypatch):
    async def fake_fetch_diff(client, repo, sha, *, token):
        return "--- a/foo.py\n+++ b/foo.py\n"

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        return _VALID_LLM_RESPONSE

    monkeypatch.setattr(extractor, "fetch_commit_diff", fake_fetch_diff)
    monkeypatch.setattr(extractor, "complete", fake_complete)
    library_path = tmp_path / "library.json"

    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding()
    db.upsert_finding(database, finding)

    pattern = await extractor.extract_pattern_from_finding(
        finding, db=database, github_token="tok", library_path=library_path, dry_run=True
    )

    assert pattern is not None  # still returned so the caller can inspect/preview it
    assert db.get_pattern(database, pattern.id) is None  # but nothing written
    assert db.get_finding(database, finding.id).pattern_id is None
    assert not library_path.exists()


@pytest.mark.asyncio
async def test_extract_returns_none_when_diff_fetch_fails(tmp_path, monkeypatch):
    async def fake_fetch_diff(client, repo, sha, *, token):
        return ""

    async def fail_complete(*args, **kwargs):
        raise AssertionError("complete() should not be called when the diff fetch fails")

    monkeypatch.setattr(extractor, "fetch_commit_diff", fake_fetch_diff)
    monkeypatch.setattr(extractor, "complete", fail_complete)

    database = db.get_db(tmp_path / "test.db")
    finding = _commit_finding()
    result = await extractor.extract_pattern_from_finding(finding, db=database, github_token="tok")
    assert result is None


# --- run_pattern_extraction() ----------------------------------------------------


@pytest.mark.asyncio
async def test_run_pattern_extraction_only_processes_eligible_findings(tmp_path, monkeypatch):
    calls = []

    async def fake_extract(finding, *, db, github_token, llm_provider=None, llm_model=None, library_path=None, dry_run=False):
        calls.append(finding.id)
        return db_pattern_stub if finding.id == "commit-1b" else None

    db_pattern_stub = db.Pattern(id="MCP-X-001", vulnerability_class="x", source_finding_id="commit-1b")
    monkeypatch.setattr(extractor, "extract_pattern_from_finding", fake_extract)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_finding(database, _commit_finding(id="commit-1b", lane="1B"))
    db.upsert_finding(database, _commit_finding(id="commit-known", lane="known"))
    db.upsert_finding(database, _commit_finding(id="issue-1a", lane="1A", source="github_issue", signal_url="https://github.com/org/repo/issues/2"))
    db.upsert_finding(database, _commit_finding(id="commit-has-pattern", lane="1B", pattern_id="MCP-X-000", signal_url="https://github.com/org/repo/commit/1111111111111111"))

    extracted = await extractor.run_pattern_extraction(db=database, github_token="tok")

    assert calls == ["commit-1b"]
    assert len(extracted) == 1
    assert extracted[0].id == "MCP-X-001"
