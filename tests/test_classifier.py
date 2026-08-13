"""Tests for triage/classifier.py — cve-agent-spec.md §8.3, CLAUDE.md "Triage prompt".

No real network calls: llm.router.complete is monkeypatched at the name
classifier imported it under, same pattern as the other pipeline tests.
"""

from __future__ import annotations

import json

import pytest

from triage import classifier


def _triage_json(**overrides) -> str:
    data = {
        "lane": "1B",
        "vulnerability_class": "path traversal",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": ["CWE-22"],
        "atlas_technique": None,
        "summary": "Path traversal in file loader",
        "agentic_uplift": "Agent can be tricked into reading arbitrary files",
        "validation_steps": ["1. Clone the repo", "2. Reproduce the bug"],
        "reasoning": "Fix commit exists, no CVE assigned",
    }
    data.update(overrides)
    return json.dumps(data)


# --- build_user_prompt() extra_context -----------------------------------------


def test_build_user_prompt_includes_extra_context_when_provided():
    prompt = classifier.build_user_prompt(
        package="somepkg",
        layer="framework",
        agentic_context=None,
        signal_type="pull_request",
        signal_url="https://x",
        signal_content="some PR body",
        extra_context="PR merge status: still open/unmerged.",
    )
    assert "Pipeline-verified context" in prompt
    assert "still open/unmerged" in prompt


def test_build_user_prompt_omits_context_block_when_absent():
    prompt = classifier.build_user_prompt(
        package="somepkg",
        layer="framework",
        agentic_context=None,
        signal_type="commit",
        signal_url="https://x",
        signal_content="some commit message",
    )
    assert "Pipeline-verified context" not in prompt


# --- parsing / schema validation --------------------------------------------


def test_parse_json_response_strips_markdown_fences():
    raw = "```json\n" + _triage_json() + "\n```"
    data = classifier._parse_json_response(raw)
    assert data["lane"] == "1B"


def test_parse_json_response_invalid_json_raises():
    with pytest.raises(classifier.TriageSchemaError, match="not valid JSON"):
        classifier._parse_json_response("not json at all")


def test_parse_json_response_non_object_raises():
    with pytest.raises(classifier.TriageSchemaError, match="must be a JSON object"):
        classifier._parse_json_response("[1, 2, 3]")


def test_validate_schema_rejects_invalid_lane():
    with pytest.raises(classifier.TriageSchemaError, match="invalid or missing lane"):
        classifier._validate_schema({"lane": "5", "summary": "x"})


def test_validate_schema_requires_summary():
    with pytest.raises(classifier.TriageSchemaError, match="summary"):
        classifier._validate_schema({"lane": "3"})


def test_validate_schema_accepts_valid_lane3():
    classifier._validate_schema({"lane": "3", "summary": "noise"})  # no raise


# --- triage_signal() ---------------------------------------------------------


@pytest.mark.asyncio
async def test_triage_signal_returns_parsed_data(monkeypatch):
    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        assert phase == "triage"
        return _triage_json()

    monkeypatch.setattr(classifier, "complete", fake_complete)

    result = await classifier.triage_signal(
        package="somepkg",
        layer="mcp",
        agentic_context="used as a tool server",
        signal_type="commit",
        signal_url="https://github.com/org/repo/commit/abc",
        signal_content="fix: sanitize path input",
    )
    assert result["lane"] == "1B"
    assert result["validation_steps"]


@pytest.mark.asyncio
async def test_triage_signal_reprompts_once_when_validation_steps_missing(monkeypatch):
    calls = []

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        calls.append(user_prompt)
        if len(calls) == 1:
            return _triage_json(lane="1A", validation_steps=[])
        return _triage_json(lane="1A", validation_steps=["1. reproduce"])

    monkeypatch.setattr(classifier, "complete", fake_complete)

    result = await classifier.triage_signal(
        package="somepkg",
        layer="mcp",
        agentic_context=None,
        signal_type="commit",
        signal_url="https://x",
        signal_content="content",
    )
    assert len(calls) == 2
    assert classifier._VALIDATION_STEPS_REPROMPT in calls[1]
    assert result["lane"] == "1A"
    assert result["validation_steps"] == ["1. reproduce"]


@pytest.mark.asyncio
async def test_triage_signal_downgrades_to_lane2_if_still_missing_after_reprompt(monkeypatch):
    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        return _triage_json(lane="1A", validation_steps=[])

    monkeypatch.setattr(classifier, "complete", fake_complete)

    result = await classifier.triage_signal(
        package="somepkg",
        layer="mcp",
        agentic_context=None,
        signal_type="commit",
        signal_url="https://x",
        signal_content="content",
    )
    assert result["lane"] == "2"
    assert result["validation_steps"] == []


@pytest.mark.asyncio
async def test_triage_signal_lane3_does_not_reprompt(monkeypatch):
    calls = []

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        calls.append(1)
        return _triage_json(lane="3", validation_steps=[])

    monkeypatch.setattr(classifier, "complete", fake_complete)

    result = await classifier.triage_signal(
        package="somepkg",
        layer="mcp",
        agentic_context=None,
        signal_type="commit",
        signal_url="https://x",
        signal_content="content",
    )
    assert len(calls) == 1
    assert result["lane"] == "3"


# --- build_finding() ----------------------------------------------------------


def test_build_finding_sets_disclosure_deadline_for_lane_1a():
    triage_result = json.loads(_triage_json(lane="1A"))
    finding = classifier.build_finding(
        package="somepkg",
        ecosystem="pypi",
        layer="mcp",
        source="github_commit",
        signal_url="https://github.com/org/repo/commit/abc",
        triage_result=triage_result,
    )
    assert finding.lane == "1A"
    assert finding.disclosure_deadline is not None
    assert finding.validation_steps == triage_result["validation_steps"]


def test_build_finding_no_disclosure_deadline_for_lane_1b():
    triage_result = json.loads(_triage_json(lane="1B"))
    finding = classifier.build_finding(
        package="somepkg",
        ecosystem="pypi",
        layer="mcp",
        source="github_commit",
        signal_url="https://github.com/org/repo/commit/abc",
        triage_result=triage_result,
    )
    assert finding.lane == "1B"
    assert finding.disclosure_deadline is None


def test_build_finding_uses_triage_agentic_uplift_not_watchlist_context():
    triage_result = json.loads(_triage_json(agentic_uplift="triage-specific reasoning"))
    finding = classifier.build_finding(
        package="somepkg",
        ecosystem="pypi",
        layer="mcp",
        source="github_commit",
        signal_url="https://x",
        triage_result=triage_result,
    )
    assert finding.agentic_uplift == "triage-specific reasoning"
