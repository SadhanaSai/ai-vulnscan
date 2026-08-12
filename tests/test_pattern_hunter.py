"""Tests for hunter/scanner.py — cve-agent-spec.md §8.5 (Phase 5).

No real network calls or git clones: _clone_repo/_find_candidates/
cross_check_existing_cve/llm.router.complete are monkeypatched, same pattern
as tests/test_pre_cve.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunter import scanner
from state import db


def _pattern(**overrides) -> db.Pattern:
    defaults = dict(
        id="MCP-PATH-TRAVERSAL-001",
        vulnerability_class="path_traversal",
        layer="mcp",
        trigger="unsanitized filename reaches os.path.join",
        vulnerable_shape="os.path.join(base, user_input)",
        safe_shape="os.path.realpath + prefix check",
        agentic_context="MCP filesystem tool servers",
        cwe=["CWE-22"],
    )
    defaults.update(overrides)
    return db.Pattern(**defaults)


def _package(name="somepkg", **overrides) -> dict:
    pkg = {"name": name, "ecosystem": "pypi", "layer": "mcp", "repo": "org/repo", "agentic_context": None, "enabled": True}
    pkg.update(overrides)
    return pkg


# --- AST / regex pre-filter ------------------------------------------------------


def test_python_candidates_flags_function_with_suspicious_param():
    source = "def read_file(filename):\n    return open(filename).read()\n"
    candidates = scanner._python_candidates(source, keywords=["nonmatching"])
    assert len(candidates) == 1
    name, segment, start, end = candidates[0]
    assert name == "read_file"
    assert "open(filename)" in segment


def test_python_candidates_flags_function_via_relevant_import():
    source = "import os\n\ndef helper(x):\n    return x\n"
    candidates = scanner._python_candidates(source, keywords=["os"])
    assert len(candidates) == 1
    assert candidates[0][0] == "helper"


def test_python_candidates_skips_irrelevant_function():
    source = "def add(a, b):\n    return a + b\n"
    candidates = scanner._python_candidates(source, keywords=["subprocess"])
    assert candidates == []


def test_python_candidates_handles_syntax_error_gracefully():
    assert scanner._python_candidates("def broken(:\n", keywords=[]) == []


def test_js_candidates_flags_function_with_suspicious_param():
    source = "function readFile(filename) {\n  return fs.readFileSync(filename);\n}\n"
    candidates = scanner._js_candidates(source, keywords=["nonmatching"])
    assert len(candidates) == 1
    assert candidates[0][0] == "readFile"


def test_js_candidates_flags_arrow_function_via_keyword():
    source = "const doStuff = (x) => {\n  require('child_process').exec(x);\n}\n"
    candidates = scanner._js_candidates(source, keywords=["child_process"])
    assert len(candidates) == 1
    assert candidates[0][0] == "doStuff"


# --- config / applicability -------------------------------------------------------


def test_pattern_applies_to_package_respects_layer():
    pattern = _pattern(layer="mcp")
    assert scanner._pattern_applies_to_package(pattern, _package(layer="mcp"), {}) is True
    assert scanner._pattern_applies_to_package(pattern, _package(layer="framework"), {}) is False


def test_pattern_applies_to_package_respects_enabled_flag():
    pattern = _pattern(vulnerability_class="rug_pull")
    vuln_classes = {"rug_pull": {"enabled": False}}
    assert scanner._pattern_applies_to_package(pattern, _package(), vuln_classes) is False


def test_load_vulnerability_classes_reads_real_scan_config():
    classes = scanner.load_vulnerability_classes()
    assert "path_traversal" in classes
    assert "keywords" in classes["path_traversal"]


# --- hunt response parsing / validation_steps enforcement --------------------------


def test_parse_json_response_requires_match_field():
    with pytest.raises(scanner.HuntSchemaError):
        scanner._parse_json_response(json.dumps({"confidence": "HIGH"}))


@pytest.mark.asyncio
async def test_hunt_candidate_reprompts_once_then_discards_missing_validation_steps(monkeypatch):
    call_count = {"n": 0}

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None):
        call_count["n"] += 1
        return json.dumps({"match": True, "confidence": "HIGH", "lines": [1], "explanation": "x", "validation_steps": []})

    monkeypatch.setattr(scanner, "complete", fake_complete)
    result = await scanner.hunt_candidate(_pattern(), "def f(): pass", provider=None, model=None)

    assert call_count["n"] == 2  # original + one re-prompt
    assert result["match"] is False  # discarded after re-prompt still missing steps


@pytest.mark.asyncio
async def test_hunt_candidate_reprompt_succeeds_when_second_response_has_steps(monkeypatch):
    responses = [
        json.dumps({"match": True, "confidence": "HIGH", "lines": [1], "explanation": "x", "validation_steps": []}),
        json.dumps({"match": True, "confidence": "HIGH", "lines": [1], "explanation": "x", "validation_steps": ["1. check"]}),
    ]

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None):
        return responses.pop(0)

    monkeypatch.setattr(scanner, "complete", fake_complete)
    result = await scanner.hunt_candidate(_pattern(), "def f(): pass", provider=None, model=None)

    assert result["match"] is True
    assert result["validation_steps"] == ["1. check"]


# --- _build_match_finding() always Lane 1A ----------------------------------------


def test_build_match_finding_is_always_lane_1a():
    pattern = _pattern()
    finding = scanner._build_match_finding(
        _package(),
        pattern,
        finding_id="fid",
        signal_url="https://github.com/org/repo/blob/sha/f.py#L1-L2",
        func_name="read_file",
        hunt_result={"validation_steps": ["1. check"], "explanation": "matches"},
    )
    assert finding.lane == "1A"
    assert finding.pattern_id == pattern.id
    assert finding.disclosure_deadline is not None
    assert finding.validation_steps == ["1. check"]


# --- hunt_pattern_in_package() -----------------------------------------------------


@pytest.mark.asyncio
async def test_hunt_pattern_in_package_persists_high_confidence_match(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        return "deadbeef"

    def fake_find_candidates(root, ecosystem, keywords):
        return [(root / "server.py", "read_file", "def read_file(filename): ...", 10, 12)]

    async def fake_hunt_candidate(pattern, source, *, provider, model):
        return {"match": True, "confidence": "HIGH", "lines": [11], "explanation": "vulnerable", "validation_steps": ["1. check"]}

    async def fake_crosscheck(*args, **kwargs):
        return None

    monkeypatch.setattr(scanner, "_clone_repo", fake_clone)
    monkeypatch.setattr(scanner, "_find_candidates", fake_find_candidates)
    monkeypatch.setattr(scanner, "hunt_candidate", fake_hunt_candidate)
    monkeypatch.setattr(scanner, "cross_check_existing_cve", fake_crosscheck)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_pattern(database, _pattern())  # patterns are always DB-resident by the time hunting runs
    result = scanner.PatternHuntResult()
    findings = await scanner.hunt_pattern_in_package(
        _pattern(), _package(), db=database, github_token="tok", keywords=[],
        llm_provider=None, llm_model=None, dry_run=False, result=result, existing_ids=set(),
    )

    assert len(findings) == 1
    assert findings[0].lane == "1A"
    assert result.findings_new == 1
    stored = db.list_findings(database, lane="1A")
    assert len(stored) == 1

    pattern_row = db.get_pattern(database, _pattern().id)
    assert pattern_row is not None
    assert findings[0].id in pattern_row.confirmed_hits


@pytest.mark.asyncio
async def test_hunt_pattern_in_package_low_confidence_is_false_positive_not_finding(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        return "deadbeef"

    def fake_find_candidates(root, ecosystem, keywords):
        return [(root / "server.py", "read_file", "def read_file(filename): ...", 10, 12)]

    async def fake_hunt_candidate(pattern, source, *, provider, model):
        return {"match": True, "confidence": "LOW", "lines": [11], "explanation": "maybe", "validation_steps": ["1. check"]}

    monkeypatch.setattr(scanner, "_clone_repo", fake_clone)
    monkeypatch.setattr(scanner, "_find_candidates", fake_find_candidates)
    monkeypatch.setattr(scanner, "hunt_candidate", fake_hunt_candidate)

    database = db.get_db(tmp_path / "test.db")
    pattern = _pattern()
    db.upsert_pattern(database, pattern)
    result = scanner.PatternHuntResult()
    findings = await scanner.hunt_pattern_in_package(
        pattern, _package(), db=database, github_token="tok", keywords=[],
        llm_provider=None, llm_model=None, dry_run=False, result=result, existing_ids=set(),
    )

    assert findings == []
    assert result.findings_new == 0
    stored = db.get_pattern(database, pattern.id)
    assert stored.false_positives == 1


@pytest.mark.asyncio
async def test_hunt_pattern_in_package_known_cve_match_routes_to_known_lane(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        return "deadbeef"

    def fake_find_candidates(root, ecosystem, keywords):
        return [(root / "server.py", "read_file", "def read_file(filename): ...", 10, 12)]

    async def fake_hunt_candidate(pattern, source, *, provider, model):
        return {"match": True, "confidence": "HIGH", "lines": [11], "explanation": "vulnerable", "validation_steps": ["1. check"]}

    async def fake_crosscheck(*args, **kwargs):
        return "CVE-2024-9999"

    monkeypatch.setattr(scanner, "_clone_repo", fake_clone)
    monkeypatch.setattr(scanner, "_find_candidates", fake_find_candidates)
    monkeypatch.setattr(scanner, "hunt_candidate", fake_hunt_candidate)
    monkeypatch.setattr(scanner, "cross_check_existing_cve", fake_crosscheck)

    database = db.get_db(tmp_path / "test.db")
    result = scanner.PatternHuntResult()
    findings = await scanner.hunt_pattern_in_package(
        _pattern(), _package(), db=database, github_token="tok", keywords=[],
        llm_provider=None, llm_model=None, dry_run=False, result=result, existing_ids=set(),
    )

    assert len(findings) == 1
    assert findings[0].lane == "known"
    assert findings[0].cve_id == "CVE-2024-9999"
    assert result.known_cve_matches == 1


# --- run_pattern_hunt() sibling scan (§8.5 Step 3) ---------------------------------


@pytest.mark.asyncio
async def test_run_pattern_hunt_scans_same_layer_packages_and_skips_other_layers(tmp_path, monkeypatch):
    scanned_packages = []

    async def fake_hunt_in_package(pattern, pkg, **kwargs):
        scanned_packages.append(pkg["name"])
        result = kwargs["result"]
        if pkg["name"] == "origin-pkg":
            finding = db.Finding(
                id=f"f-{pkg['name']}", package=pkg["name"], ecosystem="pypi", layer="mcp",
                source="pattern_hunt", lane="1A",
            )
            result.findings_new += 1
            return [finding]
        return []

    monkeypatch.setattr(scanner, "hunt_pattern_in_package", fake_hunt_in_package)

    database = db.get_db(tmp_path / "test.db")
    packages = [
        _package(name="origin-pkg", layer="mcp"),
        _package(name="sibling-pkg", layer="mcp"),
        _package(name="other-layer-pkg", layer="framework"),
    ]
    pattern = _pattern(layer="mcp")

    result = await scanner.run_pattern_hunt(packages, [pattern], db=database, github_token="tok")

    assert set(scanned_packages) == {"origin-pkg", "sibling-pkg"}
    assert "other-layer-pkg" not in scanned_packages  # different layer — not applicable, not a sibling
    assert result.findings_new == 1


@pytest.mark.asyncio
async def test_run_pattern_hunt_does_not_rescan_same_pattern_package_pair(tmp_path, monkeypatch):
    """Every package "confirming" would make each package a sibling-scan
    trigger for the other — the (pattern, package) dedup guard must prevent
    that turning into repeated/infinite mutual re-scanning."""
    call_count = {"n": 0}

    async def fake_hunt_in_package(pattern, pkg, **kwargs):
        call_count["n"] += 1
        result = kwargs["result"]
        finding = db.Finding(
            id=f"f-{pkg['name']}", package=pkg["name"], ecosystem="pypi", layer="mcp", source="pattern_hunt", lane="1A"
        )
        result.findings_new += 1
        return [finding]

    monkeypatch.setattr(scanner, "hunt_pattern_in_package", fake_hunt_in_package)

    database = db.get_db(tmp_path / "test.db")
    packages = [_package(name="pkg-a", layer="mcp"), _package(name="pkg-b", layer="mcp")]
    pattern = _pattern(layer="mcp")

    await scanner.run_pattern_hunt(packages, [pattern], db=database, github_token="tok")

    assert call_count["n"] == 2  # each (pattern, package) pair scanned exactly once
