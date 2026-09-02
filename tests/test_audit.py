"""Tests for audit/reviewer.py and output/audit_reporter.py —
cve-agent-spec.md §8.8, the standalone `python main.py audit` feature.

No real network calls or git clones: audit.reviewer._clone_repo/complete are
monkeypatched, same pattern as tests/test_pattern_hunter.py.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

import main as main_module
from audit import reviewer
from output import audit_reporter
from state import db


_VALID_RESPONSE = json.dumps(
    {
        "verdict": "CONFIRMED_CONCERN",
        "evidence": [{"file": "src/foo.py", "lines": "10-12", "snippet": "os.system(cmd)", "note": "shell=True equivalent"}],
        "impact": "An attacker-controlled cmd reaches a shell.",
    }
)


# --- load_audit_checklist() ----------------------------------------------------


def test_load_audit_checklist_has_all_seven_areas():
    checklist = reviewer.load_audit_checklist()
    assert set(checklist) == {
        "tool_authorization",
        "unsafe_default_permissions",
        "path_traversal",
        "token_exposure",
        "subprocess_arg_injection",
        "mcp_trust_boundaries",
        "workspace_isolation",
    }
    for area, spec in checklist.items():
        assert spec.get("question"), f"{area} missing a question"
        assert spec.get("keywords"), f"{area} missing keywords"


# --- select_relevant_files() ----------------------------------------------------


def test_select_relevant_files_scores_path_hit_higher_than_one_content_hit(tmp_path):
    (tmp_path / "permission_mode.py").write_text("x = 1\n")  # path hit only: score 2
    (tmp_path / "other.py").write_text("permission_mode\n")  # one content hit only: score 1
    selected = reviewer.select_relevant_files(tmp_path, ["permission_mode"])
    assert selected[0][0].name == "permission_mode.py"


def test_select_relevant_files_returns_empty_when_nothing_matches(tmp_path):
    (tmp_path / "foo.py").write_text("def add(a, b): return a + b\n")
    assert reviewer.select_relevant_files(tmp_path, ["subprocess"]) == []


def test_select_relevant_files_skips_test_and_vendor_dirs(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("subprocess.run(x)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "y.js").write_text("subprocess.run(x)\n")
    assert reviewer.select_relevant_files(tmp_path, ["subprocess"]) == []


def test_select_relevant_files_skips_prefixed_test_dirs_like_e2e_tests(tmp_path):
    """Regression guard: a real `audit` run against anthropics/claude-agent-
    sdk-python had e2e-tests/conftest.py outscore and displace the actual
    vulnerable production file (subprocess_cli.py) for token_exposure —
    "e2e-tests" isn't an exact match for "tests", so the old exact-match
    skip-dir set let it straight through."""
    (tmp_path / "e2e-tests").mkdir()
    (tmp_path / "e2e-tests" / "conftest.py").write_text("api_key = os.environ.get('ANTHROPIC_API_KEY')\n" * 5)
    (tmp_path / "subprocess_cli.py").write_text("cmd.extend(['--mcp-config', json.dumps({'env': server_env})])\n")

    selected = reviewer.select_relevant_files(tmp_path, ["api_key", "env"])
    assert [p.name for p, _ in selected] == ["subprocess_cli.py"]


def test_select_relevant_files_caps_at_max_files_per_area(tmp_path, monkeypatch):
    monkeypatch.setattr(reviewer, "MAX_FILES_PER_AREA", 2)
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text("subprocess.run(x)\n")
    selected = reviewer.select_relevant_files(tmp_path, ["subprocess"])
    assert len(selected) == 2


def test_select_relevant_files_windows_around_a_deep_keyword_hit_in_a_large_file(tmp_path, monkeypatch):
    """Regression guard: a real `audit` run against anthropics/claude-agent-
    sdk-python selected the correct file (subprocess_cli.py) for
    token_exposure/subprocess_arg_injection, but the vulnerable code lived
    ~650 lines in — past a naive head-truncation to MAX_FILE_CHARS, which
    only ever showed imports/docstring. Both the scoring pass (FILE_READ_CAP)
    and the sent content (windowing) must actually reach a deep hit."""
    monkeypatch.setattr(reviewer, "MAX_FILE_CHARS", 500)
    filler = "\n".join(f"# padding line {i}" for i in range(200))  # far exceeds MAX_FILE_CHARS on its own
    content = f"{filler}\nsubprocess.run(cmd, shell=True)  # the actual bug\n{filler}\n"
    (tmp_path / "big.py").write_text(content)

    selected = reviewer.select_relevant_files(tmp_path, ["shell=true"])
    assert len(selected) == 1
    _, chunk = selected[0]
    assert "shell=True" in chunk  # the deep hit survived windowing, not just the file's head


def test_select_relevant_files_uses_word_boundaries_not_bare_substring(tmp_path, monkeypatch):
    """Regression guard: the keyword "token" matched inside "tokenizer" /
    "tokenizes" throughout subprocess_cli.py in the same real run, and
    those false hits filled the window budget ahead of the actual
    `--mcp-config` line much later in the file — substring matching alone
    can't tell "auth token" from "text tokenizer"."""
    monkeypatch.setattr(reviewer, "MAX_FILE_CHARS", 500)
    filler = "\n".join(f"# the tokenizer splits input into tokens, line {i}" for i in range(50))
    content = f"{filler}\ncmd.extend(['--mcp-config', json.dumps({{'token': secret}})])\n{filler}\n"
    (tmp_path / "big.py").write_text(content)

    selected = reviewer.select_relevant_files(tmp_path, ["token"])
    assert len(selected) == 1
    _, chunk = selected[0]
    assert "--mcp-config" in chunk  # the real hit won, not the "tokenizer" false positives


def test_extract_relevant_windows_prioritizes_densest_window_over_budget():
    lines = ["padding"] * 100
    lines[5] = "credential mentioned once, far away"
    lines[80] = "token secret credential api_key authorization dense line"
    content = "\n".join(lines)
    patterns = reviewer._compile_keyword_patterns(["token", "secret", "credential", "api_key", "authorization"])

    # Budget sized to fit exactly the densest window's own hit line and
    # nothing more — proves the sparse window is dropped entirely, not
    # just truncated, once the budget is used up.
    max_chars = len(f"81: {lines[80]}")
    result = reviewer._extract_relevant_windows(content, patterns, max_chars=max_chars)

    assert "dense line" in result  # the dense cluster survived a tight budget
    assert "far away" not in result  # the sparse, earlier hit lost out entirely


# --- _parse_json_response() -----------------------------------------------------


def test_parse_json_response_rejects_invalid_verdict():
    with pytest.raises(reviewer.AuditSchemaError):
        reviewer._parse_json_response(json.dumps({"verdict": "OUT_OF_SCOPE"}))  # not an LLM-assignable verdict


def test_parse_json_response_strips_markdown_fences():
    data = reviewer._parse_json_response("```json\n" + _VALID_RESPONSE + "\n```")
    assert data["verdict"] == "CONFIRMED_CONCERN"


# --- review_area() ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_review_area_returns_out_of_scope_without_llm_call_when_no_files_match(tmp_path, monkeypatch):
    async def fail_complete(*args, **kwargs):
        raise AssertionError("complete() must not be called when no file matches the area's keywords")

    monkeypatch.setattr(reviewer, "complete", fail_complete)

    run = await reviewer.review_area(
        repo="org/repo", ecosystem="pypi", area="subprocess_arg_injection", question="q?",
        root=tmp_path, keywords=["subprocess"], llm_provider=None, llm_model=None,
    )
    assert run.verdict == "OUT_OF_SCOPE"
    assert run.evidence == []


@pytest.mark.asyncio
async def test_review_area_happy_path(tmp_path, monkeypatch):
    (tmp_path / "foo.py").write_text("subprocess.run(cmd, shell=True)\n")

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None):
        assert phase == "agentic_audit"
        assert "org/repo" in user_prompt
        return _VALID_RESPONSE

    monkeypatch.setattr(reviewer, "complete", fake_complete)

    run = await reviewer.review_area(
        repo="org/repo", ecosystem="pypi", area="subprocess_arg_injection",
        question="shell=True anywhere?", root=tmp_path, keywords=["subprocess"],
        llm_provider=None, llm_model=None,
    )
    assert run.verdict == "CONFIRMED_CONCERN"
    assert run.evidence[0]["file"] == "src/foo.py"
    assert run.impact == "An attacker-controlled cmd reaches a shell."


@pytest.mark.asyncio
async def test_review_area_reprompts_once_on_malformed_verdict_then_succeeds(tmp_path, monkeypatch):
    (tmp_path / "foo.py").write_text("subprocess.run(cmd, shell=True)\n")
    calls = {"n": 0}

    async def flaky_complete(phase, system_prompt, user_prompt, *, provider=None, model=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return json.dumps({"verdict": "CONFIRMED_CONCENCE", "evidence": [], "impact": ""})  # garbled, real Groq behavior
        return _VALID_RESPONSE

    monkeypatch.setattr(reviewer, "complete", flaky_complete)

    run = await reviewer.review_area(
        repo="org/repo", ecosystem="pypi", area="subprocess_arg_injection",
        question="shell=True anywhere?", root=tmp_path, keywords=["subprocess"],
        llm_provider=None, llm_model=None,
    )
    assert calls["n"] == 2
    assert run.verdict == "CONFIRMED_CONCERN"


@pytest.mark.asyncio
async def test_review_area_still_malformed_after_reprompt_raises(tmp_path, monkeypatch):
    (tmp_path / "foo.py").write_text("subprocess.run(cmd, shell=True)\n")

    async def always_garbled(phase, system_prompt, user_prompt, *, provider=None, model=None):
        return json.dumps({"verdict": "NOPE"})

    monkeypatch.setattr(reviewer, "complete", always_garbled)

    with pytest.raises(reviewer.AuditSchemaError):
        await reviewer.review_area(
            repo="org/repo", ecosystem="pypi", area="subprocess_arg_injection",
            question="shell=True anywhere?", root=tmp_path, keywords=["subprocess"],
            llm_provider=None, llm_model=None,
        )


# --- run_audit() -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_audit_persists_one_row_per_area(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "foo.py").write_text("subprocess.run(cmd, shell=True)\n")
        return True

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None):
        return _VALID_RESPONSE

    monkeypatch.setattr(reviewer, "_clone_repo", fake_clone)
    monkeypatch.setattr(reviewer, "complete", fake_complete)

    database = db.get_db(tmp_path / "test.db")
    result = await reviewer.run_audit(
        repo="org/repo", ecosystem="pypi", areas=["subprocess_arg_injection", "path_traversal"], db=database,
    )

    assert len(result.runs) == 2
    stored = db.list_audit_runs(database, repo="org/repo")
    assert len(stored) == 2
    assert {r.area for r in stored} == {"subprocess_arg_injection", "path_traversal"}


@pytest.mark.asyncio
async def test_run_audit_rejects_unknown_area(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    with pytest.raises(ValueError):
        await reviewer.run_audit(repo="org/repo", ecosystem="pypi", areas=["not_a_real_area"], db=database)


@pytest.mark.asyncio
async def test_run_audit_clone_failure_records_error_not_out_of_scope(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        return False

    async def fail_complete(*args, **kwargs):
        raise AssertionError("complete() must not be called when the clone failed")

    monkeypatch.setattr(reviewer, "_clone_repo", fake_clone)
    monkeypatch.setattr(reviewer, "complete", fail_complete)

    database = db.get_db(tmp_path / "test.db")
    result = await reviewer.run_audit(repo="org/nonexistent", ecosystem="pypi", areas=["path_traversal"], db=database)

    assert result.runs[0].verdict == "ERROR"
    assert "Could not clone" in result.runs[0].impact


@pytest.mark.asyncio
async def test_run_audit_per_area_failure_is_isolated(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "foo.py").write_text("subprocess.run(cmd)\npath.join(a, b)\n")
        return True

    async def flaky_complete(phase, system_prompt, user_prompt, *, provider=None, model=None):
        if "subprocess" in user_prompt.lower() and "path_traversal" not in user_prompt:
            return "not json at all"
        return _VALID_RESPONSE

    monkeypatch.setattr(reviewer, "_clone_repo", fake_clone)
    monkeypatch.setattr(reviewer, "complete", flaky_complete)

    database = db.get_db(tmp_path / "test.db")
    result = await reviewer.run_audit(
        repo="org/repo", ecosystem="pypi", areas=["subprocess_arg_injection", "path_traversal"], db=database,
    )

    by_area = {r.area: r for r in result.runs}
    assert by_area["subprocess_arg_injection"].verdict == "ERROR"
    assert by_area["path_traversal"].verdict == "CONFIRMED_CONCERN"


@pytest.mark.asyncio
async def test_run_audit_dry_run_does_not_persist(tmp_path, monkeypatch):
    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "foo.py").write_text("subprocess.run(cmd, shell=True)\n")
        return True

    async def fake_complete(*args, **kwargs):
        return _VALID_RESPONSE

    monkeypatch.setattr(reviewer, "_clone_repo", fake_clone)
    monkeypatch.setattr(reviewer, "complete", fake_complete)

    database = db.get_db(tmp_path / "test.db")
    result = await reviewer.run_audit(
        repo="org/repo", ecosystem="pypi", areas=["subprocess_arg_injection"], db=database, dry_run=True,
    )

    assert len(result.runs) == 1  # still returned so the caller/CLI can report it
    assert db.list_audit_runs(database, repo="org/repo") == []  # but nothing written


@pytest.mark.asyncio
async def test_run_audit_never_touches_findings_table(tmp_path, monkeypatch):
    """The whole point of the standalone design: no Finding is ever created
    by an audit run, whatever the verdict."""

    async def fake_clone(repo, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "foo.py").write_text("subprocess.run(cmd, shell=True)\n")
        return True

    async def fake_complete(*args, **kwargs):
        return _VALID_RESPONSE

    monkeypatch.setattr(reviewer, "_clone_repo", fake_clone)
    monkeypatch.setattr(reviewer, "complete", fake_complete)

    database = db.get_db(tmp_path / "test.db")
    await reviewer.run_audit(repo="org/repo", ecosystem="pypi", areas=["subprocess_arg_injection"], db=database)

    assert db.list_findings(database) == []


# --- output/audit_reporter.py ---------------------------------------------------


def test_generate_audit_report_orders_confirmed_concern_first():
    runs = [
        db.AuditRun(repo="org/repo", ecosystem="pypi", area="workspace_isolation", verdict="NOT_FOUND"),
        db.AuditRun(repo="org/repo", ecosystem="pypi", area="token_exposure", verdict="CONFIRMED_CONCERN", impact="leaks a secret"),
    ]
    content = audit_reporter.generate_audit_report("org/repo", "pypi", runs)
    assert content.index("token_exposure") < content.index("workspace_isolation")
    assert "leaks a secret" in content


def test_generate_audit_report_handles_no_runs():
    content = audit_reporter.generate_audit_report("org/repo", "pypi", [])
    assert "org/repo" in content


def test_write_audit_report_default_path_is_slugified(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_reporter, "DEFAULT_REPORT_DIR", tmp_path)
    path = audit_reporter.write_audit_report("content", "Org/Some-Repo")
    assert path.parent == tmp_path
    assert path.name.startswith("audit-org-some-repo-")
    assert path.read_text() == "content"


# --- main.py audit (CliRunner) --------------------------------------------------


def test_audit_cli_requires_areas_or_all(monkeypatch, tmp_path):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)

    result = CliRunner().invoke(main_module.cli, ["audit", "--repo", "org/repo", "--ecosystem", "pypi"])
    assert result.exit_code != 0
    assert "specify --areas" in result.output


def test_audit_cli_errors_without_llm_key(monkeypatch, tmp_path):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    # --llm-provider forces claude explicitly, regardless of whatever
    # config/scan_config.yaml's real agentic_audit default currently is —
    # this test broke once before when that real file's default changed
    # out from under it (claude -> ollama, which needs no key at all).
    result = CliRunner().invoke(
        main_module.cli,
        ["audit", "--repo", "org/repo", "--ecosystem", "pypi", "--areas", "path_traversal", "--llm-provider", "claude"],
    )
    assert result.exit_code != 0
    assert "ANTHROPIC_API_KEY" in result.output


def test_audit_cli_happy_path_writes_report(monkeypatch, tmp_path):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def fake_run_audit(*, repo, ecosystem, areas, db, llm_provider, llm_model, dry_run):
        from audit.reviewer import AuditResult
        from state.db import AuditRun

        return AuditResult(repo=repo, ecosystem=ecosystem, runs=[
            AuditRun(repo=repo, ecosystem=ecosystem, area=areas[0], verdict="NOT_FOUND"),
        ])

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)

    report_path = tmp_path / "report.md"
    result = CliRunner().invoke(
        main_module.cli,
        ["audit", "--repo", "org/repo", "--ecosystem", "pypi", "--areas", "path_traversal", "--output", str(report_path)],
    )

    assert result.exit_code == 0, result.output
    assert "NOT_FOUND" in result.output
    assert report_path.exists()
