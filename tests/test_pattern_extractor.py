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


# --- known-CVE path: version resolution -----------------------------------------


def _known_finding(**overrides) -> db.Finding:
    defaults = dict(
        id="k1",
        package="somepkg",
        ecosystem="pypi",
        layer="mcp",
        source="osv",
        signal_url="https://osv.dev/vulnerability/OSV-2024-1",
        summary="Path traversal",
        lane="known",
        cve_id="CVE-2024-1234",
        cvss=7.5,
        cwe=["CWE-22"],
    )
    defaults.update(overrides)
    return db.Finding(**defaults)


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


@pytest.mark.asyncio
async def test_resolve_affected_fixed_versions_extracts_from_osv_ranges(monkeypatch):
    async def fake_query_osv(client, package, ecosystem):
        return [
            {
                "cve_id": "CVE-2024-1234",
                "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]}],
            },
            {"cve_id": "CVE-2024-9999", "affected": []},
        ]

    monkeypatch.setattr(extractor, "query_osv", fake_query_osv)
    affected, fixed = await extractor._resolve_affected_fixed_versions(object(), "pkg", "pypi", "CVE-2024-1234")
    assert affected == "1.0.0"
    assert fixed == "1.5.0"


@pytest.mark.asyncio
async def test_resolve_affected_fixed_versions_returns_none_when_cve_not_present(monkeypatch):
    async def fake_query_osv(client, package, ecosystem):
        return [{"cve_id": "CVE-2024-9999", "affected": []}]

    monkeypatch.setattr(extractor, "query_osv", fake_query_osv)
    affected, fixed = await extractor._resolve_affected_fixed_versions(object(), "pkg", "pypi", "CVE-2024-1234")
    assert affected is None
    assert fixed is None


@pytest.mark.asyncio
async def test_resolve_affected_fixed_versions_handles_last_affected_without_fixed(monkeypatch):
    """Real-world OSV shape (e.g. GHSA-f4j7-r4q5-qw2c / CVE-2026-45829):
    'introduced' + 'last_affected', no 'fixed' — the exact fix version isn't
    always pinned down by the advisory."""

    async def fake_query_osv(client, package, ecosystem):
        return [
            {
                "cve_id": "CVE-2024-1234",
                "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"last_affected": "1.5.9"}]}]}],
            }
        ]

    monkeypatch.setattr(extractor, "query_osv", fake_query_osv)
    affected, fixed = await extractor._resolve_affected_fixed_versions(object(), "pkg", "pypi", "CVE-2024-1234")
    assert affected == "1.5.9"  # last_affected is the more precise/recent boundary, used over introduced
    assert fixed is None


@pytest.mark.asyncio
async def test_find_matching_tag_prefers_v_prefixed_exact_match(monkeypatch):
    async def fake_request(*args, **kwargs):
        return _FakeResp([{"name": "v1.5.0"}, {"name": "v1.4.0"}])

    monkeypatch.setattr(extractor, "request_with_retry", fake_request)
    tag = await extractor._find_matching_tag(object(), "org/repo", "1.5.0", token="tok")
    assert tag == "v1.5.0"


@pytest.mark.asyncio
async def test_find_matching_tag_falls_back_to_fuzzy_suffix_match(monkeypatch):
    async def fake_request(*args, **kwargs):
        return _FakeResp([{"name": "myproject-release-2.0.0"}])

    monkeypatch.setattr(extractor, "request_with_retry", fake_request)
    tag = await extractor._find_matching_tag(object(), "org/repo", "2.0.0", token="tok")
    assert tag == "myproject-release-2.0.0"


@pytest.mark.asyncio
async def test_find_matching_tag_returns_none_when_nothing_matches(monkeypatch):
    async def fake_request(*args, **kwargs):
        return _FakeResp([{"name": "v9.9.9"}])

    monkeypatch.setattr(extractor, "request_with_retry", fake_request)
    tag = await extractor._find_matching_tag(object(), "org/repo", "1.0.0", token="tok")
    assert tag is None


# --- known-CVE path: fix commit via git log between tags --------------------------


@pytest.mark.asyncio
async def test_find_fix_commit_via_version_range_picks_first_keyword_match(monkeypatch):
    def fake_create_subprocess_exec(*args, **kwargs):
        if "clone" in args:
            return _FakeProc(returncode=0)
        if "log" in args:
            log_output = (
                b"aaaa111 unrelated refactor\n"
                b"bbbb222 fix path traversal vulnerability\n"
                b"cccc333 bump version\n"
            )
            return _FakeProc(stdout=log_output, returncode=0)
        raise AssertionError(f"unexpected git invocation: {args}")

    async def _dispatch(*args, **kwargs):
        return fake_create_subprocess_exec(*args, **kwargs)

    monkeypatch.setattr(extractor.asyncio, "create_subprocess_exec", _dispatch)

    sha = await extractor._find_fix_commit_via_version_range("org/repo", "v1.0.0", "v1.1.0")
    assert sha == "bbbb222"


@pytest.mark.asyncio
async def test_find_fix_commit_via_version_range_returns_none_when_no_keyword_match(monkeypatch):
    async def _dispatch(*args, **kwargs):
        if "clone" in args:
            return _FakeProc(returncode=0)
        if "log" in args:
            return _FakeProc(stdout=b"aaaa111 unrelated refactor\nbbbb222 bump version\n", returncode=0)
        raise AssertionError(f"unexpected git invocation: {args}")

    monkeypatch.setattr(extractor.asyncio, "create_subprocess_exec", _dispatch)

    sha = await extractor._find_fix_commit_via_version_range("org/repo", "v1.0.0", "v1.1.0")
    assert sha is None


@pytest.mark.asyncio
async def test_find_fix_commit_via_version_range_returns_none_on_clone_failure(monkeypatch):
    async def _dispatch(*args, **kwargs):
        if "clone" in args:
            return _FakeProc(stderr=b"repository not found", returncode=128)
        raise AssertionError("git log should not run after a failed clone")

    monkeypatch.setattr(extractor.asyncio, "create_subprocess_exec", _dispatch)

    sha = await extractor._find_fix_commit_via_version_range("org/repo", "v1.0.0", "v1.1.0")
    assert sha is None


@pytest.mark.asyncio
async def test_find_fix_commit_via_version_range_without_affected_tag_uses_single_ref(monkeypatch):
    seen_range_spec = {}

    async def _dispatch(*args, **kwargs):
        if "clone" in args:
            return _FakeProc(returncode=0)
        if "log" in args:
            log_index = args.index("log")
            seen_range_spec["value"] = args[log_index + 1]
            return _FakeProc(stdout=b"", returncode=0)
        raise AssertionError(f"unexpected git invocation: {args}")

    monkeypatch.setattr(extractor.asyncio, "create_subprocess_exec", _dispatch)

    await extractor._find_fix_commit_via_version_range("org/repo", None, "v1.1.0")
    assert seen_range_spec["value"] == "v1.1.0"  # no ".." range when there's no affected tag


@pytest.mark.asyncio
async def test_find_fix_commit_via_version_range_head_search_uses_reverse_and_is_capped(monkeypatch):
    seen_args = {}

    async def _dispatch(*args, **kwargs):
        if "clone" in args:
            return _FakeProc(returncode=0)
        if "log" in args:
            seen_args["args"] = args
            # more lines than the cap, oldest-first (as --reverse would produce)
            lines = [f"sha{i:04d} unrelated commit {i}".encode() for i in range(extractor.MAX_HEAD_SEARCH_COMMITS + 50)]
            return _FakeProc(stdout=b"\n".join(lines), returncode=0)
        raise AssertionError(f"unexpected git invocation: {args}")

    monkeypatch.setattr(extractor.asyncio, "create_subprocess_exec", _dispatch)

    sha = await extractor._find_fix_commit_via_version_range("org/repo", "v1.0.0", "HEAD")

    assert "--reverse" in seen_args["args"]
    assert sha is None  # none of the (capped) lines matched a security keyword


@pytest.mark.asyncio
async def test_find_fix_commit_via_version_range_head_search_finds_match_within_cap(monkeypatch):
    async def _dispatch(*args, **kwargs):
        if "clone" in args:
            return _FakeProc(returncode=0)
        if "log" in args:
            lines = [b"aaaa000 unrelated", b"bbbb111 fix arbitrary file read vulnerability", b"cccc222 unrelated"]
            return _FakeProc(stdout=b"\n".join(lines), returncode=0)
        raise AssertionError(f"unexpected git invocation: {args}")

    monkeypatch.setattr(extractor.asyncio, "create_subprocess_exec", _dispatch)

    sha = await extractor._find_fix_commit_via_version_range("org/repo", "v1.0.0", "HEAD")
    assert sha == "bbbb111"


# --- extract_pattern_from_known_cve() eligibility gates ---------------------------


@pytest.mark.asyncio
async def test_extract_known_cve_skips_non_known_lane(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding(lane="1B")
    result = await extractor.extract_pattern_from_known_cve(finding, repo="org/repo", db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_known_cve_skips_missing_cve_id(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding(cve_id=None)
    result = await extractor.extract_pattern_from_known_cve(finding, repo="org/repo", db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_known_cve_skips_already_patterned(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding(pattern_id="MCP-X-001")
    result = await extractor.extract_pattern_from_known_cve(finding, repo="org/repo", db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_known_cve_skips_when_version_unresolvable(tmp_path, monkeypatch):
    async def fake_resolve(*args, **kwargs):
        return None, None

    monkeypatch.setattr(extractor, "_resolve_affected_fixed_versions", fake_resolve)

    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding()
    result = await extractor.extract_pattern_from_known_cve(finding, repo="org/repo", db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_known_cve_skips_when_fixed_known_but_affected_unknown(tmp_path, monkeypatch):
    """affected_version anchors the search window — without it, a fixed-only
    result would mean "everything reachable from the fixed tag", far too
    broad to trust the first-keyword-match heuristic."""

    async def fake_resolve(*args, **kwargs):
        return None, "1.5.0"

    monkeypatch.setattr(extractor, "_resolve_affected_fixed_versions", fake_resolve)

    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding()
    result = await extractor.extract_pattern_from_known_cve(finding, repo="org/repo", db=database, github_token="tok")
    assert result is None


@pytest.mark.asyncio
async def test_extract_known_cve_uses_head_when_only_last_affected_known(tmp_path, monkeypatch):
    async def fake_resolve(*args, **kwargs):
        return "1.5.9", None  # last_affected, no exact fix version

    async def fake_find_tag(client, repo, version, *, token):
        assert version == "1.5.9"
        return "v1.5.9"

    seen_tags = {}

    async def fake_find_commit(repo, affected_tag, fixed_tag):
        seen_tags["affected"] = affected_tag
        seen_tags["fixed"] = fixed_tag
        return "deadbeef456"

    async def fake_fetch_diff(client, repo, sha, *, token):
        return "--- a/foo.py\n+++ b/foo.py\n"

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        return _VALID_LLM_RESPONSE

    monkeypatch.setattr(extractor, "_resolve_affected_fixed_versions", fake_resolve)
    monkeypatch.setattr(extractor, "_find_matching_tag", fake_find_tag)
    monkeypatch.setattr(extractor, "_find_fix_commit_via_version_range", fake_find_commit)
    monkeypatch.setattr(extractor, "fetch_commit_diff", fake_fetch_diff)
    monkeypatch.setattr(extractor, "complete", fake_complete)

    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding()

    pattern = await extractor.extract_pattern_from_known_cve(
        finding, repo="org/repo", db=database, github_token="tok", library_path=tmp_path / "library.json"
    )

    assert seen_tags["affected"] == "v1.5.9"
    assert seen_tags["fixed"] == "HEAD"
    assert pattern is not None
    assert pattern.source_commit_url == "https://github.com/org/repo/commit/deadbeef456"


@pytest.mark.asyncio
async def test_extract_known_cve_skips_when_tag_unresolvable(tmp_path, monkeypatch):
    async def fake_resolve(*args, **kwargs):
        return "1.0.0", "1.5.0"

    async def fake_find_tag(*args, **kwargs):
        return None

    monkeypatch.setattr(extractor, "_resolve_affected_fixed_versions", fake_resolve)
    monkeypatch.setattr(extractor, "_find_matching_tag", fake_find_tag)

    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding()
    result = await extractor.extract_pattern_from_known_cve(finding, repo="org/repo", db=database, github_token="tok")
    assert result is None


# --- extract_pattern_from_known_cve() happy path ----------------------------------


@pytest.mark.asyncio
async def test_extract_known_cve_full_happy_path(tmp_path, monkeypatch):
    async def fake_resolve(*args, **kwargs):
        return "1.0.0", "1.5.0"

    async def fake_find_tag(client, repo, version, *, token):
        return f"v{version}"

    async def fake_find_commit(repo, affected_tag, fixed_tag):
        assert affected_tag == "v1.0.0"
        assert fixed_tag == "v1.5.0"
        return "deadbeef123"

    async def fake_fetch_diff(client, repo, sha, *, token):
        assert sha == "deadbeef123"
        return "--- a/foo.py\n+++ b/foo.py\n"

    async def fake_complete(phase, system_prompt, user_prompt, *, provider=None, model=None, llm_config=None):
        return _VALID_LLM_RESPONSE

    monkeypatch.setattr(extractor, "_resolve_affected_fixed_versions", fake_resolve)
    monkeypatch.setattr(extractor, "_find_matching_tag", fake_find_tag)
    monkeypatch.setattr(extractor, "_find_fix_commit_via_version_range", fake_find_commit)
    monkeypatch.setattr(extractor, "fetch_commit_diff", fake_fetch_diff)
    monkeypatch.setattr(extractor, "complete", fake_complete)

    database = db.get_db(tmp_path / "test.db")
    finding = _known_finding()
    db.upsert_finding(database, finding)

    pattern = await extractor.extract_pattern_from_known_cve(
        finding, repo="org/repo", db=database, github_token="tok", library_path=tmp_path / "library.json"
    )

    assert pattern is not None
    assert pattern.source_finding_id == finding.id
    assert pattern.source_commit_url == "https://github.com/org/repo/commit/deadbeef123"

    updated = db.get_finding(database, finding.id)
    assert updated.pattern_id == pattern.id


# --- run_pattern_extraction() known-CVE integration --------------------------------


@pytest.mark.asyncio
async def test_run_pattern_extraction_known_cve_requires_package_to_repo(tmp_path, monkeypatch):
    async def fail_extract_known(*args, **kwargs):
        raise AssertionError("extract_pattern_from_known_cve should not run without package_to_repo")

    async def empty_commit_extract(*args, **kwargs):
        return None

    monkeypatch.setattr(extractor, "extract_pattern_from_known_cve", fail_extract_known)
    monkeypatch.setattr(extractor, "extract_pattern_from_finding", empty_commit_extract)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_finding(database, _known_finding(id="k1"))

    await extractor.run_pattern_extraction(db=database, github_token="tok")  # no package_to_repo — should not raise


@pytest.mark.asyncio
async def test_run_pattern_extraction_known_cve_capped_and_sorted_by_severity(tmp_path, monkeypatch):
    processed = []

    async def fake_extract_known(finding, *, repo, db, github_token, llm_provider=None, llm_model=None, library_path=None, dry_run=False):
        processed.append((finding.id, finding.cvss))
        return None

    async def empty_commit_extract(*args, **kwargs):
        return None

    monkeypatch.setattr(extractor, "extract_pattern_from_known_cve", fake_extract_known)
    monkeypatch.setattr(extractor, "extract_pattern_from_finding", empty_commit_extract)
    monkeypatch.setattr(extractor, "MAX_KNOWN_CVE_EXTRACTIONS_PER_RUN", 2)

    database = db.get_db(tmp_path / "test.db")
    db.upsert_finding(database, _known_finding(id="low", cvss=3.0, package="pkg-a"))
    db.upsert_finding(database, _known_finding(id="high", cvss=9.8, package="pkg-a"))
    db.upsert_finding(database, _known_finding(id="mid", cvss=6.5, package="pkg-a"))
    db.upsert_finding(database, _known_finding(id="no-repo", cvss=9.9, package="unmapped-pkg"))

    await extractor.run_pattern_extraction(db=database, github_token="tok", package_to_repo={"pkg-a": "org/repo"})

    assert processed == [("high", 9.8), ("mid", 6.5)]  # top 2 by CVSS; "no-repo" excluded, "low" excluded by cap
