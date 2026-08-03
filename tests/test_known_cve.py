"""Tests for pipelines/known_cve.py — cve-agent-spec.md §8.1, §13 Phase 1.

No real network calls: httpx clients here are built with httpx.MockTransport,
and run_known_cve_pipeline's own query calls are monkeypatched.
"""

from __future__ import annotations

import httpx
import pytest

from pipelines import known_cve
from pipelines.http_utils import RateLimiter
from state import db


async def _fake_empty(*args, **kwargs):
    return []


async def _fake_osv_minimal(client, package, ecosystem):
    """A single unscored OSV hit for CVE-2024-5555 — shared by the
    dedup/dry-run pipeline tests, which only care about identity, not fields."""
    return [
        {
            "source": "osv",
            "cve_id": "CVE-2024-5555",
            "summary": "s",
            "severity": None,
            "cvss": None,
            "cwe": [],
            "signal_url": "https://x",
        }
    ]


# --- pure helpers ---------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [(9.8, "CRITICAL"), (9.0, "CRITICAL"), (7.5, "HIGH"), (7.0, "HIGH"), (5.0, "MEDIUM"), (4.0, "MEDIUM"), (1.0, "LOW"), (None, None)],
)
def test_severity_from_score(score, expected):
    assert known_cve._severity_from_score(score) == expected


def test_cpe_confirms_matches_exact_product():
    cve = {
        "configurations": [
            {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:aiohttp_project:aiohttp:3.8.0:*:*:*:*:*:*:*"}]}]}
        ]
    }
    assert known_cve._cpe_confirms(cve, "aiohttp") is True
    assert known_cve._cpe_confirms(cve, "aiohttp-session") is False


def test_cpe_confirms_no_configurations():
    assert known_cve._cpe_confirms({}, "aiohttp") is False


def test_repo_confirms_does_not_match_sibling_repo():
    """aio-libs/aiohttp-session must not confirm aio-libs/aiohttp — a naive
    substring check would let this through (the bug this test guards)."""
    cve = {"references": [{"url": "https://github.com/aio-libs/aiohttp-session/security/advisories/GHSA-xxx"}]}
    assert known_cve._repo_confirms(cve, "aio-libs/aiohttp") is False
    assert known_cve._repo_confirms(cve, "aio-libs/aiohttp-session") is True


def test_repo_confirms_exact_repo():
    cve = {"references": [{"url": "https://github.com/langchain-ai/langchain/commit/abc123"}]}
    assert known_cve._repo_confirms(cve, "langchain-ai/langchain") is True


def test_merge_by_cve_prefers_nvd_but_keeps_cwe_fallback():
    osv = [{"source": "osv", "cve_id": "CVE-2024-1", "summary": "osv summary", "severity": None, "cvss": None, "cwe": ["CWE-22"], "signal_url": "https://osv"}]
    nvd = [{"source": "nvd", "cve_id": "CVE-2024-1", "summary": "nvd summary", "severity": "HIGH", "cvss": 7.5, "cwe": [], "signal_url": "https://nvd"}]
    ghsa = [{"source": "ghsa", "cve_id": "CVE-2024-1", "summary": "ghsa summary", "severity": "CRITICAL", "cvss": 9.0, "cwe": ["CWE-89"], "signal_url": "https://ghsa"}]

    merged = known_cve._merge_by_cve(osv, nvd, ghsa)
    assert len(merged) == 1
    result = merged[0]
    # NVD has highest priority for scalar fields
    assert result["source"] == "nvd"
    assert result["summary"] == "nvd summary"
    assert result["severity"] == "HIGH"
    assert result["cvss"] == 7.5
    # NVD had no CWE, so the OSV fallback (first non-empty) is kept
    assert result["cwe"] == ["CWE-22"]
    assert sorted(result["sources"]) == ["ghsa", "nvd", "osv"]


def test_merge_by_cve_skips_entries_without_cve_id():
    results = known_cve._merge_by_cve([{"source": "osv", "cve_id": None, "summary": "no id"}])
    assert results == []


def test_merge_by_cve_keeps_distinct_cves_separate():
    a = [{"source": "osv", "cve_id": "CVE-2024-1", "summary": "a", "cwe": []}]
    b = [{"source": "osv", "cve_id": "CVE-2024-2", "summary": "b", "cwe": []}]
    merged = known_cve._merge_by_cve(a, b)
    assert {m["cve_id"] for m in merged} == {"CVE-2024-1", "CVE-2024-2"}


# --- source query normalization (mocked HTTP) -----------------------------


@pytest.mark.asyncio
async def test_query_osv_normalizes_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "GHSA-xxxx",
                        "aliases": ["CVE-2024-9999"],
                        "summary": "Test vuln",
                        "database_specific": {"cwe_ids": ["CWE-22"]},
                        "references": [{"type": "FIX", "url": "https://github.com/org/repo/commit/abc"}],
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await known_cve.query_osv(client, "somepkg", "pypi")
    await client.aclose()

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-9999"
    assert results[0]["cwe"] == ["CWE-22"]
    assert results[0]["signal_url"] == "https://github.com/org/repo/commit/abc"


@pytest.mark.asyncio
async def test_query_osv_unknown_ecosystem_returns_empty():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    results = await known_cve.query_osv(client, "somepkg", "cargo")
    await client.aclose()
    assert results == []


@pytest.mark.asyncio
async def test_query_ghsa_maps_moderate_to_medium_and_extracts_cve():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "securityVulnerabilities": {
                        "nodes": [
                            {
                                "advisory": {
                                    "ghsaId": "GHSA-yyyy",
                                    "summary": "GHSA test",
                                    "severity": "MODERATE",
                                    "cvss": {"score": 5.5},
                                    "identifiers": [{"type": "CVE", "value": "CVE-2024-8888"}],
                                    "references": [{"url": "https://github.com/advisories/GHSA-yyyy"}],
                                    "cwes": {"nodes": [{"cweId": "CWE-79"}]},
                                }
                            }
                        ]
                    }
                }
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await known_cve.query_ghsa(client, "somepkg", "pypi", token="fake-token")
    await client.aclose()

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-8888"
    assert results[0]["severity"] == "MEDIUM"
    assert results[0]["cwe"] == ["CWE-79"]


@pytest.mark.asyncio
async def test_query_ghsa_without_token_returns_empty():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    results = await known_cve.query_ghsa(client, "somepkg", "pypi", token=None)
    await client.aclose()
    assert results == []


@pytest.mark.asyncio
async def test_query_nvd_drops_unconfirmed_generic_name_collision():
    """Regression test for the 'mcp' collision: a short/generic package name
    must not match an unrelated CVE on text alone — see §Phase 1 build notes."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-1999-0001",
                            "descriptions": [{"lang": "en", "value": "The ClearPath MCP environment allows something unrelated."}],
                            "references": [{"url": "https://example.com/unrelated"}],
                        }
                    },
                    {
                        "cve": {
                            "id": "CVE-2025-1111",
                            "descriptions": [{"lang": "en", "value": "The MCP Python SDK has a vulnerability."}],
                            "references": [{"url": "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-zzzz"}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
                            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-284"}]}],
                        }
                    },
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = RateLimiter(min_interval=0.0)
    results = await known_cve.query_nvd(
        client, "mcp", api_key=None, rate_limiter=limiter, repo="modelcontextprotocol/python-sdk"
    )
    await client.aclose()

    assert [r["cve_id"] for r in results] == ["CVE-2025-1111"]
    assert results[0]["cvss"] == 8.1
    assert results[0]["cwe"] == ["CWE-284"]


# --- end-to-end pipeline (query functions monkeypatched, real temp SQLite) -


@pytest.mark.asyncio
async def test_run_known_cve_pipeline_writes_new_findings(tmp_path, monkeypatch):
    async def fake_osv(client, package, ecosystem):
        return [{"source": "osv", "cve_id": "CVE-2024-5555", "summary": "s", "severity": "HIGH", "cvss": 7.1, "cwe": ["CWE-22"], "signal_url": "https://x"}]

    async def fake_nvd(client, package, *, api_key, rate_limiter, repo=None):
        return []

    async def fake_ghsa(client, package, ecosystem, *, token):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_nvd", fake_nvd)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_ghsa)

    database = db.get_db(tmp_path / "test.db")
    packages = [{"name": "somepkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/somepkg", "enabled": True}]

    result = await known_cve.run_known_cve_pipeline(packages, db=database, github_token="x", nvd_api_key=None)

    assert result.packages_scanned == 1
    assert result.findings_new == 1
    findings = db.list_findings(database, lane="known")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2024-5555"
    assert findings[0].package == "somepkg"


@pytest.mark.asyncio
async def test_run_known_cve_pipeline_dedups_on_second_run(tmp_path, monkeypatch):
    monkeypatch.setattr(known_cve, "query_osv", _fake_osv_minimal)
    monkeypatch.setattr(known_cve, "query_nvd", _fake_empty)
    monkeypatch.setattr(known_cve, "query_ghsa", _fake_empty)

    database = db.get_db(tmp_path / "test.db")
    packages = [{"name": "somepkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/somepkg", "enabled": True}]

    first = await known_cve.run_known_cve_pipeline(packages, db=database, github_token=None, nvd_api_key=None)
    second = await known_cve.run_known_cve_pipeline(packages, db=database, github_token=None, nvd_api_key=None)

    assert first.findings_new == 1
    assert second.findings_new == 0
    assert len(db.list_findings(database, lane="known")) == 1


@pytest.mark.asyncio
async def test_run_known_cve_pipeline_dry_run_does_not_persist(tmp_path, monkeypatch):
    monkeypatch.setattr(known_cve, "query_osv", _fake_osv_minimal)
    monkeypatch.setattr(known_cve, "query_nvd", _fake_empty)
    monkeypatch.setattr(known_cve, "query_ghsa", _fake_empty)

    database = db.get_db(tmp_path / "test.db")
    packages = [{"name": "somepkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/somepkg", "enabled": True}]

    result = await known_cve.run_known_cve_pipeline(packages, db=database, github_token=None, nvd_api_key=None, dry_run=True)

    assert result.findings_new == 1
    assert len(db.list_findings(database, lane="known")) == 0


@pytest.mark.asyncio
async def test_run_known_cve_pipeline_skips_disabled_packages(tmp_path, monkeypatch):
    called = []

    async def fake_osv(client, package, ecosystem):
        called.append(package)
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_nvd", _fake_empty)
    monkeypatch.setattr(known_cve, "query_ghsa", _fake_empty)

    database = db.get_db(tmp_path / "test.db")
    packages = [
        {"name": "enabled-pkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/a", "enabled": True},
        {"name": "disabled-pkg", "ecosystem": "pypi", "layer": "framework", "repo": "org/b", "enabled": False},
    ]

    await known_cve.run_known_cve_pipeline(packages, db=database, github_token=None, nvd_api_key=None)

    assert called == ["enabled-pkg"]
