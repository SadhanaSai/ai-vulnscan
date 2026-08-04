"""Tests for cross_check_existing_cve() — cve-agent-spec.md §8.2a / §8.6.

No real network calls: query_osv/query_ghsa are monkeypatched, same pattern
as tests/test_known_cve.py's pipeline tests.
"""

from __future__ import annotations

import pytest

from pipelines import known_cve


# --- version-range / commit-sha matching helpers ----------------------------


def test_version_in_osv_ranges_matches_within_bounds():
    affected = [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]}]
    assert known_cve._version_in_osv_ranges("1.2.0", affected) is True


def test_version_in_osv_ranges_excludes_fixed_version_and_above():
    affected = [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]}]
    assert known_cve._version_in_osv_ranges("1.5.0", affected) is False
    assert known_cve._version_in_osv_ranges("2.0.0", affected) is False


def test_version_in_osv_ranges_exact_version_list_match():
    affected = [{"versions": ["1.2.3", "1.2.4"]}]
    assert known_cve._version_in_osv_ranges("1.2.3", affected) is True
    assert known_cve._version_in_osv_ranges("1.2.5", affected) is False


def test_version_in_osv_ranges_invalid_version_is_no_match_not_error():
    affected = [{"versions": ["1.2.3"]}]
    assert known_cve._version_in_osv_ranges("not-a-version", affected) is False


def test_version_satisfies_range_string():
    assert known_cve._version_satisfies_range_string("1.2.0", ">= 1.0.0, < 1.5.0") is True
    assert known_cve._version_satisfies_range_string("2.0.0", ">= 1.0.0, < 1.5.0") is False
    assert known_cve._version_satisfies_range_string("1.0.0", None) is False


def test_commit_sha_in_refs():
    refs = ["https://github.com/org/repo/commit/abc123def456"]
    assert known_cve._commit_sha_in_refs("abc123def456", refs) is True
    assert known_cve._commit_sha_in_refs("deadbeef", refs) is False


# --- cross_check_existing_cve() end-to-end (query fns monkeypatched) --------


@pytest.mark.asyncio
async def test_cross_check_matches_on_commit_sha(monkeypatch):
    async def fake_osv(client, package, ecosystem):
        return []

    async def fake_ghsa(client, package, ecosystem, *, token):
        return [
            {
                "source": "ghsa",
                "cve_id": "CVE-2024-1234",
                "references": ["https://github.com/org/repo/commit/deadbeef00"],
                "vulnerable_version_range": None,
            }
        ]

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_ghsa)

    cve_id = await known_cve.cross_check_existing_cve(
        "somepkg", "pypi", commit_sha="deadbeef00", github_token="x"
    )
    assert cve_id == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_cross_check_matches_on_version_range(monkeypatch):
    async def fake_osv(client, package, ecosystem):
        return [
            {
                "source": "osv",
                "cve_id": "CVE-2024-5678",
                "references": [],
                "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}],
            }
        ]

    async def fake_ghsa(client, package, ecosystem, *, token):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_ghsa)

    cve_id = await known_cve.cross_check_existing_cve("somepkg", "pypi", version="1.5.0")
    assert cve_id == "CVE-2024-5678"


@pytest.mark.asyncio
async def test_cross_check_no_match_returns_none(monkeypatch):
    async def fake_osv(client, package, ecosystem):
        return [{"source": "osv", "cve_id": "CVE-2024-9999", "references": [], "affected": []}]

    async def fake_ghsa(client, package, ecosystem, *, token):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_ghsa)

    cve_id = await known_cve.cross_check_existing_cve(
        "somepkg", "pypi", commit_sha="not-in-any-ref", version="9.9.9"
    )
    assert cve_id is None


@pytest.mark.asyncio
async def test_cross_check_ignores_results_without_cve_id(monkeypatch):
    async def fake_osv(client, package, ecosystem):
        return [{"source": "osv", "cve_id": None, "references": ["https://github.com/org/repo/commit/abc"], "affected": []}]

    async def fake_ghsa(client, package, ecosystem, *, token):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_ghsa)

    cve_id = await known_cve.cross_check_existing_cve("somepkg", "pypi", commit_sha="abc")
    assert cve_id is None


@pytest.mark.asyncio
async def test_cross_check_no_signal_data_returns_none(monkeypatch):
    """No commit_sha and no version given — nothing to match against, even
    if results exist, since neither match branch can fire."""

    async def fake_osv(client, package, ecosystem):
        return [{"source": "osv", "cve_id": "CVE-2024-1111", "references": ["https://x/commit/abc"], "affected": []}]

    async def fake_ghsa(client, package, ecosystem, *, token):
        return []

    monkeypatch.setattr(known_cve, "query_osv", fake_osv)
    monkeypatch.setattr(known_cve, "query_ghsa", fake_ghsa)

    cve_id = await known_cve.cross_check_existing_cve("somepkg", "pypi")
    assert cve_id is None
