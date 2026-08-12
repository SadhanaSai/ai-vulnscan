"""Resolves which exact `package==version` `python main.py validate` should
install — cve-agent-spec.md §8.7 default depth requires "the exact affected
`package==version`", but Finding has no persisted version field (same
reasoning as cross_check_existing_cve() and
patterns/extractor.py's known-CVE path always re-querying OSV fresh rather
than trusting a stored value).

Three sources, tried in order:
1. An explicit --version override (the researcher already knows it).
2. For a finding with a cve_id: OSV's affected-version range for that CVE.
3. Otherwise (pre-CVE Lane 1A/1B — no CVE to look up a range for): the
   latest published version. This is the only thing "affected" can mean for
   a hunter/commit-sourced finding, since those are findings about
   currently-live source in the first place.

No fourth silent guess — if none of these resolve, the caller (main.py)
records the run as "inconclusive" rather than picking an arbitrary version.
"""

from __future__ import annotations

import httpx

from pipelines.http_utils import request_with_retry
from pipelines.known_cve import query_osv
from pipelines.pre_cve import NPM_REGISTRY_URL, PYPI_JSON_URL
from state.db import Finding


async def _affected_version_for_cve(client: httpx.AsyncClient, package: str, ecosystem: str, cve_id: str) -> str | None:
    vulns = await query_osv(client, package, ecosystem)
    for v in vulns:
        if v.get("cve_id") != cve_id:
            continue
        for entry in v.get("affected", []):
            for rng in entry.get("ranges", []):
                events = rng.get("events", [])
                last_affected = next((e["last_affected"] for e in events if "last_affected" in e), None)
                if last_affected:
                    return last_affected
                introduced = next((e["introduced"] for e in events if "introduced" in e), None)
                if introduced and introduced != "0":
                    return introduced
    return None


async def _latest_published_version(client: httpx.AsyncClient, package: str, ecosystem: str) -> str | None:
    if ecosystem == "pypi":
        resp = await request_with_retry(client, "GET", PYPI_JSON_URL.format(package=package))
        if resp is None:
            return None
        return resp.json().get("info", {}).get("version")
    if ecosystem == "npm":
        resp = await request_with_retry(client, "GET", NPM_REGISTRY_URL.format(package=package))
        if resp is None:
            return None
        return resp.json().get("version")
    return None


async def resolve_version(finding: Finding, *, override_version: str | None = None) -> tuple[str | None, str]:
    """Returns (version, how_it_was_resolved). version is None if nothing
    could be resolved and no override was given."""
    if override_version:
        return override_version, "explicit --version override"

    async with httpx.AsyncClient(timeout=30) as client:
        if finding.cve_id:
            version = await _affected_version_for_cve(client, finding.package, finding.ecosystem, finding.cve_id)
            if version:
                return version, f"OSV affected-version range for {finding.cve_id}"

        version = await _latest_published_version(client, finding.package, finding.ecosystem)
        if version:
            return version, "latest published version (no CVE-pinned version available)"

    return None, "could not resolve a version automatically — pass --version explicitly"
