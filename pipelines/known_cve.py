"""Known CVE pipeline — cve-agent-spec.md §8.1.

Queries OSV.dev, NVD, and GHSA (GitHub GraphQL) for each watchlist package,
dedups across sources by CVE ID, and writes new findings (lane="known") to
SQLite. No LLM calls — pure feed aggregation.

PyPI Safety DB is listed as a fourth source in the spec but is deliberately
not implemented here: the upstream feed (pyup.io / pyupio/safety-db) has
been unmaintained since ~2022, and OSV.dev already aggregates PyPI advisories
(including the PYSEC-* records that used to be Safety DB's unique value) so
adding it back would mostly reintroduce stale, duplicate data. Revisit if a
maintained free replacement shows up.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml
from packaging.version import InvalidVersion, Version

from pipelines.http_utils import RateLimiter, console, request_with_retry
from state.db import PROJECT_ROOT, Finding, make_finding_id, upsert_finding

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/graphql"

DEFAULT_WATCHLIST_PATH = PROJECT_ROOT / "config" / "watchlist.yaml"

_OSV_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}
_GHSA_ECOSYSTEM = {"pypi": "PIP", "npm": "NPM"}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

GHSA_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
  securityVulnerabilities(first: 25, ecosystem: $ecosystem, package: $package) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss { score }
        identifiers { type value }
        references { url }
        cwes(first: 10) { nodes { cweId } }
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""


def load_watchlist(path: str | Path = DEFAULT_WATCHLIST_PATH) -> list[dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text())
    return data.get("packages", [])


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def query_osv(client: httpx.AsyncClient, package: str, ecosystem: str) -> list[dict[str, Any]]:
    osv_ecosystem = _OSV_ECOSYSTEM.get(ecosystem)
    if osv_ecosystem is None:
        return []
    resp = await request_with_retry(
        client, "POST", OSV_URL, json={"package": {"name": package, "ecosystem": osv_ecosystem}}
    )
    if resp is None:
        return []
    vulns = resp.json().get("vulns", [])
    results = []
    for v in vulns:
        cve_id = next((a for a in v.get("aliases", []) if _CVE_RE.match(a)), None) or v.get("id")
        cwe = (v.get("database_specific") or {}).get("cwe_ids", [])
        fix_url = next(
            (r["url"] for r in v.get("references", []) if r.get("type") == "FIX"),
            v.get("references", [{}])[0].get("url") if v.get("references") else None,
        )
        results.append(
            {
                "source": "osv",
                "cve_id": cve_id,
                "summary": v.get("summary") or (v.get("details") or "")[:280],
                "severity": None,
                "cvss": None,
                "cwe": cwe,
                "signal_url": fix_url or f"https://osv.dev/vulnerability/{v.get('id')}",
                # kept for cross_check_existing_cve()'s version-range and
                # commit-SHA matching — not used by the known-CVE pipeline itself
                "affected": v.get("affected", []),
                "references": [r["url"] for r in v.get("references", []) if r.get("url")],
            }
        )
    return results


def _cpe_confirms(cve: dict[str, Any], package: str) -> bool:
    """True if any CPE match in NVD's structured config data names this
    exact package as the product — the authoritative signal when present."""
    target = package.lower().replace("_", "-")
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4 and parts[4].lower().replace("_", "-") == target:
                    return True
    return False


def _repo_confirms(cve: dict[str, Any], repo: str) -> bool:
    """True if a reference URL points at this exact repo — not a sibling
    repo with the same prefix (e.g. aio-libs/aiohttp vs aio-libs/aiohttp-session)."""
    pattern = re.compile(rf"github\.com/{re.escape(repo)}(?:[/#?]|$)", re.IGNORECASE)
    return any(pattern.search(r.get("url", "")) for r in cve.get("references", []))


async def query_nvd(
    client: httpx.AsyncClient,
    package: str,
    *,
    api_key: str | None,
    rate_limiter: RateLimiter,
    repo: str | None = None,
) -> list[dict[str, Any]]:
    headers = {"apiKey": api_key} if api_key else {}
    await rate_limiter.wait()
    resp = await request_with_retry(
        client, "GET", NVD_URL, params={"keywordSearch": package}, headers=headers
    )
    if resp is None:
        return []
    results = []
    for item in resp.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # keywordSearch is a loose full-text match over the whole description,
        # not a product-name field, so free-text position/word-boundary
        # heuristics still let through two kinds of noise that matter for a
        # tool researchers are meant to trust: unrelated products that
        # happen to share a short/generic name (e.g. "mcp" also being a
        # legacy mainframe OS), and CVEs in some *other* product whose
        # description merely mentions this package as a dependency (e.g. a
        # CVE in "AutoGPT" that references aiohttp in passing). Neither is
        # reliably distinguishable from real hits by text position alone, so
        # only keep a result when NVD's own structured data confirms it:
        #   1. CPE config data names this exact package as the affected product
        #   2. a reference URL points back at the package's own GitHub repo
        # This trades recall (very recent CVEs NVD hasn't CPE-tagged yet, and
        # lacking a repo-referencing URL, get missed here) for precision —
        # OSV.dev and GHSA remain the primary, precise discovery sources;
        # NVD mainly adds authoritative CVSS/CWE enrichment on top of those.
        if not (_cpe_confirms(cve, package) or (repo and _repo_confirms(cve, repo))):
            continue
        metrics = cve.get("metrics", {})
        cvss_data = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss_data = metrics[key][0]["cvssData"]
                break
        cwe = [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description") and w["description"][0]["value"].startswith("CWE-")
        ]
        results.append(
            {
                "source": "nvd",
                "cve_id": cve.get("id"),
                "summary": summary,
                "severity": (cvss_data or {}).get("baseSeverity"),
                "cvss": (cvss_data or {}).get("baseScore"),
                "cwe": cwe,
                "signal_url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
            }
        )
    return results


async def query_ghsa(client: httpx.AsyncClient, package: str, ecosystem: str, *, token: str | None) -> list[dict[str, Any]]:
    if not token:
        return []
    ghsa_ecosystem = _GHSA_ECOSYSTEM.get(ecosystem)
    if ghsa_ecosystem is None:
        return []
    resp = await request_with_retry(
        client,
        "POST",
        GHSA_URL,
        headers={"Authorization": f"Bearer {token}"},
        json={"query": GHSA_QUERY, "variables": {"ecosystem": ghsa_ecosystem, "package": package}},
    )
    if resp is None:
        return []
    payload = resp.json()
    if "errors" in payload:
        console.print(f"[yellow]warning:[/yellow] GHSA GraphQL error for {package}: {payload['errors']}")
        return []
    nodes = ((payload.get("data") or {}).get("securityVulnerabilities") or {}).get("nodes", [])
    results = []
    for node in nodes:
        advisory = node.get("advisory", {})
        cve_id = next(
            (i["value"] for i in advisory.get("identifiers", []) if i.get("type") == "CVE"),
            advisory.get("ghsaId"),
        )
        cwe = [c["cweId"] for c in (advisory.get("cwes") or {}).get("nodes", [])]
        refs = advisory.get("references", [])
        severity = advisory.get("severity")
        if severity == "MODERATE":
            severity = "MEDIUM"
        results.append(
            {
                "source": "ghsa",
                "cve_id": cve_id,
                "summary": advisory.get("summary"),
                "severity": severity,
                "cvss": (advisory.get("cvss") or {}).get("score"),
                "cwe": cwe,
                "signal_url": refs[0]["url"] if refs else f"https://github.com/advisories/{advisory.get('ghsaId')}",
                # kept for cross_check_existing_cve()'s version-range and
                # commit-SHA matching — not used by the known-CVE pipeline itself
                "vulnerable_version_range": node.get("vulnerableVersionRange"),
                "references": [r["url"] for r in refs if r.get("url")],
            }
        )
    return results


def _merge_by_cve(*result_lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedup across sources by CVE ID, preferring NVD > GHSA > OSV for each field."""
    priority = {"nvd": 0, "ghsa": 1, "osv": 2}
    merged: dict[str, dict[str, Any]] = {}
    for results in result_lists:
        for r in results:
            if not r.get("cve_id"):
                continue
            key = r["cve_id"]
            if key not in merged:
                merged[key] = dict(r)
                merged[key]["sources"] = [r["source"]]
                continue
            existing = merged[key]
            existing["sources"].append(r["source"])
            if priority.get(r["source"], 9) < priority.get(existing["source"], 9):
                for field_name in ("summary", "severity", "cvss", "signal_url"):
                    if r.get(field_name) is not None:
                        existing[field_name] = r[field_name]
                existing["source"] = r["source"]
            if not existing.get("cwe") and r.get("cwe"):
                existing["cwe"] = r["cwe"]
    return list(merged.values())


_RANGE_CLAUSE_RE = re.compile(r"(>=|<=|>|<|=)\s*([\w.\-+]+)")


def _commit_sha_in_refs(commit_sha: str, references: list[str]) -> bool:
    return any(commit_sha in ref for ref in references)


def _version_in_osv_ranges(version: str, affected: list[dict[str, Any]]) -> bool:
    """True if `version` is listed exactly, or falls within an
    introduced/fixed bound, in an OSV `affected[]` entry. Any parse failure
    is treated as no-match — conservative, since a missed match here just
    means the signal proceeds to triage as normal (safe), while a false
    match would wrongly suppress a real finding (unsafe)."""
    try:
        target = Version(version)
    except InvalidVersion:
        return False
    for entry in affected:
        if version in entry.get("versions", []):
            return True
        for rng in entry.get("ranges", []):
            introduced = next((e["introduced"] for e in rng.get("events", []) if "introduced" in e), None)
            fixed = next((e["fixed"] for e in rng.get("events", []) if "fixed" in e), None)
            try:
                if introduced and introduced != "0" and target < Version(introduced):
                    continue
                if fixed and target >= Version(fixed):
                    continue
            except InvalidVersion:
                continue
            return True
    return False


def _version_satisfies_range_string(version: str, range_str: str | None) -> bool:
    """True if `version` satisfies a GHSA-style range string, e.g. '>= 1.0.0, < 2.0.0'."""
    if not range_str:
        return False
    try:
        target = Version(version)
    except InvalidVersion:
        return False
    clauses = _RANGE_CLAUSE_RE.findall(range_str)
    if not clauses:
        return False
    for op, bound in clauses:
        try:
            bound_v = Version(bound)
        except InvalidVersion:
            return False
        satisfied = {
            ">=": target >= bound_v,
            ">": target > bound_v,
            "<=": target <= bound_v,
            "<": target < bound_v,
            "=": target == bound_v,
        }[op]
        if not satisfied:
            return False
    return True


async def cross_check_existing_cve(
    package: str,
    ecosystem: str,
    repo: str | None = None,
    commit_sha: str | None = None,
    version: str | None = None,
    *,
    client: httpx.AsyncClient | None = None,
    github_token: str | None = None,
) -> str | None:
    """cve-agent-spec.md §8.2a / §8.6 — query OSV.dev + GHSA (the same
    sources §8.1 already queries, reused rather than duplicated) for an
    existing CVE that could plausibly cover this pre-CVE signal, so it never
    gets triaged into Lane 1A/1B when a CVE for the same issue was actually
    assigned days or weeks ago. Called before triage (§8.2a) and again,
    fresh, immediately before a finding may become `ready_to_file` (§8.6) —
    callers must not cache or skip this.

    Matches on a fix-commit reference (highest confidence) or an
    affected-version-range overlap. Returns the matched CVE id, or None.
    `repo` is accepted for signature parity with the signal shape but isn't
    needed here — OSV/GHSA are already queried by package+ecosystem, not repo.
    """

    async def _run(c: httpx.AsyncClient) -> str | None:
        osv_results, ghsa_results = await asyncio.gather(
            query_osv(c, package, ecosystem),
            query_ghsa(c, package, ecosystem, token=github_token),
        )
        for result in (*osv_results, *ghsa_results):
            if not result.get("cve_id"):
                continue
            if commit_sha and _commit_sha_in_refs(commit_sha, result.get("references", [])):
                return result["cve_id"]
            if version and _version_in_osv_ranges(version, result.get("affected") or []):
                return result["cve_id"]
            if version and _version_satisfies_range_string(version, result.get("vulnerable_version_range")):
                return result["cve_id"]
        return None

    if client is not None:
        return await _run(client)
    async with httpx.AsyncClient(timeout=30.0) as new_client:
        return await _run(new_client)


@dataclass
class KnownCveScanResult:
    packages_scanned: int = 0
    findings_new: int = 0


async def run_known_cve_pipeline(
    packages: list[dict[str, Any]],
    *,
    db: Any,
    github_token: str | None,
    nvd_api_key: str | None,
    concurrency: int = 4,
    dry_run: bool = False,
) -> KnownCveScanResult:
    result = KnownCveScanResult()
    nvd_limiter = RateLimiter(min_interval=0.65 if nvd_api_key else 6.5)
    semaphore = asyncio.Semaphore(concurrency)
    # Batch-loaded once instead of one SELECT COUNT(*) per finding below —
    # this loop can produce hundreds of candidates per run.
    existing_ids = {row["id"] for row in db["findings"].rows_where(select="id")}

    async with httpx.AsyncClient(timeout=30.0) as client:

        async def process(pkg: dict[str, Any]) -> None:
            async with semaphore:
                osv_task = query_osv(client, pkg["name"], pkg["ecosystem"])
                nvd_task = query_nvd(
                    client, pkg["name"], api_key=nvd_api_key, rate_limiter=nvd_limiter, repo=pkg.get("repo")
                )
                ghsa_task = query_ghsa(client, pkg["name"], pkg["ecosystem"], token=github_token)
                osv_results, nvd_results, ghsa_results = await asyncio.gather(osv_task, nvd_task, ghsa_task)
                for merged in _merge_by_cve(osv_results, nvd_results, ghsa_results):
                    finding_id = make_finding_id(pkg["name"], merged["source"], merged["cve_id"])
                    if finding_id in existing_ids:
                        continue
                    existing_ids.add(finding_id)
                    finding = Finding(
                        id=finding_id,
                        package=pkg["name"],
                        ecosystem=pkg["ecosystem"],
                        layer=pkg["layer"],
                        source=merged["source"],
                        signal_url=merged.get("signal_url"),
                        summary=merged.get("summary"),
                        lane="known",
                        severity=merged.get("severity") or _severity_from_score(merged.get("cvss")),
                        cvss=merged.get("cvss"),
                        cwe=merged.get("cwe") or [],
                        cve_id=merged["cve_id"],
                        agentic_uplift=pkg.get("agentic_context"),
                    )
                    if not dry_run:
                        upsert_finding(db, finding)
                    result.findings_new += 1
                result.packages_scanned += 1

        enabled = [p for p in packages if p.get("enabled", True)]
        await asyncio.gather(*(process(p) for p in enabled))

    return result
