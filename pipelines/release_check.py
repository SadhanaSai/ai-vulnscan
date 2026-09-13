"""Static "does the flawed shape still ship?" check for pre-CVE signals.

Manual audit of Lane 1A/1B findings found systemic false positives that
triage's LLM (triage/classifier.py) had no way to catch on its own: it only
sees signal prose (commit/PR/issue text) plus `_pipeline_verified_context()`
facts about PR merge status and changed filenames (pipelines/pre_cve.py) —
nothing checks whether the flawed code a signal describes is actually
present in what the package currently ships. Phase 7's `validate` attempts
something similar but is gated to six fixed CWE classes
(config/scan_config.yaml), a dead end for the DoS/logic-flaw CWEs that make
up most pre-CVE signals.

This module does a lightweight, CWE-agnostic, purely static check instead:
does the code *removed* by a commit/PR's own diff still appear in the
package's actual latest *released* version (not just GitHub `main`, which
can be ahead of what's published)? The result is folded into
`_pipeline_verified_context()` as one more authoritative pipeline fact.

Ephemeral by construction (CLAUDE.md constraint 4): release archives are
read fully into memory and discarded at the end of a pipeline run (only the
GitHub-tag fallback path touches disk, and that's cleaned up in a `finally`
block, same as hunter/scanner.py's clone -> read -> delete).
"""

from __future__ import annotations

import io
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from hunter.scanner import _clone_repo
from pipelines.http_utils import console, request_with_retry

MAX_REMOVED_LINES_PER_FILE = 40
MAX_FILES_PER_NOTE = 5

_TEST_PATH_RE_SOURCE = r"(^|/)tests?(/|_|$)|_test\.|\.test\.|\.spec\."


def _looks_like_test_path(path: str) -> bool:
    import re

    return bool(re.search(_TEST_PATH_RE_SOURCE, path, re.IGNORECASE))


@dataclass(frozen=True)
class FileRemoval:
    filename: str
    removed_lines: list[str]


def _removed_lines_from_patch(patch: str | None) -> list[str]:
    """Extracts `-`-prefixed lines (the pre-fix shape) from a GitHub file
    `patch` (a unified-diff body with no ---/+++ header — GitHub's files
    API starts directly at the first @@ hunk). Returns [] if there's no
    usable patch (large/binary/rename-only diffs omit this field) or if the
    diff exceeds MAX_REMOVED_LINES_PER_FILE — a diff that large is more
    likely to have been reflowed/refactored than to superficially
    text-match anyway, so we don't check a truncated, misleading subset."""
    if not patch:
        return []
    removed: list[str] = []
    for line in patch.split("\n"):
        if line.startswith("@@") or line.startswith("\\"):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
    if len(removed) > MAX_REMOVED_LINES_PER_FILE:
        return []
    return removed


def build_file_removals(files: list[dict[str, Any]]) -> list[FileRemoval]:
    """Filters a GitHub commit/PR files list (as returned by
    pipelines.pre_cve._fetch_commit_files/_fetch_pr_files) down to the
    files worth release-checking: skips test-only paths (no point checking
    whether a test's removed lines still ship) and files with no usable
    diff."""
    out = []
    for f in files:
        filename = f.get("filename", "")
        if not filename or _looks_like_test_path(filename):
            continue
        removed = _removed_lines_from_patch(f.get("patch"))
        if removed:
            out.append(FileRemoval(filename=filename, removed_lines=removed))
    return out


def _normalize(line: str) -> str:
    return " ".join(line.split())


@dataclass
class _ReleaseArtifact:
    version: str
    source: str  # "pypi_sdist" | "npm_tarball" | "github_tag"
    members: dict[str, bytes]


ReleaseCache = dict[tuple[str, str], "_ReleaseArtifact | None"]


def _extract_tar_or_zip(content: bytes, url: str) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                members[name] = zf.read(name)
        return members
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            extracted = tf.extractfile(member)
            if extracted is not None:
                members[member.name] = extracted.read()
    return members


async def _fetch_pypi_artifact(client: httpx.AsyncClient, package: str) -> _ReleaseArtifact | None:
    """Resolves the latest published version and fetches its sdist in one
    PyPI JSON API call — both `info.version` and `urls` come from the same
    response, so there's no separate version-resolution round trip (and no
    need to import validation/version_resolution.py, which would create a
    circular import back into this module via pipelines/pre_cve.py)."""
    resp = await request_with_retry(client, "GET", f"https://pypi.org/pypi/{package}/json")
    if resp is None:
        return None
    payload = resp.json()
    version = payload.get("info", {}).get("version")
    if not version:
        return None
    sdist = next((u for u in payload.get("urls", []) if u.get("packagetype") == "sdist"), None)
    if sdist is None:
        return None
    dl = await request_with_retry(client, "GET", sdist["url"])
    if dl is None:
        return None
    try:
        members = _extract_tar_or_zip(dl.content, sdist["url"])
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        console.print(f"[yellow]warning:[/yellow] could not extract sdist for {package}=={version}: {exc}")
        return None
    return _ReleaseArtifact(version=version, source="pypi_sdist", members=members)


async def _fetch_npm_artifact(client: httpx.AsyncClient, package: str) -> _ReleaseArtifact | None:
    resp = await request_with_retry(client, "GET", f"https://registry.npmjs.org/{package}/latest")
    if resp is None:
        return None
    payload = resp.json()
    version = payload.get("version")
    tarball = payload.get("dist", {}).get("tarball")
    if not version or not tarball:
        return None
    dl = await request_with_retry(client, "GET", tarball)
    if dl is None:
        return None
    try:
        members = _extract_tar_or_zip(dl.content, tarball)
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        console.print(f"[yellow]warning:[/yellow] could not extract npm tarball for {package}=={version}: {exc}")
        return None
    return _ReleaseArtifact(version=version, source="npm_tarball", members=members)


async def _fetch_github_tag_artifact(
    client: httpx.AsyncClient, repo: str, *, github_token: str
) -> _ReleaseArtifact | None:
    """Fallback for packages with no real pypi/npm registry entry (e.g.
    scan-repo-registered server binaries like ollama-server/qdrant-server) —
    resolve the latest GitHub release tag and shallow-clone it. This is the
    only path here that touches disk; it's cleaned up unconditionally
    (CLAUDE.md constraint 4: clone -> read -> delete)."""
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"}
    resp = await request_with_retry(client, "GET", f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
    tag = resp.json().get("tag_name") if resp is not None else None
    if not tag:
        resp = await request_with_retry(client, "GET", f"https://api.github.com/repos/{repo}/tags", headers=headers)
        tags = resp.json() if resp is not None else []
        tag = tags[0]["name"] if tags else None
    if not tag:
        return None

    dest = Path(tempfile.mkdtemp(prefix="cve-release-check-"))
    try:
        sha = await _clone_repo(repo, dest, ref=tag)
        if sha is None:
            return None
        members = {
            str(p.relative_to(dest)): p.read_bytes()
            for p in dest.rglob("*")
            if p.is_file() and ".git" not in p.parts
        }
        return _ReleaseArtifact(version=tag, source="github_tag", members=members)
    finally:
        shutil.rmtree(dest, ignore_errors=True)


async def _get_or_fetch_release(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: str,
    repo: str,
    *,
    github_token: str,
    cache: ReleaseCache,
) -> _ReleaseArtifact | None:
    key = (package, ecosystem)
    if key in cache:
        return cache[key]

    artifact: _ReleaseArtifact | None = None
    try:
        if ecosystem == "pypi":
            artifact = await _fetch_pypi_artifact(client, package)
        elif ecosystem == "npm":
            artifact = await _fetch_npm_artifact(client, package)
        if artifact is None:
            artifact = await _fetch_github_tag_artifact(client, repo, github_token=github_token)
    except Exception as exc:  # network/parse failure — never raise into the pipeline
        console.print(f"[yellow]warning:[/yellow] release check could not fetch a release for {package}: {exc}")
        artifact = None

    cache[key] = artifact
    return artifact


def _locate_member(artifact: _ReleaseArtifact, filename: str) -> bytes | None:
    """Suffix-matches a repo-relative diff path (e.g. src/pkg/foo.py)
    against archive member paths (which carry a package/version prefix,
    e.g. pkgname-1.2.3/src/pkg/foo.py). Ambiguous matches (two members
    share the same trailing segment) always resolve to "not located" —
    never guess which one is the real match (CLAUDE.md constraint 5)."""
    parts = Path(filename).parts
    for depth in range(len(parts), 0, -1):
        suffix = "/".join(parts[-depth:])
        matches = [m for m in artifact.members if m == suffix or m.endswith("/" + suffix)]
        if len(matches) == 1:
            return artifact.members[matches[0]]
        if len(matches) > 1:
            return None
    return None


async def check_pattern_in_release(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: str,
    repo: str,
    removed_lines_by_file: list[FileRemoval],
    *,
    github_token: str,
    cache: ReleaseCache,
    warned_packages: set[tuple[str, str]],
) -> str | None:
    """Returns a note for _pipeline_verified_context(), or None if there's
    nothing to check (no removed-line diffs) or nothing new worth saying
    (a package this run has already been flagged as unverifiable for)."""
    if not removed_lines_by_file:
        return None

    artifact = await _get_or_fetch_release(client, package, ecosystem, repo, github_token=github_token, cache=cache)
    key = (package, ecosystem)
    if artifact is None:
        if key in warned_packages:
            return None
        warned_packages.add(key)
        return (
            f"Release check: could not verify against {package}'s latest release "
            "(no published pypi/npm version and no GitHub release tag found for "
            f"{repo}) — treat this signal's currently-shipped status as unconfirmed."
        )

    per_file_notes: list[str] = []
    for removal in removed_lines_by_file[:MAX_FILES_PER_NOTE]:
        content = _locate_member(artifact, removal.filename)
        if content is None:
            per_file_notes.append(f"{removal.filename} — could not be located in the release artifact")
            continue
        try:
            text = _normalize(content.decode("utf-8", errors="replace"))
        except Exception:
            per_file_notes.append(f"{removal.filename} — could not be decoded")
            continue
        still_present = any(_normalize(line) and _normalize(line) in text for line in removal.removed_lines)
        if still_present:
            per_file_notes.append(f"{removal.filename} — pre-fix shape appears present")
        else:
            per_file_notes.append(f"{removal.filename} — pre-fix shape does not appear present")

    if not per_file_notes:
        return None

    return (
        f"Release check against {package} {artifact.version} (latest {ecosystem} release): "
        + "; ".join(per_file_notes)
        + "."
    )
