"""Tests for pipelines/release_check.py.

No real network calls or git clones: HTTP is routed through
httpx.MockTransport (same convention as tests/test_known_cve.py), and
_clone_repo is monkeypatched (same convention as tests/test_pattern_hunter.py).
"""

from __future__ import annotations

import io
import tarfile

import httpx
import pytest

from pipelines import release_check


def _make_sdist(files: dict[str, str]) -> bytes:
    """Builds an in-memory .tar.gz whose members are prefixed pkg-1.0.0/,
    matching a real PyPI sdist's layout."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"pkg-1.0.0/{path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --- _removed_lines_from_patch -----------------------------------------------


def test_removed_lines_from_patch_extracts_minus_lines():
    patch = "@@ -1,3 +1,3 @@\n def f():\n-    return old()\n+    return new()\n"
    assert release_check._removed_lines_from_patch(patch) == ["    return old()"]


def test_removed_lines_from_patch_skips_no_newline_marker():
    patch = "@@ -1,1 +1,1 @@\n-old\n\\ No newline at end of file\n+new"
    assert release_check._removed_lines_from_patch(patch) == ["old"]


def test_removed_lines_from_patch_missing_patch_returns_empty():
    assert release_check._removed_lines_from_patch(None) == []
    assert release_check._removed_lines_from_patch("") == []


def test_removed_lines_from_patch_oversized_diff_returns_empty():
    patch = "@@ -1,50 +1,1 @@\n" + "\n".join(f"-line{i}" for i in range(50))
    assert release_check._removed_lines_from_patch(patch) == []


# --- build_file_removals ------------------------------------------------------


def test_build_file_removals_skips_test_paths_and_missing_patch():
    files = [
        {"filename": "tests/test_foo.py", "patch": "@@ -1 +1 @@\n-bad()\n"},
        {"filename": "src/foo.py", "patch": None},
        {"filename": "src/bar.py", "patch": "@@ -1 +1 @@\n-vulnerable_call()\n"},
    ]
    removals = release_check.build_file_removals(files)
    assert len(removals) == 1
    assert removals[0].filename == "src/bar.py"
    assert removals[0].removed_lines == ["vulnerable_call()"]


# --- check_pattern_in_release: shape present / not present -------------------


@pytest.mark.asyncio
async def test_shape_still_present():
    sdist_bytes = _make_sdist({"src/bar.py": "def bar():\n    vulnerable_call()\n"})

    def handler(request: httpx.Request) -> httpx.Response:
        if "pypi.org" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [{"packagetype": "sdist", "url": "https://files.pythonhosted.org/pkg-1.0.0.tar.gz"}],
                },
            )
        return httpx.Response(200, content=sdist_bytes)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="src/bar.py", removed_lines=["vulnerable_call()"])]
    note = await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert note is not None
    assert "pkg 1.0.0" in note
    assert "pre-fix shape appears present" in note


@pytest.mark.asyncio
async def test_shape_no_longer_present():
    sdist_bytes = _make_sdist({"src/bar.py": "def bar():\n    safe_call()\n"})

    def handler(request: httpx.Request) -> httpx.Response:
        if "pypi.org" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [{"packagetype": "sdist", "url": "https://files.pythonhosted.org/pkg-1.0.0.tar.gz"}],
                },
            )
        return httpx.Response(200, content=sdist_bytes)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="src/bar.py", removed_lines=["vulnerable_call()"])]
    note = await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert note is not None
    assert "does not appear present" in note


@pytest.mark.asyncio
async def test_shape_present_ignores_whitespace_drift():
    # Reindented (8 spaces instead of 4) but the same tokens — a superficial
    # textual check should still match this, since it's whitespace drift
    # (e.g. from an intervening reformat), not a real code change.
    sdist_bytes = _make_sdist({"src/bar.py": "def bar():\n        vulnerable_call()\n"})

    def handler(request: httpx.Request) -> httpx.Response:
        if "pypi.org" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [{"packagetype": "sdist", "url": "https://files.pythonhosted.org/pkg-1.0.0.tar.gz"}],
                },
            )
        return httpx.Response(200, content=sdist_bytes)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="src/bar.py", removed_lines=["    vulnerable_call()"])]
    note = await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert "pre-fix shape appears present" in note


@pytest.mark.asyncio
async def test_no_removed_lines_returns_none():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    note = await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", [], github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()
    assert note is None


@pytest.mark.asyncio
async def test_file_not_located_in_artifact():
    sdist_bytes = _make_sdist({"src/other.py": "unrelated()\n"})

    def handler(request: httpx.Request) -> httpx.Response:
        if "pypi.org" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [{"packagetype": "sdist", "url": "https://files.pythonhosted.org/pkg-1.0.0.tar.gz"}],
                },
            )
        return httpx.Response(200, content=sdist_bytes)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="src/bar.py", removed_lines=["vulnerable_call()"])]
    note = await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert "could not be located" in note


# --- GitHub-tag fallback (no real registry entry) -----------------------------


@pytest.mark.asyncio
async def test_falls_back_to_github_tag_when_registry_unresolvable(monkeypatch, tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "pypi.org" in url:
            return httpx.Response(404, json={"message": "Not Found"})
        if "releases/latest" in url:
            return httpx.Response(200, json={"tag_name": "v2.0.0"})
        return httpx.Response(200, json={})

    async def fake_clone(repo, dest, ref=None):
        assert ref == "v2.0.0"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "bar.py").write_text("vulnerable_call()\n")
        return "deadbeef"

    monkeypatch.setattr(release_check, "_clone_repo", fake_clone)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="bar.py", removed_lines=["vulnerable_call()"])]
    note = await release_check.check_pattern_in_release(
        client, "qdrant-server", "pypi", "qdrant/qdrant", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert "pre-fix shape appears present" in note


@pytest.mark.asyncio
async def test_github_tag_fallback_cleans_up_temp_dir_even_on_read_error(monkeypatch):
    captured_dest = {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "pypi.org" in url:
            return httpx.Response(404, json={"message": "Not Found"})
        if "releases/latest" in url:
            return httpx.Response(200, json={"tag_name": "v2.0.0"})
        return httpx.Response(200, json={})

    async def fake_clone(repo, dest, ref=None):
        dest.mkdir(parents=True, exist_ok=True)
        captured_dest["path"] = dest
        raise RuntimeError("simulated read failure after clone")

    monkeypatch.setattr(release_check, "_clone_repo", fake_clone)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="bar.py", removed_lines=["x"])]
    note = await release_check.check_pattern_in_release(
        client, "qdrant-server", "pypi", "qdrant/qdrant", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert note is not None  # falls through to "could not verify", not an exception
    assert not captured_dest["path"].exists()  # cleaned up despite the raised error


@pytest.mark.asyncio
async def test_totally_unresolvable_returns_could_not_verify_note():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="bar.py", removed_lines=["x"])]
    note = await release_check.check_pattern_in_release(
        client, "ghost-pkg", "pypi", "org/ghost", removals, github_token="tok", cache={}, warned_packages=set()
    )
    await client.aclose()

    assert note is not None
    assert "could not verify" in note


@pytest.mark.asyncio
async def test_could_not_verify_note_only_emitted_once_per_package_per_run():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    removals = [release_check.FileRemoval(filename="bar.py", removed_lines=["x"])]
    cache: release_check.ReleaseCache = {}
    warned: set[tuple[str, str]] = set()

    first = await release_check.check_pattern_in_release(
        client, "ghost-pkg", "pypi", "org/ghost", removals, github_token="tok", cache=cache, warned_packages=warned
    )
    second = await release_check.check_pattern_in_release(
        client, "ghost-pkg", "pypi", "org/ghost", removals, github_token="tok", cache=cache, warned_packages=warned
    )
    await client.aclose()

    assert first is not None
    assert second is None


# --- cache reuse ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_avoids_refetching_release_for_same_package():
    call_count = {"n": 0}
    sdist_bytes = _make_sdist({"src/bar.py": "vulnerable_call()\n"})

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "pypi.org" in url:
            call_count["n"] += 1
            return httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [{"packagetype": "sdist", "url": "https://files.pythonhosted.org/pkg-1.0.0.tar.gz"}],
                },
            )
        return httpx.Response(200, content=sdist_bytes)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache: release_check.ReleaseCache = {}
    removals = [release_check.FileRemoval(filename="src/bar.py", removed_lines=["vulnerable_call()"])]

    await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", removals, github_token="tok", cache=cache, warned_packages=set()
    )
    await release_check.check_pattern_in_release(
        client, "pkg", "pypi", "org/pkg", removals, github_token="tok", cache=cache, warned_packages=set()
    )
    await client.aclose()

    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_cache_memoizes_failure_without_retrying():
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(404, json={"message": "Not Found"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache: release_check.ReleaseCache = {}
    removals = [release_check.FileRemoval(filename="bar.py", removed_lines=["x"])]

    await release_check.check_pattern_in_release(
        client, "ghost-pkg", "pypi", "org/ghost", removals, github_token="tok", cache=cache, warned_packages=set()
    )
    first_count = call_count["n"]
    await release_check.check_pattern_in_release(
        client, "ghost-pkg", "pypi", "org/ghost", removals, github_token="tok", cache=cache, warned_packages=set()
    )
    await client.aclose()

    assert call_count["n"] == first_count  # second call served entirely from cache
