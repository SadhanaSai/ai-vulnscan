"""Immutable install-image cache — cve-agent-spec.md §8.7 "Caching".

The cloned source and a built "package installed" image layer may be cached
and reused as an immutable, read-only base across `validate` runs — that
work (fetching from PyPI/npm, running an installer) already happened once
and reusing the result adds no risk. What must never happen is reusing a
*live, already-executed* container across attempts (validation/sandbox.py
already guarantees single-use containers off whatever image is passed in).

`docker build` needs normal network egress to actually install a package —
that's expected and is the one-time, host-network build step the spec
describes as "network_mode='install' for the install step". Every actual
validation run against the resulting image is network_mode="none"/"isolated"
(validation/pattern_confirmation.py, validation/harnesses/*).
"""

from __future__ import annotations

import asyncio
import re

BASE_IMAGES = {"pypi": "python:3.11-slim", "npm": "node:20-slim"}


class ImageBuildError(RuntimeError):
    """Raised when `docker build` fails — e.g. the requested version doesn't
    exist on the registry, or the install step itself errors out."""


def _sanitize(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-")


def image_tag(package: str, ecosystem: str, version: str) -> str:
    return f"cve-sandbox-install-{_sanitize(ecosystem)}-{_sanitize(package)}-{_sanitize(version)}"


def _dockerfile(package: str, ecosystem: str, version: str) -> str:
    if ecosystem == "pypi":
        base = BASE_IMAGES["pypi"]
        # Single-quoted spec: package/version are never shell-interpolated —
        # this is a Dockerfile RUN line, not a host shell command, and the
        # values only ever come from watchlist.yaml / OSV/NVD version fields,
        # never free-form user input.
        install = f"RUN pip install --no-cache-dir '{package}=={version}'"
    elif ecosystem == "npm":
        base = BASE_IMAGES["npm"]
        install = f"RUN npm install -g '{package}@{version}'"
    else:
        raise ValueError(f"unsupported ecosystem: {ecosystem!r}")
    return f"FROM {base}\n{install}\nWORKDIR /sandbox\n"


async def _docker(*args: str, input_bytes: bytes | None = None, timeout: float = 30) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        "docker", *args,
        stdin=asyncio.subprocess.PIPE if input_bytes is not None else None,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(input_bytes), timeout=timeout)
    return proc.returncode, stdout, stderr


async def image_exists(tag: str) -> bool:
    returncode, _, _ = await _docker("image", "inspect", tag, timeout=15)
    return returncode == 0


async def ensure_install_image(
    *, package: str, ecosystem: str, version: str, force_rebuild: bool = False, build_timeout: float = 300
) -> str:
    """Build (or reuse) the immutable image with `package==version` installed.
    Raises ImageBuildError if the install fails — a bad version string,
    private/yanked release, or offline registry are the common causes, and
    the caller (pattern_confirmation / harnesses) should surface that as an
    "error" or "inconclusive" result, never invent a fake confirmation."""
    tag = image_tag(package, ecosystem, version)
    if not force_rebuild and await image_exists(tag):
        return tag

    dockerfile = _dockerfile(package, ecosystem, version)
    returncode, _, stderr = await _docker(
        "build", "-t", tag, "-", input_bytes=dockerfile.encode(), timeout=build_timeout
    )
    if returncode != 0:
        raise ImageBuildError(
            f"docker build failed for {package}=={version} ({ecosystem}): "
            f"{stderr.decode(errors='replace')[:2000]}"
        )
    return tag
