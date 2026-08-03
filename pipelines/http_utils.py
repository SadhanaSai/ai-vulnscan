"""Shared async HTTP resilience helpers for the pipeline modules.

Generic (no NVD/OSV/GHSA-specific logic) so pre_cve.py (Phase 2 — GitHub
Search API, HN Algolia) can reuse the same rate limiting and retry/backoff
behavior instead of re-implementing it, per CLAUDE.md's code-quality
standard that retry logic is consistent project-wide.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
from rich.console import Console

console = Console()


class RateLimiter:
    """Serializes calls with a minimum interval between them (e.g. NVD's
    request-per-30s limits, GitHub Search API's per-minute limits)."""

    def __init__(self, min_interval: float):
        self.min_interval = min_interval
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            remaining = self.min_interval - (now - self._last_call)
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_call = time.monotonic()


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int = 3,
    backoff_base: float = 1.5,
    **kwargs: Any,
) -> httpx.Response | None:
    """Retries on transient failures (429, 5xx, connection errors) only.
    A non-retryable 4xx (bad request, auth failure, etc.) fails fast."""
    for attempt in range(max_retries):
        try:
            resp = await client.request(method, url, **kwargs)
            retryable = resp.status_code == 429 or resp.status_code >= 500
            failure_detail = f"HTTP {resp.status_code}"
        except httpx.TransportError as exc:
            resp = None
            retryable = True
            failure_detail = str(exc)

        if resp is not None and not retryable:
            if resp.status_code >= 400:
                console.print(f"[yellow]warning:[/yellow] {method} {url} returned HTTP {resp.status_code}: {resp.text[:200]}")
                return None
            return resp

        if attempt == max_retries - 1:
            console.print(f"[yellow]warning:[/yellow] {method} {url} failed after {max_retries} attempts: {failure_detail}")
            return None
        await asyncio.sleep(backoff_base * (2**attempt))
    return None
