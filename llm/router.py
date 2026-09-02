"""Provider-agnostic LLM client — cve-agent-spec.md §7a.

Every phase that needs an LLM call (triage, pattern extraction, pattern
hunt, CVE drafting) goes through complete(). No other module imports
`anthropic` or `openai` directly — provider choice is a config concern
(config/scan_config.yaml's `llm:` section), not a code concern.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any

import yaml
from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
from rich.console import Console

from state.db import PROJECT_ROOT

console = Console()

DEFAULT_SCAN_CONFIG_PATH = PROJECT_ROOT / "config" / "scan_config.yaml"

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

REQUIRED_ENV_VAR = {
    "groq": "GROQ_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
    "ollama": None,  # local, no auth
}


class _RateLimiter:
    """Serializes calls with a minimum interval between them. Small,
    private, and deliberately not the pipelines/http_utils.py RateLimiter
    of the same shape — llm/router.py is a foundational module other
    pipelines depend on, so it shouldn't gain a dependency running the
    other direction."""

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


# Groq's on-demand/free tier caps out at a small per-minute token budget
# (8000 TPM at the tier this project has been run against) — comfortably
# exceeded by sequential calls from any phase, not just one. Confirmed by
# real runs of `python main.py audit` against anthropics/claude-agent-sdk-
# python (2026-08-30): individual 413s from oversized single requests, and
# 429s from simple accumulation even after requests were shrunk — a 12s
# gap between calls still ended up sustaining ~17-20k TPM, well over the
# cap. 40s keeps sustained throughput to ~1.5 calls/minute with margin.
#
# Every phase that can route to Groq (triage, pattern_extraction,
# pattern_hunt, cve_drafting, agentic_audit) shares this one limiter, gated
# on provider == "groq" only — Claude/Ollama calls are unaffected, since
# only Groq's tier is this constrained. Centralized here rather than in
# each pipeline module, so no caller has to remember to add it themselves.
GROQ_PACING_SECONDS = 40.0
_groq_rate_limiter = _RateLimiter(min_interval=GROQ_PACING_SECONDS)


def load_llm_config(path: str | Path = DEFAULT_SCAN_CONFIG_PATH) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text())
    return data.get("llm", {})


def resolve_provider_model(
    phase: str,
    *,
    provider: str | None = None,
    model: str | None = None,
    llm_config: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """CLI override (provider/model args) wins over config/scan_config.yaml's
    per-phase default — see §7a."""
    llm_config = load_llm_config() if llm_config is None else llm_config
    phase_cfg = llm_config.get(phase, {})
    resolved_provider = provider or phase_cfg.get("provider")
    resolved_model = model or phase_cfg.get("model")
    if not resolved_provider or not resolved_model:
        raise ValueError(
            f"No LLM provider/model configured for phase {phase!r} — "
            f"set config/scan_config.yaml llm.{phase} or pass --llm-provider/--llm-model"
        )
    if resolved_provider not in REQUIRED_ENV_VAR:
        raise ValueError(f"Unknown LLM provider {resolved_provider!r} — must be one of {list(REQUIRED_ENV_VAR)}")
    return resolved_provider, resolved_model


def missing_api_key(provider: str) -> str | None:
    """Returns the missing env var name if `provider` needs one and it isn't
    set, else None. Lets callers skip an LLM-dependent step gracefully."""
    env_var = REQUIRED_ENV_VAR.get(provider)
    if env_var and not os.environ.get(env_var):
        return env_var
    return None


def _ollama_base_url() -> str:
    base_url = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    return base_url if base_url.endswith("/v1") else f"{base_url}/v1"


async def _call_openai_compatible(base_url: str, api_key: str | None, model: str, system_prompt: str, user_prompt: str) -> str:
    client = AsyncOpenAI(base_url=base_url, api_key=api_key or "not-needed")
    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return resp.choices[0].message.content or ""


async def _call_claude(api_key: str, model: str, system_prompt: str, user_prompt: str) -> str:
    client = AsyncAnthropic(api_key=api_key)
    resp = await client.messages.create(
        model=model,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
        max_tokens=4096,
    )
    return "".join(block.text for block in resp.content if hasattr(block, "text"))


async def _with_retry(fn, *, max_retries: int = 3, backoff_base: float = 1.5):
    for attempt in range(max_retries):
        try:
            return await fn()
        except Exception as exc:
            if attempt == max_retries - 1:
                console.print(f"[yellow]warning:[/yellow] LLM call failed after {max_retries} attempts: {exc}")
                raise
            await asyncio.sleep(backoff_base * (2**attempt))


async def complete(
    phase: str,
    system_prompt: str,
    user_prompt: str,
    *,
    provider: str | None = None,
    model: str | None = None,
    llm_config: dict[str, Any] | None = None,
) -> str:
    """Resolve provider+model for `phase` from scan_config.yaml (or the
    provider/model override), dispatch to the right client, return raw text."""
    resolved_provider, resolved_model = resolve_provider_model(phase, provider=provider, model=model, llm_config=llm_config)

    if resolved_provider == "claude":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(f"ANTHROPIC_API_KEY is not set but phase {phase!r} is configured for provider 'claude'")
        return await _with_retry(lambda: _call_claude(api_key, resolved_model, system_prompt, user_prompt))

    if resolved_provider == "groq":
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(f"GROQ_API_KEY is not set but phase {phase!r} is configured for provider 'groq'")
        await _groq_rate_limiter.wait()
        return await _with_retry(lambda: _call_openai_compatible(GROQ_BASE_URL, api_key, resolved_model, system_prompt, user_prompt))

    # ollama — local, no auth required
    return await _with_retry(lambda: _call_openai_compatible(_ollama_base_url(), None, resolved_model, system_prompt, user_prompt))
