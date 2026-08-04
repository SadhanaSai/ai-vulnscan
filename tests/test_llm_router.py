"""Tests for llm/router.py — cve-agent-spec.md §7a.

No real network calls: the anthropic/openai SDK client classes are
monkeypatched at the module level router imports them into, same pattern as
the other pipeline tests patch query functions rather than hit real HTTP.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from llm import router

SAMPLE_CONFIG = {
    "llm": {
        "triage": {"provider": "groq", "model": "llama-3.3-70b-versatile"},
        "cve_drafting": {"provider": "claude", "model": "claude-sonnet-4-6"},
    }
}


# --- config resolution ------------------------------------------------------


def test_resolve_provider_model_uses_config_default():
    provider, model = router.resolve_provider_model("triage", llm_config=SAMPLE_CONFIG["llm"])
    assert (provider, model) == ("groq", "llama-3.3-70b-versatile")


def test_resolve_provider_model_cli_override_wins():
    provider, model = router.resolve_provider_model(
        "triage", provider="ollama", model="qwen2.5-coder", llm_config=SAMPLE_CONFIG["llm"]
    )
    assert (provider, model) == ("ollama", "qwen2.5-coder")


def test_resolve_provider_model_partial_override_falls_back_to_config():
    # only provider overridden — model still comes from config for that phase
    provider, model = router.resolve_provider_model("cve_drafting", provider="ollama", llm_config=SAMPLE_CONFIG["llm"])
    assert provider == "ollama"
    assert model == "claude-sonnet-4-6"


def test_resolve_provider_model_missing_phase_raises():
    with pytest.raises(ValueError, match="No LLM provider/model configured"):
        router.resolve_provider_model("nonexistent_phase", llm_config=SAMPLE_CONFIG["llm"])


def test_resolve_provider_model_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        router.resolve_provider_model("x", provider="made-up", model="m", llm_config={})


@pytest.mark.parametrize(
    "provider,env_var,env_value,expected",
    [
        ("groq", "GROQ_API_KEY", None, "GROQ_API_KEY"),
        ("groq", "GROQ_API_KEY", "key", None),
        ("claude", "ANTHROPIC_API_KEY", None, "ANTHROPIC_API_KEY"),
        ("ollama", None, None, None),
    ],
)
def test_missing_api_key(monkeypatch, provider, env_var, env_value, expected):
    if env_var:
        monkeypatch.delenv(env_var, raising=False)
        if env_value:
            monkeypatch.setenv(env_var, env_value)
    assert router.missing_api_key(provider) == expected


def test_ollama_base_url_defaults_and_appends_v1(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert router._ollama_base_url() == "http://localhost:11434/v1"
    monkeypatch.setenv("OLLAMA_HOST", "http://myhost:9999")
    assert router._ollama_base_url() == "http://myhost:9999/v1"


# --- provider dispatch (SDK clients faked) ----------------------------------


class _FakeOpenAIClient:
    last_kwargs: dict = {}

    def __init__(self, base_url=None, api_key=None):
        _FakeOpenAIClient.last_kwargs = {"base_url": base_url, "api_key": api_key}
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs):
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="openai-compatible reply"))])


class _FakeAnthropicClient:
    last_kwargs: dict = {}

    def __init__(self, api_key=None):
        _FakeAnthropicClient.last_kwargs = {"api_key": api_key}
        self.messages = SimpleNamespace(create=self._create)

    async def _create(self, **kwargs):
        return SimpleNamespace(content=[SimpleNamespace(text="claude reply")])


@pytest.mark.asyncio
async def test_complete_dispatches_to_groq(monkeypatch):
    monkeypatch.setattr(router, "AsyncOpenAI", _FakeOpenAIClient)
    monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
    result = await router.complete("triage", "sys", "user", llm_config=SAMPLE_CONFIG["llm"])
    assert result == "openai-compatible reply"
    assert _FakeOpenAIClient.last_kwargs["base_url"] == router.GROQ_BASE_URL
    assert _FakeOpenAIClient.last_kwargs["api_key"] == "fake-groq-key"


@pytest.mark.asyncio
async def test_complete_dispatches_to_claude(monkeypatch):
    monkeypatch.setattr(router, "AsyncAnthropic", _FakeAnthropicClient)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-key")
    result = await router.complete("cve_drafting", "sys", "user", llm_config=SAMPLE_CONFIG["llm"])
    assert result == "claude reply"
    assert _FakeAnthropicClient.last_kwargs["api_key"] == "fake-anthropic-key"


@pytest.mark.asyncio
async def test_complete_dispatches_to_ollama_without_api_key(monkeypatch):
    monkeypatch.setattr(router, "AsyncOpenAI", _FakeOpenAIClient)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    result = await router.complete(
        "triage", "sys", "user", provider="ollama", model="llama3.3", llm_config=SAMPLE_CONFIG["llm"]
    )
    assert result == "openai-compatible reply"
    assert _FakeOpenAIClient.last_kwargs["base_url"] == "http://localhost:11434/v1"


@pytest.mark.asyncio
async def test_complete_raises_clear_error_when_claude_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        await router.complete("cve_drafting", "sys", "user", llm_config=SAMPLE_CONFIG["llm"])


# --- retry logic -------------------------------------------------------------


@pytest.mark.asyncio
async def test_with_retry_retries_then_succeeds():
    attempts = []

    async def flaky():
        attempts.append(1)
        if len(attempts) < 2:
            raise ConnectionError("boom")
        return "ok"

    result = await router._with_retry(flaky, max_retries=3, backoff_base=0.0)
    assert result == "ok"
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_with_retry_raises_after_max_attempts():
    async def always_fails():
        raise ConnectionError("boom")

    with pytest.raises(ConnectionError):
        await router._with_retry(always_fails, max_retries=2, backoff_base=0.0)
