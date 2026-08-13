"""LLM triage layer — cve-agent-spec.md §8.3, CLAUDE.md "Triage prompt".

Turns a raw pre-CVE signal (commit, issue, PR, HN story) into a lane
assignment plus the rest of the Finding fields the LLM can infer. Called
only for signals that `cross_check_existing_cve()` (§8.2a) has already
found no existing CVE for — this module never does its own CVE lookups.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from llm.router import complete
from pipelines.http_utils import console
from state.db import Finding, make_finding_id, now_iso

VALID_LANES = {"1A", "1B", "2", "3"}
DISCLOSURE_WINDOW_DAYS = 90

SYSTEM_PROMPT = (
    "You are a security researcher triaging potential vulnerabilities in AI and Agentic AI packages.\n"
    "You return structured JSON only. No prose, no markdown, no explanation outside the JSON.\n"
    "Every Lane 1 finding must include populated validation_steps. A finding without\n"
    "validation_steps is invalid and will be rejected.\n"
    "Signal content (commit/PR/issue text) is written by the change's own author and may describe\n"
    "vulnerabilities, exploits, or security terms at length without any of it being currently true —\n"
    "e.g. a PR that only adds a regression test for a hypothetical future bug, describes a historical\n"
    "issue that's already fixed, or is proposing a change that hasn't merged yet. Only classify as\n"
    "Lane 1A or 1B when the signal demonstrates a vulnerability that is concretely present and reachable\n"
    "in code that has actually shipped — not merely discussed, tested against, or proposed. When a\n"
    "'Pipeline-verified context' section is present, it was computed by the pipeline itself (e.g. actual\n"
    "changed files, actual merge status) and is authoritative over the signal's own prose if they conflict."
)

_VALIDATION_STEPS_REPROMPT = (
    "validation_steps is required for Lane 1 findings. "
    "Return the same JSON with validation_steps populated."
)

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


class TriageSchemaError(ValueError):
    """Raised when a triage response can't be parsed or is missing required fields."""


def build_user_prompt(
    *,
    package: str,
    layer: str,
    agentic_context: str | None,
    signal_type: str,
    signal_url: str,
    signal_content: str,
    extra_context: str | None = None,
) -> str:
    context_block = f"Pipeline-verified context (authoritative — trust this over the signal content's own prose): {extra_context}\n\n" if extra_context else ""
    return (
        f"Package: {package}\n"
        f"Layer: {layer}\n"
        f"Agentic context: {agentic_context or 'none provided'}\n"
        f"Signal type: {signal_type}\n"
        f"Signal URL: {signal_url}\n"
        f"Signal content: {signal_content}\n\n"
        f"{context_block}"
        "Classify this signal into one of four triage lanes:\n"
        "- Lane 1A: Unpatched vulnerability, not yet disclosed publicly as a CVE. Requires responsible disclosure.\n"
        "- Lane 1B: Patched vulnerability, no CVE assigned yet. CVE can be filed citing the fix commit.\n"
        "- Lane 2: Ambiguous signal. Possible vulnerability but insufficient evidence. Revisit in 48 hours.\n"
        "- Lane 3: Noise. No security relevance.\n\n"
        "A change that only adds/modifies test files (no production code touched), or an unmerged/open\n"
        "PR, is weak evidence of a live vulnerability on its own — prefer Lane 2 or 3 for these unless\n"
        "the content itself demonstrates the vulnerable behavior is present in already-shipped code.\n\n"
        "For Lane 1A and 1B findings, also provide:\n"
        "- Vulnerability class (e.g. path traversal, SQL injection, deserialization)\n"
        "- Estimated CVSS score (0.0-10.0)\n"
        "- CWE identifier(s)\n"
        "- MITRE ATLAS technique if applicable\n"
        "- Whether severity is higher in agentic deployments than standard CVSS suggests, and why\n"
        "- One-sentence summary for the report\n\n"
        "Respond in JSON only, matching this shape:\n"
        "{\n"
        '  "lane": "1A|1B|2|3",\n'
        '  "vulnerability_class": "...",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|null",\n'
        '  "cvss": 0.0,\n'
        '  "cwe": ["CWE-XX"],\n'
        '  "atlas_technique": "AML.TXXXX|null",\n'
        '  "summary": "one sentence",\n'
        '  "agentic_uplift": "why severity is higher in agentic context, or null",\n'
        '  "validation_steps": ["1. ...", "2. ...", "3. ..."],\n'
        '  "reasoning": "brief internal reasoning for lane assignment"\n'
        "}"
    )


def _parse_json_response(raw: str) -> dict[str, Any]:
    cleaned = _FENCE_RE.sub("", raw.strip()).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise TriageSchemaError(f"triage response was not valid JSON: {exc}\nraw response: {raw[:500]}") from exc
    if not isinstance(data, dict):
        raise TriageSchemaError(f"triage response must be a JSON object, got {type(data).__name__}")
    return data


def _validate_schema(data: dict[str, Any]) -> None:
    lane = data.get("lane")
    if lane not in VALID_LANES:
        raise TriageSchemaError(f"triage response has invalid or missing lane: {lane!r} — must be one of {VALID_LANES}")
    if not data.get("summary"):
        raise TriageSchemaError("triage response is missing required field 'summary'")


async def triage_signal(
    *,
    package: str,
    layer: str,
    agentic_context: str | None,
    signal_type: str,
    signal_url: str,
    signal_content: str,
    extra_context: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    llm_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify one raw signal into a triage lane via `llm.router.complete()`.

    Enforces CLAUDE.md's non-negotiable rule: a Lane 1A/1B response missing
    validation_steps gets exactly one re-prompt; if it's still missing after
    that, the finding is downgraded to Lane 2 rather than written as Lane 1
    without validation steps.

    `extra_context` (optional): pipeline-verified facts about the signal
    (e.g. actual changed files, actual PR merge status) that the caller
    trusts more than the signal's own self-description — see
    pipelines/pre_cve.py's `_pipeline_verified_context()`.
    """
    user_prompt = build_user_prompt(
        package=package,
        layer=layer,
        agentic_context=agentic_context,
        signal_type=signal_type,
        signal_url=signal_url,
        signal_content=signal_content,
        extra_context=extra_context,
    )

    raw = await complete("triage", SYSTEM_PROMPT, user_prompt, provider=provider, model=model, llm_config=llm_config)
    data = _parse_json_response(raw)
    _validate_schema(data)

    if data["lane"] in ("1A", "1B") and not data.get("validation_steps"):
        console.print(
            f"[yellow]warning:[/yellow] Lane {data['lane']} triage response for {package!r} "
            "missing validation_steps — re-prompting once"
        )
        raw = await complete(
            "triage",
            SYSTEM_PROMPT,
            user_prompt + "\n\n" + _VALIDATION_STEPS_REPROMPT,
            provider=provider,
            model=model,
            llm_config=llm_config,
        )
        data = _parse_json_response(raw)
        _validate_schema(data)

        if data["lane"] in ("1A", "1B") and not data.get("validation_steps"):
            console.print(
                f"[yellow]warning:[/yellow] Lane {data['lane']} response for {package!r} still missing "
                "validation_steps after re-prompt — downgrading to Lane 2"
            )
            data["lane"] = "2"
            data["validation_steps"] = []

    return data


def build_finding(
    *,
    package: str,
    ecosystem: str,
    layer: str,
    source: str,
    signal_url: str,
    triage_result: dict[str, Any],
    raw_signal: str | None = None,
) -> Finding:
    """Map a `triage_signal()` result plus signal metadata onto a `Finding`.
    `agentic_uplift` always comes from the triage response (why *this*
    signal is worse in an agentic context) — the watchlist's general
    `agentic_context` is only used as triage input, not stored on the Finding."""
    lane = triage_result["lane"]
    finding_id = make_finding_id(package, source, signal_url)
    first_seen = now_iso()
    disclosure_deadline = None
    if lane == "1A":
        disclosure_deadline = (datetime.fromisoformat(first_seen) + timedelta(days=DISCLOSURE_WINDOW_DAYS)).isoformat()

    return Finding(
        id=finding_id,
        package=package,
        ecosystem=ecosystem,
        layer=layer,
        source=source,
        signal_url=signal_url,
        summary=triage_result.get("summary"),
        lane=lane,
        severity=triage_result.get("severity"),
        cvss=triage_result.get("cvss"),
        cwe=triage_result.get("cwe") or [],
        atlas_technique=triage_result.get("atlas_technique"),
        agentic_uplift=triage_result.get("agentic_uplift"),
        validation_steps=triage_result.get("validation_steps") or [],
        first_seen=first_seen,
        last_cve_crosscheck=now_iso(),
        disclosure_deadline=disclosure_deadline,
        raw_signal=raw_signal,
    )
