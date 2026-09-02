"""Agentic-tooling security-posture audit — cve-agent-spec.md §8.8 (standalone
feature, backs `python main.py audit`).

Distinct from the CVE-finding pipeline: areas (config/audit_checklist.yaml)
are architectural security-posture questions specific to agent/LLM-tool SDKs
and MCP-based tooling — "is the default permission mode safe", "are MCP
servers trust-isolated" — not CWE-shaped patterns hunted for via a confirmed
fix (that's hunter/scanner.py, Phase 5). A CONFIRMED_CONCERN here is not
automatically CVE-worthy (it can be a documented, opt-in tradeoff), so this
module never touches Finding/lane/status/disclosure — same precedent as
Phase 7 dynamic validation being informational-only.

clone -> read -> delete (CLAUDE.md constraint 4): shallow-clones the target
repo once per `run_audit()` call, reviews every requested area against a
bounded, keyword-pre-filtered slice of its source, then removes the clone
unconditionally, win or lose.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from llm.router import DEFAULT_SCAN_CONFIG_PATH, complete
from pipelines.http_utils import console
from state.db import AuditRun, record_audit_run

DEFAULT_CHECKLIST_PATH = DEFAULT_SCAN_CONFIG_PATH.parent / "audit_checklist.yaml"

VALID_LLM_VERDICTS = {"CONFIRMED_CONCERN", "LIKELY_BY_DESIGN", "NOT_FOUND"}
ALL_VERDICTS = VALID_LLM_VERDICTS | {"OUT_OF_SCOPE", "ERROR"}

# Sized to stay well under the smallest realistic per-minute token budget a
# researcher is likely to be running this against — Groq's on-demand free
# tier caps at 8000 TPM (prompt + completion combined), and a single area's
# request was measured at ~10-12k tokens before this was tightened (real
# `python main.py audit --all` run against anthropics/claude-agent-sdk-python,
# 2026-08-30 — every area failed with a 413/429 before this changed). ~10000
# chars of source is roughly 2500 tokens; with the system/question/schema
# text and a JSON response, a single area's request now comes in under
# ~4000 tokens total, leaving headroom under an 8000 TPM ceiling even before
# llm.router.complete()'s Groq pacing (GROQ_PACING_SECONDS) is factored in.
MAX_FILES_PER_AREA = 4            # bounds LLM prompt size/cost per area
MAX_FILE_CHARS = 3000             # per-file cap before concatenation
MAX_TOTAL_CONTEXT_CHARS = 10000   # total prompt budget across all selected files

# Sequential-call pacing against Groq's small per-minute token budget lives
# centrally in llm.router.complete() (GROQ_PACING_SECONDS), gated on
# provider == "groq" — shared by every phase, not reimplemented here. It
# used to be a bespoke constant in this module alone; centralizing it means
# scan's own triage/pattern_extraction/pattern_hunt calls get the same
# protection instead of only audit runs having it.

_SOURCE_GLOBS = ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx")
_SKIP_DIR_NAMES = {
    "node_modules", "__pycache__", ".git", "dist", "build",
    "vendor", "venv", ".venv", "docs", "examples",
}  # fmt: skip

# Deliberately not an exact-match set like _SKIP_DIR_NAMES above: a real
# `python main.py audit` run against anthropics/claude-agent-sdk-python
# (2026-08-30) had e2e-tests/conftest.py and a test docstring outscore and
# displace the actual vulnerable production file (subprocess_cli.py) as
# token_exposure evidence, because "e2e-tests" doesn't equal "tests" under
# exact matching — a small, keyword-dense test file can beat a large
# production file on a naive hit-count score even though it's the wrong
# evidence entirely. Matches "tests"/"test" as a whole path segment
# (allowing a "-"/"_" prefix like "e2e-tests", "unit_test") or as a
# filename suffix (test_x.py, x_test.py, x.spec.ts) — a substring match on
# bare "test" would also misfire on real production filenames like
# attestation.py or latest_version.py, which this avoids.
_TEST_PATH_RE = re.compile(r"(^|[-_/])tests?([-_/]|$)|_test\.|\.test\.|\.spec\.", re.IGNORECASE)

SYSTEM_PROMPT = (
    "You are a security researcher performing a static, read-only architectural "
    "review of an agent/LLM-tool SDK's source code against one specific security "
    "posture question. You return structured JSON only. Every evidence entry must "
    "cite an exact file path and line number(s) from the provided source — never "
    "invent a file, line, or behavior that isn't shown to you. If the provided "
    "source does not contain enough evidence to answer either way, say NOT_FOUND "
    "rather than guessing."
)


class AuditSchemaError(ValueError):
    """Raised when an audit-review response can't be parsed or is missing required fields."""


def load_audit_checklist(path: str | Path = DEFAULT_CHECKLIST_PATH) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text())
    return data.get("areas", {})


async def _clone_repo(repo: str, dest: Path) -> bool:
    """Shallow clone; True on success. Deliberately not shared with
    hunter/scanner.py's own `_clone_repo` (kept private there) — audit only
    ever needs the working tree, never the checked-out SHA, and importing a
    `_`-prefixed helper across two independent features would couple them
    for no real gain."""
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--quiet", f"https://github.com/{repo}.git", str(dest),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        console.print(f"[yellow]warning:[/yellow] git clone failed for {repo}: {stderr.decode(errors='replace')[:200]}")
        return False
    return True


def _iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for glob in _SOURCE_GLOBS:
        for path in root.rglob(glob):
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            if _TEST_PATH_RE.search(path.relative_to(root).as_posix()):
                continue
            files.append(path)
    return files


def _compile_keyword_patterns(keywords: list[str]) -> list[re.Pattern[str]]:
    """Word-boundary-wrapped, case-insensitive patterns — plain substring
    matching (the original implementation) was a real, observed bug: the
    keyword "token" matched inside "tokenizer"/"tokenizes" throughout
    subprocess_cli.py, and those false hits won the window-selection budget
    ahead of the actual, keyword-dense `--mcp-config` section much later in
    the same file (real `audit` run against anthropics/claude-agent-sdk-
    python, 2026-08-30). `\\b` is only applied on a side where the keyword
    itself starts/ends on a word character — a keyword like "exec(" or
    "shell=true" needs a boundary before "exec"/"shell" but can't sensibly
    require one immediately after "(" (not a word character to transition
    from)."""
    patterns = []
    for kw in keywords:
        escaped = re.escape(kw)
        prefix = r"\b" if kw[:1].isalnum() or kw[:1] == "_" else ""
        suffix = r"\b" if kw[-1:].isalnum() or kw[-1:] == "_" else ""
        patterns.append(re.compile(prefix + escaped + suffix, re.IGNORECASE))
    return patterns


def _score_file(path: Path, content: str, patterns: list[re.Pattern[str]]) -> int:
    """Path hits count double a content hit — a keyword in the filename
    (e.g. `permission_mode` in a path segment) is a stronger relevance
    signal than one incidental mention in a large file."""
    path_str = str(path)
    score = sum(2 for p in patterns if p.search(path_str))
    score += sum(len(p.findall(content)) for p in patterns)
    return score


# Generous cap on how much of a file gets read for *scoring* — distinct
# from MAX_FILE_CHARS (how much of a file's content actually gets sent to
# the LLM). Most real source files are far smaller than this; it only
# guards against a pathologically huge single file. Scoring off a file's
# full content (not a head-truncated slice) matters because the file
# selection race itself was previously blind to any keyword occurring past
# the truncation point — see WINDOW_CONTEXT_LINES below for why that was a
# real, observed bug, not a hypothetical one.
FILE_READ_CAP = 60000

# When a selected file is larger than MAX_FILE_CHARS, extract windows of
# this many lines of context around each keyword hit, rather than sending
# `content[:MAX_FILE_CHARS]`. Naive head-truncation was a real, observed
# bug: a real `python main.py audit` run against
# anthropics/claude-agent-sdk-python (2026-08-30) selected the correct file
# (subprocess_cli.py) for both token_exposure and subprocess_arg_injection,
# but the vulnerable code lives ~650 lines in — well past a 3000-char head
# slice, which only ever showed imports/docstring. The model correctly
# reported NOT_FOUND/LIKELY_BY_DESIGN based on what it could see; what it
# could see just never included the actual bug.
WINDOW_CONTEXT_LINES = 15


def _render_window_around_center(lines: list[str], start: int, end: int, center: int, budget: int) -> str:
    """Lines closest to `center` (the window's densest hit line) first,
    expanding outward until `budget` is used — so a window that doesn't
    fully fit still keeps its actual hit line, rather than always keeping
    `start` and truncating away from it (which, for a window opened wide
    enough by WINDOW_CONTEXT_LINES, could truncate before ever reaching
    the hit that justified the window in the first place)."""
    order = sorted(range(start, end), key=lambda i: abs(i - center))
    keep: set[int] = set()
    used = 0
    for i in order:
        line_text = f"{i + 1}: {lines[i]}\n"
        if keep and used + len(line_text) > budget:
            break
        keep.add(i)
        used += len(line_text)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in sorted(keep))


def _extract_relevant_windows(content: str, patterns: list[re.Pattern[str]], *, max_chars: int) -> str:
    """Line-windows centered on each keyword hit, merged where they
    overlap/touch. When the combined windows don't fit max_chars, the
    densest (most total keyword matches, not just most hit lines) windows
    are kept first — a real observed failure was an early, isolated,
    single-match hit filling the budget ahead of a keyword-dense cluster
    much later in the same file, purely because it came first in line
    order. A window that itself doesn't fit is trimmed from its densest
    line outward (_render_window_around_center), not from its start, so
    truncation can't cut away the exact hit that made the window relevant.
    Kept windows are re-sorted back to file order before joining
    (readability), separated by an explicit '...' marker so the model
    knows content is missing rather than reading a splice as contiguous.
    Falls back to a head slice only if the file is short enough to not
    need truncation at all, or if none of its lines actually contain a
    keyword (a path-only match, e.g. `permission_mode.py` with no in-file
    hit)."""
    if len(content) <= max_chars:
        return content

    lines = content.splitlines()
    line_hit_counts = [sum(len(p.findall(line)) for p in patterns) for line in lines]
    hit_lines = [i for i, count in enumerate(line_hit_counts) if count > 0]
    if not hit_lines:
        return content[:max_chars]

    windows: list[list[int]] = []  # [start, end, total_hits, densest_line]
    for i in hit_lines:
        start = max(0, i - WINDOW_CONTEXT_LINES)
        end = min(len(lines), i + WINDOW_CONTEXT_LINES + 1)
        if windows and start <= windows[-1][1]:
            w = windows[-1]
            w[1] = max(w[1], end)
            w[2] += line_hit_counts[i]
            if line_hit_counts[i] > line_hit_counts[w[3]]:
                w[3] = i
        else:
            windows.append([start, end, line_hit_counts[i], i])

    kept: list[tuple[int, str]] = []
    budget = max_chars
    for start, end, _hits, center in sorted(windows, key=lambda w: -w[2]):
        if budget <= 0:
            break
        full = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
        chunk = full if len(full) <= budget else _render_window_around_center(lines, start, end, center, budget)
        kept.append((start, chunk))
        budget -= len(chunk)

    kept.sort(key=lambda t: t[0])
    return "\n...\n".join(chunk for _start, chunk in kept)


def select_relevant_files(root: Path, keywords: list[str]) -> list[tuple[Path, str]]:
    """Top MAX_FILES_PER_AREA source files by keyword hit count (scored
    against up to FILE_READ_CAP of each file's content), capped at
    MAX_TOTAL_CONTEXT_CHARS combined once windowed for display. Returns []
    if nothing matches at all — callers must treat that as OUT_OF_SCOPE,
    never send an empty prompt and let the model guess at a verdict with no
    evidence."""
    patterns = _compile_keyword_patterns(keywords)
    scored: list[tuple[int, Path, str]] = []
    for path in _iter_source_files(root):
        try:
            content = path.read_text(errors="ignore")[:FILE_READ_CAP]
        except OSError:
            continue
        score = _score_file(path, content, patterns)
        if score > 0:
            scored.append((score, path, content))
    scored.sort(key=lambda t: -t[0])

    selected: list[tuple[Path, str]] = []
    budget = MAX_TOTAL_CONTEXT_CHARS
    for _score, path, content in scored[:MAX_FILES_PER_AREA]:
        if budget <= 0:
            break
        per_file_budget = min(MAX_FILE_CHARS, budget)
        chunk = _extract_relevant_windows(content, patterns, max_chars=per_file_budget)
        selected.append((path, chunk))
        budget -= len(chunk)
    return selected


def build_user_prompt(*, repo: str, area: str, question: str, files: list[tuple[Path, str]], root: Path) -> str:
    file_blocks = []
    for path, content in files:
        rel = path.relative_to(root).as_posix()
        file_blocks.append(f"--- {rel} ---\n{content}")
    joined = "\n\n".join(file_blocks)
    return (
        f"Repository: {repo}\n"
        f"Security posture question ({area}): {question}\n\n"
        f"Source files selected as most relevant to this question "
        f"(top {len(files)} by keyword match — may not be exhaustive, note this "
        f"in your evidence if something seems like it needs a file not shown here):\n\n"
        f"{joined}\n\n"
        "Answer the question above using only what's shown. Respond in JSON only, "
        "matching this shape:\n"
        "{\n"
        '  "verdict": "CONFIRMED_CONCERN|LIKELY_BY_DESIGN|NOT_FOUND",\n'
        '  "evidence": [{"file": "path/to/file.py", "lines": "10-15", "snippet": "...", "note": "..."}],\n'
        '  "impact": "one sentence on exploitability/impact if CONFIRMED_CONCERN, else empty string"\n'
        "}\n"
        "verdict must be NOT_FOUND if the provided source doesn't show a concern for this "
        "question, or LIKELY_BY_DESIGN if what you found is a documented/opt-in tradeoff "
        "rather than a bug. Never answer OUT_OF_SCOPE yourself — that verdict is decided "
        "before you're called, based on whether any relevant file existed at all."
    )


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _parse_json_response(raw: str) -> dict[str, Any]:
    cleaned = _FENCE_RE.sub("", raw.strip()).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise AuditSchemaError(f"audit response was not valid JSON: {exc}\nraw response: {raw[:500]}") from exc
    if not isinstance(data, dict):
        raise AuditSchemaError(f"audit response must be a JSON object, got {type(data).__name__}")
    if data.get("verdict") not in VALID_LLM_VERDICTS:
        raise AuditSchemaError(f"audit response has invalid or missing verdict: {data.get('verdict')!r}")
    return data


async def review_area(
    *,
    repo: str,
    ecosystem: str,
    area: str,
    question: str,
    root: Path,
    keywords: list[str],
    llm_provider: str | None,
    llm_model: str | None,
) -> AuditRun:
    """Review one checklist area against `root` (an already-cloned working
    tree). Returns OUT_OF_SCOPE without an LLM call if no file matched the
    area's keywords at all — a real "nothing to review" result, not a
    guess."""
    files = select_relevant_files(root, keywords)
    if not files:
        return AuditRun(
            repo=repo,
            ecosystem=ecosystem,
            area=area,
            verdict="OUT_OF_SCOPE",
            evidence=[],
            impact="No source files in this repo matched this area's keywords — nothing to review.",
        )

    user_prompt = build_user_prompt(repo=repo, area=area, question=question, files=files, root=root)
    raw = await complete("agentic_audit", SYSTEM_PROMPT, user_prompt, provider=llm_provider, model=llm_model)
    try:
        data = _parse_json_response(raw)
    except AuditSchemaError as exc:
        # One re-prompt on a malformed/invalid response before giving up —
        # same pattern as triage/classifier.py and hunter/scanner.py's
        # hunt_candidate() for their own schema violations. If it's still
        # bad after this, _parse_json_response raises again and propagates
        # to run_audit()'s per-area catch (verdict="ERROR") — no fabrication.
        console.print(f"[yellow]warning:[/yellow] audit response for area {area!r} was malformed — re-prompting once: {exc}")
        raw = await complete(
            "agentic_audit",
            SYSTEM_PROMPT,
            user_prompt + f"\n\nYour previous response was invalid ({exc}). Return ONLY the JSON "
            "object, with verdict exactly one of CONFIRMED_CONCERN, LIKELY_BY_DESIGN, or NOT_FOUND.",
            provider=llm_provider,
            model=llm_model,
        )
        data = _parse_json_response(raw)

    return AuditRun(
        repo=repo,
        ecosystem=ecosystem,
        area=area,
        verdict=data["verdict"],
        evidence=data.get("evidence") or [],
        impact=data.get("impact") or None,
    )


@dataclass
class AuditResult:
    repo: str
    ecosystem: str
    runs: list[AuditRun]


async def run_audit(
    *,
    repo: str,
    ecosystem: str,
    areas: list[str],
    db: Any,
    checklist_path: str | Path = DEFAULT_CHECKLIST_PATH,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    dry_run: bool = False,
) -> AuditResult:
    """Clone `repo` once, review every requested area against it, persist
    each as an append-only AuditRun (unless dry_run), then unconditionally
    remove the clone. A clone failure or a per-area review failure both
    record verdict="ERROR" (never OUT_OF_SCOPE, which is reserved for "no
    relevant files existed") — the researcher sees an honest failure, not a
    fabricated result."""
    checklist = load_audit_checklist(checklist_path)
    unknown = [a for a in areas if a not in checklist]
    if unknown:
        raise ValueError(f"Unknown audit area(s) {unknown} — must be one of {sorted(checklist)}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="cve-audit-"))
    runs: list[AuditRun] = []
    try:
        cloned = await _clone_repo(repo, tmp_dir)
        if not cloned:
            for area in areas:
                run = AuditRun(
                    repo=repo,
                    ecosystem=ecosystem,
                    area=area,
                    verdict="ERROR",
                    evidence=[],
                    impact=f"Could not clone {repo} — repo not found or not accessible.",
                )
                if not dry_run:
                    record_audit_run(db, run)
                runs.append(run)
            return AuditResult(repo=repo, ecosystem=ecosystem, runs=runs)

        for area in areas:
            spec = checklist[area]
            try:
                run = await review_area(
                    repo=repo,
                    ecosystem=ecosystem,
                    area=area,
                    question=spec["question"],
                    root=tmp_dir,
                    keywords=spec.get("keywords", []),
                    llm_provider=llm_provider,
                    llm_model=llm_model,
                )
            except Exception as exc:
                console.print(f"[yellow]warning:[/yellow] audit failed for area {area!r}: {exc}")
                run = AuditRun(repo=repo, ecosystem=ecosystem, area=area, verdict="ERROR", evidence=[], impact=str(exc)[:500])
            if not dry_run:
                record_audit_run(db, run)
            runs.append(run)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)  # CLAUDE.md: delete cloned source after analysis

    return AuditResult(repo=repo, ecosystem=ecosystem, runs=runs)
