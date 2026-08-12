"""Pattern hunter — cve-agent-spec.md §8.5 (Phase 5).

For each pattern in the library, clones each applicable watchlist package's
repo locally (CLAUDE.md: git clone -> read -> delete), runs a cheap
AST (Python) / regex (JS/TS) pre-filter keyed on the pattern's
vulnerability_class keyword list (config/scan_config.yaml) to find candidate
functions, then confirms each candidate via
`llm.router.complete(phase="pattern_hunt", ...)`. A confirmed HIGH/MEDIUM
match triggers a sibling scan (§8.5 Step 3): every other enabled package in
the same layer gets checked for the same pattern. Confirmed matches become
new Findings — always Lane 1A (see note on `_build_match_finding`), always
after the mandatory §8.2a cross-check, same as every other signal type.
"""

from __future__ import annotations

import ast
import asyncio
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from llm.router import DEFAULT_SCAN_CONFIG_PATH, complete
from pipelines.http_utils import console
from pipelines.known_cve import cross_check_existing_cve
from state.db import (
    Finding,
    Pattern,
    make_finding_id,
    now_iso,
    record_pattern_false_positive,
    record_pattern_hit,
    upsert_finding,
)
from triage.classifier import DISCLOSURE_WINDOW_DAYS

SYSTEM_PROMPT = (
    "You are a security researcher checking whether a function exhibits a known vulnerability pattern.\n"
    "You return structured JSON only.\n"
    "If you answer YES, you must provide exact line numbers and a validation_steps list "
    "the researcher can follow to confirm the finding manually."
)

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

SUSPICIOUS_PARAM_NAMES = {
    "user_input", "filename", "file_name", "path", "filepath", "file_path",
    "query", "cmd", "command", "url", "input", "data", "payload", "content",
}  # fmt: skip

MAX_FILES_SCANNED_PER_PACKAGE = 300
MAX_FILE_SIZE_BYTES = 200_000
MAX_CANDIDATES_PER_PACKAGE = 15  # bounds LLM calls per (package, pattern)
_JS_FUNC_BODY_LINES = 60  # heuristic span sent to the LLM — exact brace-matching isn't worth the complexity here

_JS_GLOBS = ("*.js", "*.ts", "*.jsx", "*.tsx")
_SKIP_DIR_NAMES = {"node_modules", "test", "tests", "__pycache__", ".git", "dist", "build", "vendor", "venv", ".venv"}

_JS_FUNC_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)"
    r"|^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"
)


class HuntSchemaError(ValueError):
    """Raised when a pattern-hunt response can't be parsed or is missing required fields."""


# --- config ------------------------------------------------------------------


def load_vulnerability_classes(path: str | Path = DEFAULT_SCAN_CONFIG_PATH) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text())
    return data.get("vulnerability_classes", {})


def _pattern_applies_to_package(pattern: Pattern, pkg: dict[str, Any], vuln_classes: dict[str, dict]) -> bool:
    if pattern.layer and pkg.get("layer") != pattern.layer:
        return False
    return vuln_classes.get(pattern.vulnerability_class, {}).get("enabled", True)


# --- git clone (CLAUDE.md: clone -> read -> delete) --------------------------


async def _clone_repo(repo: str, dest: Path) -> str | None:
    """Shallow clone; returns the checked-out commit SHA, or None on failure."""
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--quiet", f"https://github.com/{repo}.git", str(dest),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        console.print(f"[yellow]warning:[/yellow] git clone failed for {repo}: {stderr.decode(errors='replace')[:200]}")
        return None

    sha_proc = await asyncio.create_subprocess_exec(
        "git", "-C", str(dest), "rev-parse", "HEAD",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await sha_proc.communicate()
    sha = out.decode().strip()
    return sha or None


# --- AST/regex pre-filter -----------------------------------------------------


def _python_candidates(source: str, keywords: list[str]) -> list[tuple[str, str, int, int]]:
    """Returns (function_name, function_source, start_line, end_line)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    lowered_keywords = [k.lower() for k in keywords]
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_names.update(alias.name.split(".")[0].lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_names.add(node.module.split(".")[0].lower())

    file_imports_relevant = any(any(kw in imp for kw in lowered_keywords) for imp in imported_names)

    candidates = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_names = {a.arg.lower() for a in node.args.args}
            if file_imports_relevant or (param_names & SUSPICIOUS_PARAM_NAMES):
                segment = ast.get_source_segment(source, node)
                if segment:
                    end_line = getattr(node, "end_lineno", node.lineno)
                    candidates.append((node.name, segment, node.lineno, end_line))
    return candidates


def _js_candidates(source: str, keywords: list[str]) -> list[tuple[str, str, int, int]]:
    """Regex-based, not a real parser — spec §8.5 explicitly allows regex for
    npm packages. Returns (function_name, function_source, start_line, end_line)."""
    lowered_keywords = [k.lower() for k in keywords]
    file_relevant = any(kw in source.lower() for kw in lowered_keywords)
    lines = source.splitlines()
    candidates = []
    for i, line in enumerate(lines):
        m = _JS_FUNC_RE.match(line)
        if not m:
            continue
        name = m.group(1) or m.group(3) or "anonymous"
        params = (m.group(2) if m.group(1) else m.group(4)) or ""
        has_suspicious_param = any(
            p.strip().split(":")[0].strip().lower() in SUSPICIOUS_PARAM_NAMES for p in params.split(",") if p.strip()
        )
        if file_relevant or has_suspicious_param:
            end = min(i + _JS_FUNC_BODY_LINES, len(lines))
            candidates.append((name, "\n".join(lines[i:end]), i + 1, end))
    return candidates


def _iter_source_files(root: Path, ecosystem: str) -> list[Path]:
    globs = ["*.py"] if ecosystem == "pypi" else list(_JS_GLOBS)
    files: list[Path] = []
    for g in globs:
        for path in root.rglob(g):
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= MAX_FILES_SCANNED_PER_PACKAGE:
                return files
    return files


def _find_candidates(
    root: Path, ecosystem: str, keywords: list[str], *, path_prefix: str | None = None
) -> list[tuple[Path, str, str, int, int]]:
    """Returns (filepath, function_name, function_source, start_line, end_line),
    capped at MAX_CANDIDATES_PER_PACKAGE to bound LLM calls.

    `path_prefix` (watchlist.yaml, for monorepo-hosted packages) scopes the
    walk to that subdirectory — without it, hunting a package like
    azure-ai-inference would scan the entire azure-sdk-for-python monorepo
    and could misattribute an unrelated sibling package's code here."""
    finder = _python_candidates if ecosystem == "pypi" else _js_candidates
    scan_root = (root / path_prefix) if path_prefix else root
    if not scan_root.is_dir():
        return []
    results: list[tuple[Path, str, str, int, int]] = []
    for path in _iter_source_files(scan_root, ecosystem):
        try:
            source = path.read_text(errors="ignore")
        except OSError:
            continue
        for name, segment, start, end in finder(source, keywords):
            results.append((path, name, segment, start, end))
            if len(results) >= MAX_CANDIDATES_PER_PACKAGE:
                return results
    return results


# --- LLM semantic scan ---------------------------------------------------------


def build_user_prompt(*, pattern: Pattern, function_source: str) -> str:
    return (
        f"Vulnerability pattern: {pattern.id}\n"
        f"Class: {pattern.vulnerability_class}\n"
        f"Trigger condition: {pattern.trigger}\n"
        f"Vulnerable code shape: {pattern.vulnerable_shape}\n"
        f"Safe code shape: {pattern.safe_shape}\n"
        f"Agentic context: {pattern.agentic_context or 'none provided'}\n\n"
        f"Function to analyze:\n{function_source}\n\n"
        "Does this function exhibit the vulnerability described in the pattern?\n"
        "Answer YES or NO, with:\n"
        "- The specific line(s) where the vulnerability exists (if YES)\n"
        "- The reason (either way)\n"
        "- Confidence: HIGH | MEDIUM | LOW\n\n"
        "Respond in JSON only, matching this shape:\n"
        "{\n"
        '  "match": true,\n'
        '  "confidence": "HIGH|MEDIUM|LOW",\n'
        '  "lines": [42, 43],\n'
        '  "explanation": "...",\n'
        '  "validation_steps": ["1. ...", "2. ..."]\n'
        "}"
    )


def _parse_json_response(raw: str) -> dict[str, Any]:
    cleaned = _FENCE_RE.sub("", raw.strip()).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise HuntSchemaError(f"pattern hunt response was not valid JSON: {exc}\nraw response: {raw[:500]}") from exc
    if not isinstance(data, dict) or "match" not in data:
        raise HuntSchemaError(f"pattern hunt response missing required field 'match': {raw[:500]}")
    return data


async def hunt_candidate(
    pattern: Pattern, function_source: str, *, provider: str | None, model: str | None
) -> dict[str, Any]:
    user_prompt = build_user_prompt(pattern=pattern, function_source=function_source)
    raw = await complete("pattern_hunt", SYSTEM_PROMPT, user_prompt, provider=provider, model=model)
    data = _parse_json_response(raw)

    if data.get("match") and not data.get("validation_steps"):
        console.print(f"[yellow]warning:[/yellow] pattern hunt match for {pattern.id} missing validation_steps — re-prompting once")
        raw = await complete(
            "pattern_hunt",
            SYSTEM_PROMPT,
            user_prompt + "\n\nvalidation_steps is required when match is true. Return the same JSON with validation_steps populated.",
            provider=provider,
            model=model,
        )
        data = _parse_json_response(raw)
        if data.get("match") and not data.get("validation_steps"):
            console.print(f"[yellow]warning:[/yellow] pattern hunt match for {pattern.id} still missing validation_steps after re-prompt — discarding")
            data["match"] = False

    return data


def _build_match_finding(
    pkg: dict[str, Any], pattern: Pattern, *, finding_id: str, signal_url: str, func_name: str, hunt_result: dict[str, Any]
) -> Finding:
    """Confirmed pattern-hunter matches are scanned from the package's
    current default-branch source, so a match means the vulnerable shape is
    still present today — there is no sense in which it could already be
    "patched" (that would mean it wouldn't have matched). So unlike
    commit/issue/PR-sourced findings, hunter matches are always Lane 1A
    (unpatched, undisclosed by us), never 1B."""
    first_seen = now_iso()
    return Finding(
        id=finding_id,
        package=pkg["name"],
        ecosystem=pkg["ecosystem"],
        layer=pkg["layer"],
        source="pattern_hunt",
        signal_url=signal_url,
        summary=f"{pattern.vulnerability_class} pattern match ({pattern.id}) in {func_name}",
        lane="1A",
        cwe=pattern.cwe,
        atlas_technique=pattern.atlas_technique,
        agentic_uplift=pkg.get("agentic_context") or pattern.agentic_context,
        validation_steps=hunt_result.get("validation_steps") or [],
        first_seen=first_seen,
        last_cve_crosscheck=now_iso(),
        disclosure_deadline=(datetime.fromisoformat(first_seen) + timedelta(days=DISCLOSURE_WINDOW_DAYS)).isoformat(),
        pattern_id=pattern.id,
        raw_signal=hunt_result.get("explanation"),
    )


@dataclass
class PatternHuntResult:
    patterns_checked: int = 0
    scans_run: int = 0  # one per (pattern, package) pair actually cloned/scanned
    candidates_scanned: int = 0
    findings_new: int = 0
    known_cve_matches: int = 0
    llm_calls: int = 0


async def hunt_pattern_in_package(
    pattern: Pattern,
    pkg: dict[str, Any],
    *,
    db: Any,
    github_token: str | None,
    keywords: list[str],
    llm_provider: str | None,
    llm_model: str | None,
    dry_run: bool,
    result: PatternHuntResult,
    existing_ids: set[str],
) -> list[Finding]:
    """Clone pkg's repo, pre-filter, LLM-confirm candidates for `pattern`.
    Returns newly confirmed findings (already persisted unless dry_run)."""
    repo = pkg.get("repo")
    if not repo:
        return []

    tmp_dir = Path(tempfile.mkdtemp(prefix="cve-hunt-"))
    new_findings: list[Finding] = []
    try:
        sha = await _clone_repo(repo, tmp_dir)
        if sha is None:
            return []

        candidates = _find_candidates(tmp_dir, pkg["ecosystem"], keywords, path_prefix=pkg.get("path_prefix"))
        result.candidates_scanned += len(candidates)

        for filepath, func_name, func_source, start, end in candidates:
            rel_path = filepath.relative_to(tmp_dir).as_posix()
            signal_url = f"https://github.com/{repo}/blob/{sha}/{rel_path}#L{start}-L{end}"
            finding_id = make_finding_id(pkg["name"], "pattern_hunt", signal_url)
            if finding_id in existing_ids:
                continue

            try:
                hunt_result = await hunt_candidate(pattern, func_source, provider=llm_provider, model=llm_model)
            except Exception as exc:
                console.print(f"[yellow]warning:[/yellow] pattern hunt failed for {pkg['name']!r} {rel_path}:{func_name}: {exc}")
                continue
            result.llm_calls += 1

            if not hunt_result.get("match") or hunt_result.get("confidence") not in ("HIGH", "MEDIUM"):
                if hunt_result.get("match"):
                    record_pattern_false_positive(db, pattern.id)  # LOW confidence — logged, not filed
                continue

            existing_ids.add(finding_id)

            # §8.2a — mandatory, before this signal is allowed anywhere near a lane assignment.
            cve_id = await cross_check_existing_cve(pkg["name"], pkg["ecosystem"], repo=repo, github_token=github_token)
            if cve_id:
                finding = Finding(
                    id=finding_id,
                    package=pkg["name"],
                    ecosystem=pkg["ecosystem"],
                    layer=pkg["layer"],
                    source="pattern_hunt",
                    signal_url=signal_url,
                    summary=f"{pattern.vulnerability_class} pattern match ({pattern.id}) in {func_name}",
                    lane="known",
                    cve_id=cve_id,
                    agentic_uplift=pkg.get("agentic_context"),
                    last_cve_crosscheck=now_iso(),
                    pattern_id=pattern.id,
                )
                result.known_cve_matches += 1
            else:
                finding = _build_match_finding(
                    pkg, pattern, finding_id=finding_id, signal_url=signal_url, func_name=func_name, hunt_result=hunt_result
                )
                record_pattern_hit(db, pattern.id, finding_id)

            if not dry_run:
                upsert_finding(db, finding)
            result.findings_new += 1
            new_findings.append(finding)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)  # CLAUDE.md: delete cloned source after analysis

    return new_findings


async def run_pattern_hunt(
    packages: list[dict[str, Any]],
    patterns: list[Pattern],
    *,
    db: Any,
    github_token: str | None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    concurrency: int = 2,  # git clones are heavier than HTTP calls — keep this modest
    dry_run: bool = False,
) -> PatternHuntResult:
    """cve-agent-spec.md §8.5 — hunt every given pattern across every
    applicable enabled package in `packages`, with sibling-layer expansion
    (Step 3) on any confirmed match, scoped to `packages`."""
    result = PatternHuntResult()
    if not patterns:
        return result

    vuln_classes = load_vulnerability_classes()
    existing_ids = {row["id"] for row in db["findings"].rows_where(select="id")}
    targets = [p for p in packages if p.get("enabled", True) and p.get("repo")]
    semaphore = asyncio.Semaphore(concurrency)
    scanned_pairs: set[tuple[str, str]] = set()  # (pattern.id, package_name) — guards cycles across sibling triggers

    async def scan_one(pattern: Pattern, pkg: dict[str, Any]) -> None:
        key = (pattern.id, pkg["name"])
        if key in scanned_pairs:
            return
        scanned_pairs.add(key)
        async with semaphore:
            keywords = vuln_classes.get(pattern.vulnerability_class, {}).get("keywords", [])
            new_findings = await hunt_pattern_in_package(
                pattern, pkg, db=db, github_token=github_token, keywords=keywords,
                llm_provider=llm_provider, llm_model=llm_model, dry_run=dry_run,
                result=result, existing_ids=existing_ids,
            )
        result.scans_run += 1
        if any(f.lane == "1A" for f in new_findings):
            # §8.5 Step 3 — sibling scan: same layer, same pattern, every other enabled package.
            siblings = [p for p in targets if p["layer"] == pkg["layer"] and p["name"] != pkg["name"]]
            await asyncio.gather(*(scan_one(pattern, sib) for sib in siblings))

    for pattern in patterns:
        result.patterns_checked += 1
        applicable = [p for p in targets if _pattern_applies_to_package(pattern, p, vuln_classes)]
        await asyncio.gather(*(scan_one(pattern, p) for p in applicable))

    return result
