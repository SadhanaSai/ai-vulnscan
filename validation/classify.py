"""Maps a Finding's CWE list to a Phase 7 harness class — cve-agent-spec.md
§8.7: "`--class` ... rejects anything else outright, including a request
that doesn't match the finding's own recorded vulnerability_class/CWE."

Finding has no explicit `vulnerability_class` field (CLAUDE.md's Finding
schema only carries `cwe`), so the mapping goes CWE -> class via
config/scan_config.yaml's per-class `cwe` lists — the same source of truth
hunter/scanner.py's AST pre-filter already uses.
"""

from __future__ import annotations

from pathlib import Path

from hunter.scanner import load_vulnerability_classes
from llm.router import DEFAULT_SCAN_CONFIG_PATH
from state.db import Finding

# The only six classes a sandbox-execution harness exists for —
# cve-agent-spec.md §8.7. Any other class (prompt_injection, tool_poisoning,
# supply_chain, credential_exposure, agent_state_deserialization, rug_pull)
# doesn't fit this model and has no harness, by design.
HARNESS_CLASSES = (
    "path_traversal",
    "command_injection",
    "sql_injection",
    "deserialization",
    "ssrf",
    "arbitrary_file_rw",
)


def infer_vulnerability_classes(finding: Finding, *, config_path: str | Path = DEFAULT_SCAN_CONFIG_PATH) -> list[str]:
    """All harness-eligible classes whose CWE list overlaps this finding's
    `cwe` field. Usually zero or one; CWE-502 is shared by `deserialization`
    and the non-harness `agent_state_deserialization`, so this can return
    more than one class — callers decide how to handle ambiguity."""
    if not finding.cwe:
        return []
    vuln_classes = load_vulnerability_classes(config_path)
    finding_cwes = set(finding.cwe)
    return [
        cls
        for cls in HARNESS_CLASSES
        if finding_cwes & set(vuln_classes.get(cls, {}).get("cwe", []))
    ]


def class_matches_finding(
    requested_class: str, finding: Finding, *, config_path: str | Path = DEFAULT_SCAN_CONFIG_PATH
) -> bool:
    """True if `requested_class` is among the classes inferred from the
    finding's own recorded CWE(s) — the §8.7 --class mismatch gate."""
    return requested_class in infer_vulnerability_classes(finding, config_path=config_path)
