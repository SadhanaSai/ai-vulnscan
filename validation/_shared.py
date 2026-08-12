"""Shared types for validation/pattern_confirmation.py and
validation/harnesses/*.py — cve-agent-spec.md §8.7.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ValidationOutcome:
    result: str  # "confirmed" | "not_confirmed" | "inconclusive" | "error"
    summary: str
    log: str
