"""Registry of the six fixed class-exploit harnesses — cve-agent-spec.md
§8.7. `--class` only ever accepts one of these; there is no generic or
LLM-improvised exploit-generation path anywhere in this project, and there
will not be one added later without CLAUDE.md's constraint 1 being
revisited explicitly.
"""

from __future__ import annotations

import importlib
from typing import Awaitable, Callable

from validation._shared import ValidationOutcome

HARNESS_MODULES = {
    "path_traversal": "validation.harnesses.path_traversal",
    "command_injection": "validation.harnesses.command_injection",
    "sql_injection": "validation.harnesses.sql_injection",
    "deserialization": "validation.harnesses.deserialization",
    "ssrf": "validation.harnesses.ssrf",
    "arbitrary_file_rw": "validation.harnesses.arbitrary_file_rw",
}


def get_harness_runner(vulnerability_class: str) -> Callable[..., Awaitable[ValidationOutcome]]:
    """Resolves a --class name to its run() coroutine. Raises KeyError for
    anything outside the fixed six — main.py's CLI option already restricts
    --class to click.Choice(HARNESS_MODULES), this is defense-in-depth."""
    module = importlib.import_module(HARNESS_MODULES[vulnerability_class])
    return module.run
