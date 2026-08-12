"""Shared scaffolding for the six class-based exploit harnesses —
cve-agent-spec.md §8.7, "2. --class {name} — class-based exploit harness."

Every harness in this package follows the same shape:
- researcher-supplied `target_module`/`target_callable` (and usually
  `target_param`) are REQUIRED — no harness ever guesses or LLM-generates
  these. Missing params -> MissingTargetParams, which the caller (main.py)
  surfaces as an "inconclusive" run, never a fabricated result.
- the package is installed once into a cached, immutable image
  (validation/image_cache.py — the only step with network access).
- the actual probe runs in a fresh, single-use, network_mode="none"/
  "isolated" container (validation/sandbox.py) — never "install" mode,
  since the exploit step itself needs no registry access.
- proof of the vulnerability is a random marker value the harness plants
  and then checks for, never a destructive action (no real file deleted,
  no real command with side effects beyond echoing the marker, no real
  target hit besides a throwaway listener/DB spun up inside the same
  container for this one run).
- dynamic values (module/callable/param names, marker, target package)
  cross into the sandbox only via SandboxConfig.env, never spliced into
  the driver script's source text — the same no-injection-surface pattern
  validation/pattern_confirmation.py already uses.
"""

from __future__ import annotations

import secrets

from validation._shared import ValidationOutcome
from validation.image_cache import ImageBuildError, ensure_install_image
from validation.sandbox import SandboxResult

DEFAULT_TIMEOUT_SECONDS = 120


class MissingTargetParams(ValueError):
    """Raised when --target-module/--target-callable weren't supplied. The
    researcher reads the exact file/function/line from the finding's
    validation_steps (CLAUDE.md's required format) and supplies them
    explicitly — no harness ever infers these on its own."""


def require_target(target_module: str | None, target_callable: str | None) -> None:
    if not target_module or not target_callable:
        raise MissingTargetParams(
            "This harness requires --target-module and --target-callable. "
            "Read this finding's validation_steps to determine the exact "
            "vulnerable module/function before running --class."
        )


def random_marker() -> str:
    return "CVEMARK-" + secrets.token_hex(8)


async def build_image(package: str, ecosystem: str, version: str) -> tuple[str | None, ValidationOutcome | None]:
    """(image_tag, None) on success, or (None, error_outcome) on failure —
    lets each harness do `image, err = await build_image(...); if err: return err`."""
    try:
        image = await ensure_install_image(package=package, ecosystem=ecosystem, version=version)
        return image, None
    except ImageBuildError as exc:
        return None, ValidationOutcome(
            result="error", summary=f"Could not install {package}=={version}: {exc}", log=str(exc)
        )


def format_log(result: SandboxResult) -> str:
    return f"$ {' '.join(result.command_run)}\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
