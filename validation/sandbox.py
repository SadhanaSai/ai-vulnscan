"""Hardened, ephemeral Docker sandbox — the isolation layer future Phase 7
(dynamic validation, on-demand only) will run on top of.

Scope note: this module is infrastructure, built and tested standalone
against benign fixtures only (alpine/busybox images, no real package
installs, no real Finding data). It does not run anything from the CVE
pipeline. Wiring an actual `validate` command that installs a real
flagged-vulnerable package and runs code from it is a separate, later step
that requires CLAUDE.md's constraint 1 ("static analysis only... non-
negotiable") to be explicitly amended first — that hasn't happened, and
this module doesn't assume it will.

Isolation ceiling, stated plainly: this environment has runc/containerd
only — no gVisor/Kata/microVM available. Every guarantee below is real
defense-in-depth (dropped capabilities, non-root, read-only rootfs,
isolated network namespace, resource/time limits, forced teardown), not a
hard boundary against a kernel-level container escape. Anyone extending
this into real exploit execution against untrusted code should assume a
sufficiently novel escape is possible and run it somewhere with zero
access to real credentials — never in the same environment as a live
GITHUB_TOKEN/ANTHROPIC_API_KEY/etc.

Every run is a single-use container: hardened, isolated, unconditionally
torn down (container + any per-run network), even on timeout or exception.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field

DOCKER_BIN = "docker"

# Hard-disallowed: no caller-supplied network mode ever resolves to the
# host network namespace. Only these three modes exist — there is no way
# to construct a config that requests --network host.
_NETWORK_MODES = {
    "none",      # docker --network none — no network stack at all
    "isolated",  # per-run docker network with --internal — no external
                 # routing; the container's own loopback only, never the host's
    "install",   # per-run bridge network with normal (non-internal) egress —
                 # for package-registry access; still never host networking.
                 # Note: this is unrestricted internet egress, not allow-
                 # listed to specific registry hosts — a stronger version
                 # would add an egress-filtering proxy. Documented gap, not
                 # a silent one.
}

DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS_LIMIT = 128
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_SCRATCH_SIZE_MB = 256
MAX_CAPTURED_OUTPUT_CHARS = 20000


class SandboxSecurityError(ValueError):
    """Raised when a sandbox configuration would violate a hard safety guarantee."""


@dataclass
class SandboxConfig:
    image: str
    command: list[str]
    network_mode: str = "none"
    memory: str = DEFAULT_MEMORY
    cpus: str = DEFAULT_CPUS
    pids_limit: int = DEFAULT_PIDS_LIMIT
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    run_as_uid: int = 65534  # nobody — sandboxed code never runs as root
    scratch_size_mb: int = DEFAULT_SCRATCH_SIZE_MB  # writable /sandbox tmpfs size
    # Explicit allow-list only. No function in this codebase populates this
    # from os.environ — the container never sees the parent process's
    # environment (GITHUB_TOKEN, GROQ_API_KEY, etc.) unless a caller
    # deliberately, individually adds a key here.
    env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.network_mode not in _NETWORK_MODES:
            raise SandboxSecurityError(
                f"network_mode must be one of {sorted(_NETWORK_MODES)} — got {self.network_mode!r}. "
                "Host networking is never permitted."
            )
        if self.run_as_uid == 0:
            raise SandboxSecurityError("run_as_uid must not be 0 (root) — sandboxed code never runs as root.")


@dataclass
class SandboxResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    command_run: list[str]  # the exact `docker run ...` invocation — full audit trail, nothing redacted


async def _run_subprocess(args: list[str], *, timeout: float) -> tuple[int | None, bytes, bytes, bool]:
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout, stderr, False
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return None, b"", b"", True


async def _create_network(mode: str, name: str) -> None:
    if mode == "isolated":
        await _run_subprocess([DOCKER_BIN, "network", "create", "--internal", name], timeout=30)
    elif mode == "install":
        await _run_subprocess([DOCKER_BIN, "network", "create", name], timeout=30)
    # mode == "none": no docker network object needed — handled via --network none directly


async def _remove_network(mode: str, name: str) -> None:
    if mode in ("isolated", "install"):
        await _run_subprocess([DOCKER_BIN, "network", "rm", name], timeout=30)


def _build_docker_args(config: SandboxConfig, *, run_id: str, network_arg: str) -> list[str]:
    args = [
        DOCKER_BIN, "run", "--rm", "--name", run_id,
        "--network", network_arg,
        "--memory", config.memory,
        "--cpus", config.cpus,
        "--pids-limit", str(config.pids_limit),
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs", f"/sandbox:rw,nosuid,size={config.scratch_size_mb}m",
        "--user", str(config.run_as_uid),
    ]
    for key, value in config.env.items():
        args += ["-e", f"{key}={value}"]
    args += [config.image, *config.command]
    return args


async def run_in_sandbox(config: SandboxConfig) -> SandboxResult:
    """Run one command in a single-use, hardened container.

    Guarantees enforced here, not just documented:
    - never --network host (SandboxConfig.__post_init__ rejects any other value)
    - never any host environment variable — config.env is the only source
    - always: no-new-privileges, all capabilities dropped, non-root user,
      read-only root filesystem (+ small /tmp and /sandbox tmpfs mounts for
      scratch space), memory/cpu/pids limits
    - a hard wall-clock timeout enforced from the outside (not left to the
      container to self-limit)
    - the container and any network created for it are always removed,
      even on timeout or exception
    """
    run_id = f"cve-sandbox-{uuid.uuid4().hex[:12]}"
    network_name = f"{run_id}-net"

    if config.network_mode in ("isolated", "install"):
        await _create_network(config.network_mode, network_name)
        network_arg = network_name
    else:
        network_arg = "none"

    args = _build_docker_args(config, run_id=run_id, network_arg=network_arg)

    start = time.monotonic()
    try:
        exit_code, stdout, stderr, timed_out = await _run_subprocess(args, timeout=config.timeout_seconds)
    finally:
        # --rm handles normal cleanup; force-remove covers the timeout-kill
        # path where --rm may not have finished, and is a harmless no-op
        # otherwise. Removing the network only after the container is gone.
        await _run_subprocess([DOCKER_BIN, "rm", "-f", run_id], timeout=15)
        await _remove_network(config.network_mode, network_name)

    duration = time.monotonic() - start
    return SandboxResult(
        exit_code=exit_code,
        stdout=stdout.decode(errors="replace")[:MAX_CAPTURED_OUTPUT_CHARS],
        stderr=stderr.decode(errors="replace")[:MAX_CAPTURED_OUTPUT_CHARS],
        timed_out=timed_out,
        duration_seconds=duration,
        command_run=args,
    )
