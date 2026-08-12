"""Tests for validation/sandbox.py — the isolation layer future Phase 7
(dynamic validation) will run on top of.

Two tiers: fast config-validation tests (no Docker needed — pure Python
guarantees), and real integration tests against the actual Docker daemon
(skipped if Docker isn't available) that prove the guarantees hold in
practice, not just in the code that constructs the command line. These use
only benign public images (alpine) — nothing from the CVE pipeline.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from validation import sandbox

_DOCKER_AVAILABLE = shutil.which("docker") is not None

pytestmark_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available in this environment")


# --- config validation (no Docker required) --------------------------------------


def test_config_rejects_host_network():
    with pytest.raises(sandbox.SandboxSecurityError):
        sandbox.SandboxConfig(image="alpine:3.19", command=["true"], network_mode="host")


def test_config_rejects_arbitrary_network_mode():
    with pytest.raises(sandbox.SandboxSecurityError):
        sandbox.SandboxConfig(image="alpine:3.19", command=["true"], network_mode="bridge")


def test_config_rejects_root_uid():
    with pytest.raises(sandbox.SandboxSecurityError):
        sandbox.SandboxConfig(image="alpine:3.19", command=["true"], run_as_uid=0)


def test_config_accepts_valid_network_modes():
    for mode in ("none", "isolated", "install"):
        config = sandbox.SandboxConfig(image="alpine:3.19", command=["true"], network_mode=mode)
        assert config.network_mode == mode


def test_config_default_env_is_empty_not_inherited():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["true"])
    assert config.env == {}


def test_build_docker_args_never_contains_network_host():
    for mode in ("none", "isolated", "install"):
        config = sandbox.SandboxConfig(image="alpine:3.19", command=["true"], network_mode=mode)
        args = sandbox._build_docker_args(config, run_id="test-run", network_arg="whatever")
        assert "host" not in args
        assert "--cap-drop" in args and "ALL" in args
        assert "--read-only" in args
        assert "--security-opt" in args and "no-new-privileges" in args
        assert "--user" in args and "65534" in args


def test_build_docker_args_includes_resource_limits():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["true"], memory="256m", cpus="0.5", pids_limit=64)
    args = sandbox._build_docker_args(config, run_id="test-run", network_arg="none")
    assert "--memory" in args and "256m" in args
    assert "--cpus" in args and "0.5" in args
    assert "--pids-limit" in args and "64" in args


def test_build_docker_args_only_forwards_explicit_env():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["true"], env={"ONLY_THIS": "value"})
    args = sandbox._build_docker_args(config, run_id="test-run", network_arg="none")
    assert "-e" in args
    assert "ONLY_THIS=value" in args
    # exactly one -e flag — no host env vars silently added alongside it
    assert args.count("-e") == 1


@pytest.mark.asyncio
async def test_run_subprocess_timeout_returns_timed_out_flag(monkeypatch):
    exit_code, stdout, stderr, timed_out = await sandbox._run_subprocess(["sleep", "5"], timeout=0.1)
    assert timed_out is True
    assert exit_code is None


# --- real Docker integration tests -------------------------------------------------


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_never_leaks_host_env_vars(monkeypatch):
    monkeypatch.setenv("FAKE_SECRET_FOR_TEST", "should-never-appear-in-sandbox")
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["env"], network_mode="none", timeout_seconds=30)
    result = await sandbox.run_in_sandbox(config)

    assert "FAKE_SECRET_FOR_TEST" not in result.stdout
    assert "should-never-appear-in-sandbox" not in result.stdout


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_runs_as_non_root():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["id", "-u"], network_mode="none", timeout_seconds=30)
    result = await sandbox.run_in_sandbox(config)
    assert result.stdout.strip() == "65534"


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_root_filesystem_is_read_only():
    config = sandbox.SandboxConfig(
        image="alpine:3.19", command=["sh", "-c", "touch /this-should-fail 2>&1 || echo READONLY_CONFIRMED"],
        network_mode="none", timeout_seconds=30,
    )
    result = await sandbox.run_in_sandbox(config)
    assert "READONLY_CONFIRMED" in result.stdout


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_scratch_dir_is_writable():
    config = sandbox.SandboxConfig(
        image="alpine:3.19", command=["sh", "-c", "echo hello > /sandbox/f.txt && cat /sandbox/f.txt"],
        network_mode="none", timeout_seconds=30,
    )
    result = await sandbox.run_in_sandbox(config)
    assert result.exit_code == 0
    assert "hello" in result.stdout


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_isolated_network_has_no_internet_access():
    config = sandbox.SandboxConfig(
        image="alpine:3.19",
        command=["sh", "-c", "wget -T 3 -q -O- https://1.1.1.1 >/dev/null 2>&1 && echo REACHED || echo UNREACHABLE"],
        network_mode="isolated", timeout_seconds=30,
    )
    result = await sandbox.run_in_sandbox(config)
    assert "UNREACHABLE" in result.stdout
    assert "REACHED" not in result.stdout


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_none_network_has_no_loopback_reachable_service():
    config = sandbox.SandboxConfig(
        image="alpine:3.19", command=["sh", "-c", "ip addr show 2>&1 || echo NO_NETWORK_STACK"],
        network_mode="none", timeout_seconds=30,
    )
    result = await sandbox.run_in_sandbox(config)
    # --network none still gives a loopback-only interface with no route out;
    # confirm no non-loopback interface (e.g. eth0) is present
    assert "eth0" not in result.stdout


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_enforces_timeout_and_removes_container():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["sleep", "30"], network_mode="none", timeout_seconds=2)
    result = await sandbox.run_in_sandbox(config)

    assert result.timed_out is True
    assert result.duration_seconds < 10  # well under the sleep 30 — actually killed, not waited out

    run_id = result.command_run[result.command_run.index("--name") + 1]
    check = subprocess.run(["docker", "ps", "-a", "--filter", f"name={run_id}", "--format", "{{.Names}}"], capture_output=True, text=True)
    assert run_id not in check.stdout  # container was actually removed, not left behind


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_removes_container_after_normal_completion():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["echo", "done"], network_mode="none", timeout_seconds=30)
    result = await sandbox.run_in_sandbox(config)

    run_id = result.command_run[result.command_run.index("--name") + 1]
    check = subprocess.run(["docker", "ps", "-a", "--filter", f"name={run_id}", "--format", "{{.Names}}"], capture_output=True, text=True)
    assert run_id not in check.stdout


@pytestmark_docker
@pytest.mark.asyncio
async def test_sandbox_removes_per_run_network():
    config = sandbox.SandboxConfig(image="alpine:3.19", command=["echo", "done"], network_mode="isolated", timeout_seconds=30)
    result = await sandbox.run_in_sandbox(config)

    run_id = result.command_run[result.command_run.index("--name") + 1]
    network_name = f"{run_id}-net"
    check = subprocess.run(["docker", "network", "ls", "--filter", f"name={network_name}", "--format", "{{.Name}}"], capture_output=True, text=True)
    assert network_name not in check.stdout
