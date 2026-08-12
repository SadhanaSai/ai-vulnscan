"""Tests for Phase 7 (dynamic validation) — cve-agent-spec.md §8.7.

Covers: dynamic_validation_runs DB CRUD (and that it never mutates a
Finding's lane/status), CWE -> harness-class classification, the
--class/--force mismatch gate and other main.py `validate` dispatch paths,
each harness's require_target() enforcement, image_cache tag/sanitization
logic, and one real (non-mocked) Docker integration test that builds a
cached install image for a tiny, permanently-available benign PyPI package
— never a real flagged-vulnerable package.
"""

from __future__ import annotations

import asyncio
import shutil

import pytest
from click.testing import CliRunner

import main as main_module
from state import db
from validation import classify, image_cache
from validation.harnesses import HARNESS_MODULES, get_harness_runner
from validation.harnesses._shared import MissingTargetParams
from validation.pattern_confirmation import confirm_pattern

_DOCKER_AVAILABLE = shutil.which("docker") is not None
pytestmark_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available in this environment")


def _finding(**overrides) -> db.Finding:
    base = dict(id="f1", package="pkg", ecosystem="pypi", layer="mcp", source="github_commit", lane="1A", cwe=["CWE-22"])
    base.update(overrides)
    return db.Finding(**base)


# --- dynamic_validation_runs DB CRUD -----------------------------------------------


def test_record_and_list_validation_runs(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    db.record_validation_run(
        database, db.DynamicValidationRun(finding_id="f1", depth="pattern_confirmation", result="confirmed", summary="s1")
    )
    db.record_validation_run(
        database,
        db.DynamicValidationRun(
            finding_id="f1", depth="class_exploit", vulnerability_class="path_traversal", result="not_confirmed", summary="s2"
        ),
    )

    runs = db.list_validation_runs(database, "f1")
    assert len(runs) == 2
    assert runs[0].id is not None and runs[1].id is not None and runs[0].id != runs[1].id


def test_latest_validation_run_returns_most_recent(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    db.record_validation_run(database, db.DynamicValidationRun(finding_id="f1", depth="pattern_confirmation", result="not_confirmed", summary="first"))
    db.record_validation_run(database, db.DynamicValidationRun(finding_id="f1", depth="pattern_confirmation", result="confirmed", summary="second"))

    assert db.latest_validation_run(database, "f1").summary == "second"


def test_all_latest_validation_runs_one_per_finding(tmp_path):
    database = db.get_db(tmp_path / "test.db")
    db.record_validation_run(database, db.DynamicValidationRun(finding_id="f1", depth="pattern_confirmation", result="confirmed", summary="a"))
    db.record_validation_run(database, db.DynamicValidationRun(finding_id="f2", depth="pattern_confirmation", result="inconclusive", summary="b"))
    db.record_validation_run(database, db.DynamicValidationRun(finding_id="f1", depth="pattern_confirmation", result="not_confirmed", summary="c"))

    latest = db.all_latest_validation_runs(database)
    assert set(latest.keys()) == {"f1", "f2"}
    assert latest["f1"].summary == "c"


def test_validation_run_never_touches_finding_lane_or_status(tmp_path):
    """§8.7: 'Explicitly does not touch lane/status/ready_to_file.'"""
    database = db.get_db(tmp_path / "test.db")
    finding = _finding(status="new", lane="1A")
    db.upsert_finding(database, finding)

    db.record_validation_run(
        database, db.DynamicValidationRun(finding_id=finding.id, depth="pattern_confirmation", result="confirmed", summary="s")
    )

    reloaded = db.get_finding(database, finding.id)
    assert reloaded.status == "new"
    assert reloaded.lane == "1A"


# --- classify.py: CWE -> harness class ----------------------------------------------


def test_infer_vulnerability_classes_matches_cwe():
    assert classify.infer_vulnerability_classes(_finding(cwe=["CWE-22"])) == ["path_traversal"]


def test_infer_vulnerability_classes_empty_when_no_cwe():
    assert classify.infer_vulnerability_classes(_finding(cwe=[])) == []


def test_infer_vulnerability_classes_non_harness_cwe_returns_empty():
    # CWE-74 is prompt_injection — not one of the six harness-eligible classes.
    assert classify.infer_vulnerability_classes(_finding(cwe=["CWE-74"])) == []


def test_class_matches_finding_true_and_false():
    finding = _finding(cwe=["CWE-89"])
    assert classify.class_matches_finding("sql_injection", finding) is True
    assert classify.class_matches_finding("path_traversal", finding) is False


# --- harness require_target() gate — all six, no Docker needed ---------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("class_name", sorted(HARNESS_MODULES))
async def test_harness_requires_target_params(class_name):
    runner = get_harness_runner(class_name)
    with pytest.raises(MissingTargetParams):
        await runner(
            _finding(), package="pkg", ecosystem="pypi", version="1.0.0", target_module=None, target_callable=None
        )


# --- pattern_confirmation.py ---------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_pattern_inconclusive_when_no_class_inferred():
    finding = _finding(cwe=["CWE-9999-NOT-A-REAL-CWE"])
    outcome = await confirm_pattern(finding, package="pkg", ecosystem="pypi", version="1.0.0")
    assert outcome.result == "inconclusive"


# --- image_cache.py: pure tag/sanitization logic --------------------------------------


def test_image_tag_is_deterministic_and_sanitized():
    tag1 = image_cache.image_tag("Some.Package", "pypi", "1.2.3")
    tag2 = image_cache.image_tag("Some.Package", "pypi", "1.2.3")
    assert tag1 == tag2
    assert tag1.startswith("cve-sandbox-install-pypi-")
    assert " " not in tag1
    assert tag1 == tag1.lower()


def test_image_tag_differs_by_version():
    assert image_cache.image_tag("pkg", "pypi", "1.0.0") != image_cache.image_tag("pkg", "pypi", "2.0.0")


# --- main.py `validate` dispatch: gate/force/docker-missing paths (CliRunner) -------


def test_validate_errors_on_unknown_finding(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "get_db", lambda: database)

    result = CliRunner().invoke(main_module.cli, ["validate", "--finding-id", "does-not-exist"])
    assert result.exit_code != 0
    assert "no finding with id" in result.output


def test_validate_errors_without_docker(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    finding = _finding()
    db.upsert_finding(database, finding)

    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.setattr(main_module.shutil, "which", lambda name: None)

    result = CliRunner().invoke(main_module.cli, ["validate", "--finding-id", finding.id])
    assert result.exit_code != 0
    assert "docker not found" in result.output


def test_validate_class_mismatch_without_force_blocks(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    finding = _finding(cwe=["CWE-89"])  # sql_injection, not path_traversal
    db.upsert_finding(database, finding)

    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.setattr(main_module.shutil, "which", lambda name: "/usr/bin/docker")

    result = CliRunner().invoke(main_module.cli, ["validate", "--finding-id", finding.id, "--class", "path_traversal"])
    assert result.exit_code != 0
    assert "does not match" in result.output
    assert db.list_validation_runs(database, finding.id) == []  # blocked before anything ran


async def _fake_resolve_version(finding, *, override_version=None):
    return None, "test stub: version resolution skipped"


def test_validate_force_bypasses_mismatch_gate_and_records_run(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    finding = _finding(cwe=["CWE-89"])
    db.upsert_finding(database, finding)

    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.setattr(main_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(main_module, "resolve_version", _fake_resolve_version)

    result = CliRunner().invoke(
        main_module.cli, ["validate", "--finding-id", finding.id, "--class", "path_traversal", "--force"]
    )
    assert result.exit_code == 0

    runs = db.list_validation_runs(database, finding.id)
    assert len(runs) == 1
    assert runs[0].depth == "class_exploit"
    assert runs[0].vulnerability_class == "path_traversal"
    assert runs[0].result == "inconclusive"  # no version resolved -> honestly inconclusive, not a guess


def test_validate_missing_target_params_records_inconclusive_not_error(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    finding = _finding(cwe=["CWE-22"])
    db.upsert_finding(database, finding)

    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.setattr(main_module.shutil, "which", lambda name: "/usr/bin/docker")

    # --version override avoids any real network call for version resolution;
    # require_target() then fires before any Docker/image-build work happens.
    result = CliRunner().invoke(
        main_module.cli,
        ["validate", "--finding-id", finding.id, "--class", "path_traversal", "--version", "1.0.0"],
    )
    assert result.exit_code == 0

    runs = db.list_validation_runs(database, finding.id)
    assert len(runs) == 1
    assert runs[0].result == "inconclusive"
    assert "target-module" in runs[0].summary.lower() or "target_module" in runs[0].summary.lower()


def test_validate_default_depth_has_no_class_recorded(tmp_path, monkeypatch):
    database = db.get_db(tmp_path / "test.db")
    finding = _finding(cwe=["CWE-9999-NOT-A-REAL-CWE"])  # no harness-eligible class -> confirm_pattern goes inconclusive fast
    db.upsert_finding(database, finding)

    monkeypatch.setattr(main_module, "get_db", lambda: database)
    monkeypatch.setattr(main_module.shutil, "which", lambda name: "/usr/bin/docker")

    result = CliRunner().invoke(main_module.cli, ["validate", "--finding-id", finding.id, "--version", "1.0.0"])
    assert result.exit_code == 0

    runs = db.list_validation_runs(database, finding.id)
    assert len(runs) == 1
    assert runs[0].depth == "pattern_confirmation"
    assert runs[0].vulnerability_class is None
    assert runs[0].result == "inconclusive"


# --- real Docker integration: install-image build/cache mechanics ------------------


@pytestmark_docker
@pytest.mark.asyncio
async def test_ensure_install_image_builds_and_caches_benign_package():
    # "six" — a tiny, single-file, permanently-published PyPI package, pinned
    # to an old stable release. This only proves the build/cache mechanics
    # work; it is never a flagged-vulnerable package and no finding data is
    # involved.
    tag = await image_cache.ensure_install_image(package="six", ecosystem="pypi", version="1.16.0")
    try:
        assert await image_cache.image_exists(tag)
        tag_again = await image_cache.ensure_install_image(package="six", ecosystem="pypi", version="1.16.0")
        assert tag_again == tag  # cached, not rebuilt
    finally:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rmi", "-f", tag, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
