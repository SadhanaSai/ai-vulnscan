"""SQLite state layer — cve-agent-spec.md §9.

The only module in this project that touches the findings / patterns /
watch_queue / disclosure_log / scan_log tables. Every other module goes
through the functions here (CLAUDE.md code quality standards).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import sqlite_utils

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "state" / "cve_agent.db"
DEFAULT_LIBRARY_PATH = PROJECT_ROOT / "patterns" / "library.json"

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    -- package/ecosystem/layer/source/lane/first_seen/last_checked are
    -- required in practice (Finding is a dataclass with no default for
    -- any of them) but are deliberately NOT declared NOT NULL here:
    -- upsert_finding() goes through sqlite_utils' upsert(), which writes
    -- new rows as `INSERT OR IGNORE INTO findings(id) VALUES (...)`
    -- followed by an UPDATE — a NOT NULL constraint on any other column
    -- makes that first insert silently fail (OR IGNORE swallows the
    -- constraint violation) and the finding is never persisted. Column
    -- presence is enforced at the Finding dataclass boundary instead.
    package TEXT,
    ecosystem TEXT,
    layer TEXT,
    source TEXT,
    signal_url TEXT,
    summary TEXT,
    lane TEXT,
    severity TEXT,
    cvss REAL,
    cwe TEXT,               -- JSON array as text
    atlas_technique TEXT,
    cve_id TEXT,
    agentic_uplift TEXT,
    validation_steps TEXT,  -- JSON array as text; required (non-null) for lane 1A/1B
    first_seen TEXT,
    last_checked TEXT,
    last_cve_crosscheck TEXT,
    disclosure_deadline TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    cve_draft TEXT,
    pattern_id TEXT,
    raw_signal TEXT
);

CREATE TABLE IF NOT EXISTS patterns (
    id TEXT PRIMARY KEY,
    -- Same reasoning as findings above: no NOT NULL on columns without a
    -- DEFAULT, since upsert_pattern() goes through the same sqlite_utils
    -- upsert() insert-or-ignore-then-update path.
    vulnerability_class TEXT,
    layer TEXT,
    trigger_desc TEXT,
    vulnerable_shape TEXT,
    safe_shape TEXT,
    agentic_context TEXT,
    cwe TEXT,
    atlas_technique TEXT,
    source_finding_id TEXT,
    source_commit_url TEXT,
    confirmed_hits TEXT,
    false_positives INTEGER DEFAULT 0,
    created_at TEXT,
    last_updated TEXT
);

CREATE TABLE IF NOT EXISTS watch_queue (
    finding_id TEXT PRIMARY KEY,
    -- Same reasoning again: schedule_watch_check()/bump_watch_check() upsert.
    next_check TEXT,
    check_count INTEGER DEFAULT 0,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS disclosure_log (
    finding_id TEXT PRIMARY KEY,
    disclosed_to TEXT,
    disclosed_at TEXT,
    deadline TEXT,
    cve_filed_at TEXT,
    cve_id_assigned TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    packages_scanned INTEGER,
    findings_new INTEGER,
    findings_lane1 INTEGER,
    findings_lane2 INTEGER,
    llm_calls_by_provider TEXT,  -- JSON object, e.g. {"groq": 12, "claude": 3, "ollama": 0}
    duration_seconds REAL
);

CREATE TABLE IF NOT EXISTS dynamic_validation_runs (  -- Phase 7, §8.7 — append-only audit log
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    depth TEXT NOT NULL,        -- "pattern_confirmation" | "class_exploit"
    vulnerability_class TEXT,   -- set only for depth="class_exploit"
    result TEXT NOT NULL,       -- "confirmed" | "not_confirmed" | "inconclusive" | "error"
    summary TEXT,
    log TEXT,                   -- full command + output audit trail, nothing redacted
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS scan_runs (  -- per-package checkpointing for `scan`
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mode TEXT NOT NULL,            -- "scan" (matches log_scan's mode values)
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,          -- "running" | "complete" | "failed"
    packages_total INTEGER NOT NULL,
    llm_provider TEXT
);

CREATE TABLE IF NOT EXISTS scan_progress (  -- append-only, one row per (run, package, phase)
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    package TEXT NOT NULL,
    phase TEXT NOT NULL,           -- "known_cve" | "pre_cve" | "pattern_extraction" | "pattern_hunt"
    status TEXT NOT NULL,          -- "done" | "error"
    findings_new INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    completed_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(id)
);
"""

# Finding fields that are stored as JSON text and need encode/decode at the boundary.
_JSON_FIELDS = ("cwe", "validation_steps")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_finding_id(package: str, source: str, signal: str) -> str:
    """id: sha256 of (package + source + signal) — CLAUDE.md Finding.id."""
    return hashlib.sha256(f"{package}|{source}|{signal}".encode("utf-8")).hexdigest()


@dataclass
class Finding:
    id: str
    package: str
    ecosystem: str
    layer: str
    source: str
    signal_url: str | None = None
    summary: str | None = None
    lane: str = "known"  # "1A" | "1B" | "2" | "3" | "known"
    severity: str | None = None
    cvss: float | None = None
    cwe: list[str] = field(default_factory=list)
    atlas_technique: str | None = None
    cve_id: str | None = None
    agentic_uplift: str | None = None
    validation_steps: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=now_iso)
    # Always overwritten by upsert_finding() right before a write, so no
    # meaningful default exists before a Finding is actually persisted.
    last_checked: str | None = None
    last_cve_crosscheck: str | None = None
    disclosure_deadline: str | None = None
    status: str = "new"
    cve_draft: str | None = None
    pattern_id: str | None = None
    raw_signal: str | None = None

    def to_row(self) -> dict[str, Any]:
        # sqlite_utils auto-JSON-encodes list/dict values on insert/upsert,
        # so cwe/validation_steps need no manual encoding here.
        return asdict(self)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Finding":
        # SCHEMA and this dataclass are kept in exact 1:1 column correspondence,
        # so every row from `findings` maps directly to a Finding's fields.
        row = dict(row)
        for f in _JSON_FIELDS:
            row[f] = json.loads(row[f]) if row.get(f) else []
        return cls(**row)


# Pattern's `trigger` field maps to the `trigger_desc` DB column (SCHEMA
# avoids the bare name `trigger` — reserved-adjacent in SQL) — CLAUDE.md's
# canonical Pattern dataclass names it `trigger`, so the row<->object mapping
# translates it at the boundary, same pattern as Finding's JSON fields.
_PATTERN_JSON_FIELDS = ("cwe", "confirmed_hits")


@dataclass
class Pattern:
    id: str
    vulnerability_class: str
    layer: str | None = None
    trigger: str | None = None
    vulnerable_shape: str | None = None
    safe_shape: str | None = None
    agentic_context: str | None = None
    cwe: list[str] = field(default_factory=list)
    atlas_technique: str | None = None
    source_finding_id: str | None = None
    source_commit_url: str | None = None
    confirmed_hits: list[str] = field(default_factory=list)
    false_positives: int = 0
    created_at: str = field(default_factory=now_iso)
    last_updated: str = field(default_factory=now_iso)

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["trigger_desc"] = row.pop("trigger")
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Pattern":
        row = dict(row)
        row["trigger"] = row.pop("trigger_desc", None)
        for f in _PATTERN_JSON_FIELDS:
            row[f] = json.loads(row[f]) if row.get(f) else []
        return cls(**row)


@dataclass
class DynamicValidationRun:
    """Phase 7 (§8.7) — one on-demand `python main.py validate` invocation.
    Append-only: a finding accumulates many of these over time, unlike the
    single mutable Finding row. Never touches Finding.lane/status."""

    finding_id: str
    depth: str  # "pattern_confirmation" | "class_exploit"
    result: str  # "confirmed" | "not_confirmed" | "inconclusive" | "error"
    vulnerability_class: str | None = None
    summary: str | None = None
    log: str | None = None
    requested_at: str = field(default_factory=now_iso)
    id: int | None = None

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row.pop("id")  # autoincrement — never set explicitly on insert
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "DynamicValidationRun":
        return cls(**dict(row))


@dataclass
class ScanRun:
    """One `python main.py scan` invocation — created at the start so
    per-package progress (ScanProgress) has something to hang off of even
    if the process dies before the run finishes normally."""

    mode: str
    packages_total: int
    llm_provider: str | None = None
    status: str = "running"  # "running" | "complete" | "failed"
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    id: int | None = None

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row.pop("id")
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "ScanRun":
        return cls(**dict(row))


@dataclass
class ScanProgress:
    """Append-only: one row per (run, package, phase) as each package
    finishes — the actual checkpoint. Never touches Finding/scan_log."""

    run_id: int
    package: str
    phase: str  # "known_cve" | "pre_cve" | "pattern_extraction" | "pattern_hunt"
    status: str  # "done" | "error"
    findings_new: int = 0
    error: str | None = None
    completed_at: str = field(default_factory=now_iso)
    id: int | None = None

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row.pop("id")
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "ScanProgress":
        return cls(**dict(row))


def get_db(path: str | Path = DEFAULT_DB_PATH) -> sqlite_utils.Database:
    """Open (creating if needed) the state DB and ensure the schema exists."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return sqlite_utils.Database(conn)


def finding_exists(db: sqlite_utils.Database, finding_id: str) -> bool:
    return db["findings"].count_where("id = ?", [finding_id]) > 0


def upsert_finding(db: sqlite_utils.Database, finding: Finding) -> None:
    finding.last_checked = now_iso()
    db["findings"].upsert(finding.to_row(), pk="id")


def get_finding(db: sqlite_utils.Database, finding_id: str) -> Finding | None:
    rows = list(db["findings"].rows_where("id = ?", [finding_id]))
    return Finding.from_row(rows[0]) if rows else None


def delete_finding(db: sqlite_utils.Database, finding_id: str) -> None:
    """Remove a finding and any watch-queue entry for it (e.g. purging confirmed bad data)."""
    db["findings"].delete_where("id = ?", [finding_id])
    remove_from_watch_queue(db, finding_id)


def list_findings(
    db: sqlite_utils.Database,
    *,
    lane: str | None = None,
    status: str | None = None,
    package: str | None = None,
) -> list[Finding]:
    where_clauses: list[str] = []
    args: list[Any] = []
    if lane is not None:
        where_clauses.append("lane = ?")
        args.append(lane)
    if status is not None:
        where_clauses.append("status = ?")
        args.append(status)
    if package is not None:
        where_clauses.append("package = ?")
        args.append(package)
    where = " AND ".join(where_clauses) if where_clauses else None
    rows = db["findings"].rows_where(where, args) if where else db["findings"].rows
    return [Finding.from_row(r) for r in rows]


def log_scan(
    db: sqlite_utils.Database,
    *,
    mode: str,
    packages_scanned: int,
    findings_new: int,
    findings_lane1: int = 0,
    findings_lane2: int = 0,
    llm_calls_by_provider: dict[str, int] | None = None,
    duration_seconds: float = 0.0,
) -> None:
    db["scan_log"].insert(
        {
            "run_at": now_iso(),
            "mode": mode,
            "packages_scanned": packages_scanned,
            "findings_new": findings_new,
            "findings_lane1": findings_lane1,
            "findings_lane2": findings_lane2,
            "llm_calls_by_provider": llm_calls_by_provider or {},
            "duration_seconds": duration_seconds,
        }
    )


WATCH_RECHECK_HOURS = 48  # cve-agent-spec.md §8.3 / CLAUDE.md lane table: Lane 2 revisits in 48h


def schedule_watch_check(db: sqlite_utils.Database, finding_id: str, *, hours: int = WATCH_RECHECK_HOURS) -> None:
    """Add (or refresh) a Lane 2 finding's watch_queue entry, due `hours` from now."""
    existing = list(db["watch_queue"].rows_where("finding_id = ?", [finding_id]))
    check_count = existing[0]["check_count"] if existing else 0
    next_check = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    db["watch_queue"].upsert(
        {"finding_id": finding_id, "next_check": next_check, "check_count": check_count}, pk="finding_id"
    )


def bump_watch_check(db: sqlite_utils.Database, finding_id: str, *, hours: int = WATCH_RECHECK_HOURS) -> None:
    """Still Lane 2 after a re-check: push next_check forward and increment check_count."""
    existing = list(db["watch_queue"].rows_where("finding_id = ?", [finding_id]))
    check_count = (existing[0]["check_count"] if existing else 0) + 1
    next_check = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    db["watch_queue"].upsert(
        {"finding_id": finding_id, "next_check": next_check, "check_count": check_count}, pk="finding_id"
    )


def due_watch_items(db: sqlite_utils.Database, *, now: str | None = None) -> list[dict[str, Any]]:
    """watch_queue rows whose next_check has passed — backs `python main.py watch`."""
    now = now or now_iso()
    return list(db["watch_queue"].rows_where("next_check <= ?", [now]))


def remove_from_watch_queue(db: sqlite_utils.Database, finding_id: str) -> None:
    if db["watch_queue"].count_where("finding_id = ?", [finding_id]) > 0:
        db["watch_queue"].delete(finding_id)


def status_summary(db: sqlite_utils.Database) -> dict[str, Any]:
    """Finding counts by lane and status — backs `python main.py status`."""
    by_lane = {row["lane"]: row["n"] for row in db.query("SELECT lane, COUNT(*) AS n FROM findings GROUP BY lane")}
    by_status = {row["status"]: row["n"] for row in db.query("SELECT status, COUNT(*) AS n FROM findings GROUP BY status")}
    return {
        "total_findings": sum(by_lane.values()),
        "by_lane": by_lane,
        "by_status": by_status,
    }


# --- patterns (cve-agent-spec.md §8.4/§8.5, Phase 4/5) -----------------------


def upsert_pattern(db: sqlite_utils.Database, pattern: Pattern) -> None:
    pattern.last_updated = now_iso()
    db["patterns"].upsert(pattern.to_row(), pk="id")


def get_pattern(db: sqlite_utils.Database, pattern_id: str) -> Pattern | None:
    rows = list(db["patterns"].rows_where("id = ?", [pattern_id]))
    return Pattern.from_row(rows[0]) if rows else None


def list_patterns(db: sqlite_utils.Database) -> list[Pattern]:
    if "patterns" not in db.table_names():
        return []
    return [Pattern.from_row(r) for r in db["patterns"].rows]


def record_pattern_hit(db: sqlite_utils.Database, pattern_id: str, finding_id: str) -> None:
    pattern = get_pattern(db, pattern_id)
    if pattern is None:
        return
    if finding_id not in pattern.confirmed_hits:
        pattern.confirmed_hits.append(finding_id)
    upsert_pattern(db, pattern)


def record_pattern_false_positive(db: sqlite_utils.Database, pattern_id: str) -> None:
    pattern = get_pattern(db, pattern_id)
    if pattern is None:
        return
    pattern.false_positives += 1
    upsert_pattern(db, pattern)


def export_pattern_library(db: sqlite_utils.Database, path: str | Path = DEFAULT_LIBRARY_PATH) -> None:
    """Rewrite patterns/library.json (git-tracked, CLAUDE.md file structure)
    from the current patterns table — the DB is the live/authoritative copy
    (confirmed_hits and false_positives change as the hunter runs), the JSON
    file is a full re-export snapshot kept in sync on every pattern change."""
    patterns = [asdict(p) for p in list_patterns(db)]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(patterns, indent=2, sort_keys=True) + "\n")


# --- disclosure log (cve-agent-spec.md §8.6/§12, Phase 6) --------------------


def record_disclosure(db: sqlite_utils.Database, finding_id: str, disclosed_to: str, *, deadline: str | None) -> None:
    """backs `python main.py disclose` — records who a Lane 1A finding was
    reported to and when, alongside its existing disclosure_deadline."""
    db["disclosure_log"].upsert(
        {
            "finding_id": finding_id,
            "disclosed_to": disclosed_to,
            "disclosed_at": now_iso(),
            "deadline": deadline,
            "cve_filed_at": None,
            "cve_id_assigned": None,
        },
        pk="finding_id",
    )


def get_disclosure(db: sqlite_utils.Database, finding_id: str) -> dict[str, Any] | None:
    rows = list(db["disclosure_log"].rows_where("finding_id = ?", [finding_id]))
    return rows[0] if rows else None


def list_disclosures(db: sqlite_utils.Database) -> list[dict[str, Any]]:
    if "disclosure_log" not in db.table_names():
        return []
    return list(db["disclosure_log"].rows)


# --- dynamic validation runs (cve-agent-spec.md §8.7, Phase 7 — on-demand only) ---


def record_validation_run(db: sqlite_utils.Database, run: DynamicValidationRun) -> DynamicValidationRun:
    """Append-only insert — never upsert. Every `validate` invocation gets
    its own row, regardless of result (including "error")."""
    row_id = db["dynamic_validation_runs"].insert(run.to_row()).last_pk
    run.id = row_id
    return run


def list_validation_runs(db: sqlite_utils.Database, finding_id: str) -> list[DynamicValidationRun]:
    if "dynamic_validation_runs" not in db.table_names():
        return []
    rows = db["dynamic_validation_runs"].rows_where("finding_id = ?", [finding_id], order_by="requested_at")
    return [DynamicValidationRun.from_row(r) for r in rows]


def latest_validation_run(db: sqlite_utils.Database, finding_id: str) -> DynamicValidationRun | None:
    runs = list_validation_runs(db, finding_id)
    return runs[-1] if runs else None


def all_latest_validation_runs(db: sqlite_utils.Database) -> dict[str, DynamicValidationRun]:
    """One most-recent run per finding_id — backs the report's dynamic
    validation section without an N+1 query per finding."""
    if "dynamic_validation_runs" not in db.table_names():
        return {}
    latest: dict[str, DynamicValidationRun] = {}
    for row in db["dynamic_validation_runs"].rows_where(order_by="requested_at"):
        latest[row["finding_id"]] = DynamicValidationRun.from_row(row)
    return latest


# --- scan checkpointing (per-package progress for `python main.py scan`) -----


def start_scan_run(db: sqlite_utils.Database, run: ScanRun) -> ScanRun:
    run.id = db["scan_runs"].insert(run.to_row()).last_pk
    return run


def finish_scan_run(db: sqlite_utils.Database, run_id: int, *, status: str) -> None:
    db["scan_runs"].update(run_id, {"status": status, "finished_at": now_iso()})


def get_scan_run(db: sqlite_utils.Database, run_id: int) -> ScanRun | None:
    rows = list(db["scan_runs"].rows_where("id = ?", [run_id]))
    return ScanRun.from_row(rows[0]) if rows else None


def latest_scan_run(db: sqlite_utils.Database) -> ScanRun | None:
    if "scan_runs" not in db.table_names():
        return None
    rows = list(db["scan_runs"].rows_where(order_by="-id", limit=1))
    return ScanRun.from_row(rows[0]) if rows else None


def record_scan_progress(db: sqlite_utils.Database, progress: ScanProgress) -> ScanProgress:
    progress.id = db["scan_progress"].insert(progress.to_row()).last_pk
    return progress


def list_scan_progress(db: sqlite_utils.Database, run_id: int) -> list[ScanProgress]:
    if "scan_progress" not in db.table_names():
        return []
    rows = db["scan_progress"].rows_where("run_id = ?", [run_id], order_by="id")
    return [ScanProgress.from_row(r) for r in rows]
