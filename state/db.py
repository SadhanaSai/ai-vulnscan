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

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    package TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    layer TEXT NOT NULL,
    source TEXT NOT NULL,
    signal_url TEXT,
    summary TEXT,
    lane TEXT NOT NULL,
    severity TEXT,
    cvss REAL,
    cwe TEXT,               -- JSON array as text
    atlas_technique TEXT,
    cve_id TEXT,
    agentic_uplift TEXT,
    validation_steps TEXT,  -- JSON array as text; required (non-null) for lane 1A/1B
    first_seen TEXT NOT NULL,
    last_checked TEXT NOT NULL,
    last_cve_crosscheck TEXT,
    disclosure_deadline TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    cve_draft TEXT,
    pattern_id TEXT,
    raw_signal TEXT
);

CREATE TABLE IF NOT EXISTS patterns (
    id TEXT PRIMARY KEY,
    vulnerability_class TEXT NOT NULL,
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
    created_at TEXT NOT NULL,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watch_queue (
    finding_id TEXT PRIMARY KEY,
    next_check TEXT NOT NULL,
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
