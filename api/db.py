"""Tiny SQLite layer. Two tables: ``alerts`` and ``events``.

Each event carries the alert_id it belongs to (or NULL for baseline noise) and
its full payload as a JSON blob, so we don't have to enumerate every possible
field across attack types.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DB_PATH = Path(__file__).parent.parent / "lab.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def session() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_id TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    description TEXT NOT NULL,
    triage_steps TEXT NOT NULL,
    matched_event_count INTEGER NOT NULL,
    affected_accounts TEXT NOT NULL,
    src_ips TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence REAL NOT NULL,
    runbook_md TEXT,
    runbook_generated_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    alert_id TEXT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    username TEXT,
    payload TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_alert ON events(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
"""


def init_db() -> None:
    with session() as conn:
        conn.executescript(SCHEMA)


def reset_db() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


def insert_events(events: list[dict], alert_event_ids: dict[str, str]) -> None:
    """Insert events, linking each one to its alert (if any) via event_id."""
    with session() as conn:
        for ev in events:
            conn.execute(
                """
                INSERT OR REPLACE INTO events
                    (event_id, alert_id, event_type, timestamp, src_ip, username, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev["event_id"],
                    alert_event_ids.get(ev["event_id"]),
                    ev.get("event_type", ""),
                    ev.get("timestamp", ""),
                    ev.get("src_ip"),
                    ev.get("username") or ev.get("actor_username"),
                    json.dumps(ev),
                ),
            )


def insert_alert(alert: dict) -> None:
    with session() as conn:
        conn.execute(
            """
            INSERT INTO alerts (
                id, rule_id, rule_name, severity, mitre_id, mitre_technique,
                description, triage_steps, matched_event_count,
                affected_accounts, src_ips, first_seen, last_seen, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["id"], alert["rule_id"], alert["rule_name"], alert["severity"],
                alert["mitre_id"], alert["mitre_technique"], alert["description"],
                json.dumps(alert["triage_steps"]),
                alert["matched_event_count"],
                json.dumps(alert["affected_accounts"]),
                json.dumps(alert["src_ips"]),
                alert["first_seen"], alert["last_seen"], alert["confidence"],
            ),
        )


def _row_to_alert(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "rule_id": row["rule_id"],
        "rule_name": row["rule_name"],
        "severity": row["severity"],
        "mitre_id": row["mitre_id"],
        "mitre_technique": row["mitre_technique"],
        "description": row["description"],
        "triage_steps": json.loads(row["triage_steps"]),
        "matched_event_count": row["matched_event_count"],
        "affected_accounts": json.loads(row["affected_accounts"]),
        "src_ips": json.loads(row["src_ips"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "confidence": row["confidence"],
        "created_at": row["created_at"],
        "runbook_generated_at": row["runbook_generated_at"],
    }


def list_alerts() -> list[dict]:
    with session() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC, first_seen DESC"
        ).fetchall()
        return [_row_to_alert(r) for r in rows]


def get_alert(alert_id: str) -> dict | None:
    with session() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        alert = _row_to_alert(row)
        events = conn.execute(
            "SELECT payload FROM events WHERE alert_id = ? ORDER BY timestamp ASC",
            (alert_id,),
        ).fetchall()
        alert["events"] = [json.loads(e["payload"]) for e in events]
        alert["runbook_md"] = row["runbook_md"]
        return alert


def save_runbook(alert_id: str, markdown: str) -> None:
    with session() as conn:
        conn.execute(
            """
            UPDATE alerts
            SET runbook_md = ?,
                runbook_generated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
            WHERE id = ?
            """,
            (markdown, alert_id),
        )


def stats() -> dict:
    with session() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ).fetchall()
        sev = {r["severity"]: r["c"] for r in sev_rows}
        techniques = [
            r["mitre_id"] for r in conn.execute(
                "SELECT DISTINCT mitre_id FROM alerts"
            ).fetchall()
        ]
        runbooks = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE runbook_md IS NOT NULL"
        ).fetchone()["c"]
    return {
        "total_alerts": total,
        "alerts_by_severity": {
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
        },
        "techniques_covered": sorted(techniques),
        "detection_coverage_pct": round(100 * len(techniques) / 5, 1),
        "runbooks_generated": runbooks,
    }
