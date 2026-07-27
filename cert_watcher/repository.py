from __future__ import annotations

import sqlite3
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone


TICKET_STATUSES = {"OPEN", "IN_PROGRESS", "PATCHED", "RISK_ACCEPTED", "CLOSED"}


def apply_migrations(connection: sqlite3.Connection) -> None:
    """Apply numbered SQL files once, in filename order."""
    connection.execute("CREATE TABLE IF NOT EXISTS schema_version (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
    applied = {row[0] for row in connection.execute("SELECT version FROM schema_version")}
    directory = Path(__file__).with_name("migrations")
    for migration in sorted(directory.glob("*.sql")):
        if migration.name in applied:
            continue
        connection.executescript(migration.read_text(encoding="utf-8"))
        connection.execute("INSERT INTO schema_version(version, applied_at) VALUES (?, ?)", (migration.name, datetime.now(timezone.utc).isoformat()))
        connection.commit()


class Repository:
    def __init__(self, path: str | Path = "data/cert_watcher.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        apply_migrations(self.connection)
        self.connection.execute("CREATE TABLE IF NOT EXISTS processed_cves (cve_id TEXT PRIMARY KEY, processed_at TEXT NOT NULL)")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
            published_at TEXT, source_added_at TEXT, first_detected_at TEXT NOT NULL, last_detected_at TEXT NOT NULL,
            actively_exploited INTEGER NOT NULL DEFAULT 0, cvss_score REAL, remediation TEXT
        )""")
        vulnerability_fields = {row[1] for row in self.connection.execute("PRAGMA table_info(vulnerabilities)")}
        if "source_added_at" not in vulnerability_fields:
            self.connection.execute("ALTER TABLE vulnerabilities ADD COLUMN source_added_at TEXT")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS source_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL, source_name TEXT NOT NULL,
            source_url TEXT NOT NULL, source_added_at TEXT, observed_at TEXT NOT NULL,
            UNIQUE(cve_id, source_name, source_url),
            FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id)
        )""")
        self.connection.execute("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, cve_id TEXT, recipient TEXT, channel TEXT, status TEXT, sent_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
            severity TEXT NOT NULL, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            due_at TEXT, affected_assets TEXT NOT NULL, owner_contacts TEXT NOT NULL,
            escalation_contacts TEXT NOT NULL DEFAULT '',
            alert_path TEXT NOT NULL, last_reminder_at TEXT, escalation_sent_at TEXT,
            resolution_comment TEXT
        )""")
        fields = {row[1] for row in self.connection.execute("PRAGMA table_info(tickets)")}
        if "escalation_contacts" not in fields:
            self.connection.execute("ALTER TABLE tickets ADD COLUMN escalation_contacts TEXT NOT NULL DEFAULT ''")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS ticket_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, occurred_at TEXT NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, comment TEXT,
            FOREIGN KEY(ticket_id) REFERENCES tickets(id)
        )""")
        self.connection.commit()

    @staticmethod
    def _source_name(source_url: str) -> str:
        url = source_url.casefold()
        if "nvd.nist.gov" in url:
            return "NIST NVD"
        if "cisa.gov" in url:
            return "CISA KEV"
        if "cert.ssi.gouv.fr" in url:
            return "CERT-FR"
        if "cveawg.mitre.org" in url:
            return "MITRE CVE"
        return "CTI"

    @staticmethod
    def _source_url(source_url: str) -> str:
        """Keep the NVD observation identity stable despite its dated query string."""
        if "nvd.nist.gov" in source_url.casefold():
            return source_url.split("?", 1)[0]
        return source_url

    def record_vulnerability(self, vulnerability) -> bool:
        """Persist CTI provenance and return True only for a newly seen CVE."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self.connection.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (vulnerability.cve_id,)).fetchone()
        self.connection.execute("""INSERT INTO vulnerabilities
            (cve_id, title, description, published_at, source_added_at, first_detected_at, last_detected_at, actively_exploited, cvss_score, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET last_detected_at=excluded.last_detected_at,
              title=excluded.title, description=excluded.description,
              actively_exploited=MAX(vulnerabilities.actively_exploited, excluded.actively_exploited),
              source_added_at=COALESCE(vulnerabilities.source_added_at, excluded.source_added_at),
              cvss_score=COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
              remediation=COALESCE(excluded.remediation, vulnerabilities.remediation)
        """, (vulnerability.cve_id, vulnerability.title, vulnerability.description,
              vulnerability.published_at.isoformat() if vulnerability.published_at else None,
              vulnerability.source_added_at.isoformat() if vulnerability.source_added_at else None,
              now, now, int(vulnerability.actively_exploited), vulnerability.cvss_score, vulnerability.remediation))
        for source_url in vulnerability.sources:
            canonical_url = self._source_url(source_url)
            self.connection.execute("""INSERT INTO source_observations
                (cve_id, source_name, source_url, source_added_at, observed_at) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cve_id, source_name, source_url) DO UPDATE SET observed_at=excluded.observed_at
            """, (vulnerability.cve_id, self._source_name(canonical_url), canonical_url,
                  vulnerability.source_added_at.isoformat() if vulnerability.source_added_at else None, now))
        self.connection.commit()
        return existing is None

    def cti_sources(self, cve_id: str) -> list[sqlite3.Row]:
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute("SELECT source_name, source_url, source_added_at, observed_at FROM source_observations WHERE cve_id = ? ORDER BY source_name", (cve_id,)).fetchall()

    def tracked_vulnerabilities(self) -> list[sqlite3.Row]:
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute("SELECT cve_id, published_at, source_added_at, first_detected_at, actively_exploited FROM vulnerabilities ORDER BY first_detected_at DESC").fetchall()

    def is_processed(self, cve_id: str) -> bool:
        return self.connection.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,)).fetchone() is not None

    def mark_processed(self, cve_id: str) -> None:
        self.connection.execute("INSERT OR IGNORE INTO processed_cves VALUES (?, CURRENT_TIMESTAMP)", (cve_id,))
        self.connection.commit()

    def has_ticket(self, cve_id: str) -> bool:
        return (
            self.connection.execute("SELECT 1 FROM tickets WHERE cve_id = ?", (cve_id,)).fetchone() is not None
            or self.connection.execute("SELECT 1 FROM vulnerability_tickets WHERE cve_id = ?", (cve_id,)).fetchone() is not None
        )

    def log_notification(self, cve_id: str, recipient: str, channel: str, status: str) -> None:
        self.connection.execute("INSERT INTO notifications (cve_id, recipient, channel, status) VALUES (?, ?, ?, ?)", (cve_id, recipient, channel, status))
        self.connection.commit()

    def upsert_asset_ticket(self, cve_id: str, asset_id: str, severity: str, contacts: list[str], fingerprint: str) -> tuple[sqlite3.Row, bool]:
        """Create a CVE+asset ticket or advance its revision when CVE content changed."""
        self.connection.row_factory = sqlite3.Row
        current = self.connection.execute("SELECT * FROM vulnerability_tickets WHERE cve_id = ? AND asset_id = ?", (cve_id, asset_id)).fetchone()
        now = datetime.now(timezone.utc).isoformat()
        contacts_json = json.dumps(sorted(set(contacts)))
        if current is None:
            ticket_id = f"SEK-{uuid.uuid4().hex[:12].upper()}"
            self.connection.execute("""INSERT INTO vulnerability_tickets
                (ticket_id, cve_id, asset_id, status, severity, detected_at, updated_at, revision, content_fingerprint, responsible_contacts)
                VALUES (?, ?, ?, 'OPEN', ?, ?, ?, 1, ?, ?)""", (ticket_id, cve_id, asset_id, severity, now, now, fingerprint, contacts_json))
            changed = True
        elif current["content_fingerprint"] != fingerprint:
            self.connection.execute("""UPDATE vulnerability_tickets SET severity = ?, updated_at = ?, revision = revision + 1,
                content_fingerprint = ?, responsible_contacts = ? WHERE ticket_id = ?""", (severity, now, fingerprint, contacts_json, current["ticket_id"]))
            ticket_id, changed = current["ticket_id"], True
        else:
            ticket_id, changed = current["ticket_id"], False
        self.connection.commit()
        ticket = self.connection.execute("SELECT * FROM vulnerability_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
        return ticket, changed

    def delivery_exists(self, ticket_id: str, revision: int, recipient: str, mode: str, channel: str = "gmail") -> bool:
        """A dry-run prevents duplicate dry-run logs, but never prevents a later live send."""
        query = "SELECT 1 FROM ticket_deliveries WHERE ticket_id = ? AND revision = ? AND recipient = ? AND channel = ? AND mode = ?"
        return self.connection.execute(query, (ticket_id, revision, recipient, channel, mode)).fetchone() is not None

    def record_delivery(self, ticket_id: str, revision: int, recipient: str, mode: str, status: str, report_path: str, gmail_message_id: str | None = None) -> None:
        self.connection.execute("""INSERT OR IGNORE INTO ticket_deliveries
            (ticket_id, revision, recipient, channel, mode, status, report_path, sent_at, gmail_message_id)
            VALUES (?, ?, ?, 'gmail', ?, ?, ?, ?, ?)""", (ticket_id, revision, recipient, mode, status, report_path, datetime.now(timezone.utc).isoformat(), gmail_message_id))
        self.connection.commit()
        self.connection.execute("UPDATE vulnerability_tickets SET report_path = ? WHERE ticket_id = ?", (report_path, ticket_id))
        self.connection.commit()

    def create_ticket(self, cve_id: str, severity: str, asset_ids: list[str], recipients: list[str], escalation_recipients: list[str], alert_path: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        self.connection.execute("""INSERT OR IGNORE INTO tickets
            (cve_id, status, severity, opened_at, updated_at, affected_assets, owner_contacts, escalation_contacts, alert_path)
            VALUES (?, 'OPEN', ?, ?, ?, ?, ?, ?, ?)""", (cve_id, severity, now, now, ",".join(asset_ids), ",".join(recipients), ",".join(escalation_recipients), alert_path))
        row = self.connection.execute("SELECT id FROM tickets WHERE cve_id = ?", (cve_id,)).fetchone()
        ticket_id = int(row[0])
        self.connection.execute("INSERT OR IGNORE INTO ticket_history (ticket_id, occurred_at, actor, action, comment) SELECT ?, ?, 'system', 'CREATED', 'Ticket créé depuis fiche d’alerte' WHERE NOT EXISTS (SELECT 1 FROM ticket_history WHERE ticket_id = ? AND action = 'CREATED')", (ticket_id, now, ticket_id))
        self.connection.commit()
        return ticket_id

    def update_ticket(self, ticket_id: int, status: str, actor: str = "operator", comment: str | None = None) -> None:
        if status not in TICKET_STATUSES:
            raise ValueError(f"Statut invalide : {status}")
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.connection.execute("UPDATE tickets SET status = ?, updated_at = ?, resolution_comment = COALESCE(?, resolution_comment) WHERE id = ?", (status, now, comment, ticket_id))
        if cursor.rowcount != 1:
            raise ValueError(f"Ticket introuvable : {ticket_id}")
        self.connection.execute("INSERT INTO ticket_history (ticket_id, occurred_at, actor, action, comment) VALUES (?, ?, ?, 'STATUS_CHANGED', ?)", (ticket_id, now, actor, f"{status}: {comment or ''}"))
        self.connection.commit()

    def open_tickets(self) -> list[sqlite3.Row]:
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute("SELECT * FROM tickets WHERE status IN ('OPEN', 'IN_PROGRESS') ORDER BY opened_at").fetchall()

    def all_tickets(self) -> list[sqlite3.Row]:
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute("SELECT * FROM tickets ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, opened_at").fetchall()

    def asset_ticket_details(self, asset_id: str) -> list[sqlite3.Row]:
        """Return all open tickets and vulnerability details that concern one asset."""
        self.connection.row_factory = sqlite3.Row
        rows = self.connection.execute("""
            SELECT tickets.id, tickets.cve_id, tickets.status, tickets.severity, tickets.opened_at,
                   vulnerabilities.title, vulnerabilities.description, vulnerabilities.cvss_score,
                   vulnerabilities.actively_exploited, vulnerabilities.remediation
            FROM tickets
            JOIN vulnerabilities ON vulnerabilities.cve_id = tickets.cve_id
            WHERE tickets.status IN ('OPEN', 'IN_PROGRESS')
              AND instr(',' || tickets.affected_assets || ',', ',' || ? || ',') > 0
            ORDER BY CASE tickets.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                     tickets.opened_at
        """, (asset_id,)).fetchall()
        return rows

    def record_reminder(self, ticket_id: int, escalated: bool = False) -> None:
        now = datetime.now(timezone.utc).isoformat()
        field = "escalation_sent_at" if escalated else "last_reminder_at"
        action = "ESCALATED" if escalated else "REMINDER_SENT"
        self.connection.execute(f"UPDATE tickets SET {field} = ?, updated_at = ? WHERE id = ?", (now, now, ticket_id))
        self.connection.execute("INSERT INTO ticket_history (ticket_id, occurred_at, actor, action, comment) VALUES (?, ?, 'system', ?, NULL)", (ticket_id, now, action))
        self.connection.commit()
