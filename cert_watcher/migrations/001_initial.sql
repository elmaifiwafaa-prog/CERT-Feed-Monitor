CREATE TABLE IF NOT EXISTS processed_cves (cve_id TEXT PRIMARY KEY, processed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
    published_at TEXT, source_added_at TEXT, first_detected_at TEXT NOT NULL, last_detected_at TEXT NOT NULL,
    actively_exploited INTEGER NOT NULL DEFAULT 0, cvss_score REAL, remediation TEXT
);
CREATE TABLE IF NOT EXISTS source_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL, source_name TEXT NOT NULL,
    source_url TEXT NOT NULL, source_added_at TEXT, observed_at TEXT NOT NULL,
    UNIQUE(cve_id, source_name, source_url), FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id)
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY, cve_id TEXT, recipient TEXT, channel TEXT, status TEXT,
    sent_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
    severity TEXT NOT NULL, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL, due_at TEXT,
    affected_assets TEXT NOT NULL, owner_contacts TEXT NOT NULL, escalation_contacts TEXT NOT NULL DEFAULT '',
    alert_path TEXT NOT NULL, last_reminder_at TEXT, escalation_sent_at TEXT, resolution_comment TEXT
);
CREATE TABLE IF NOT EXISTS ticket_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL, action TEXT NOT NULL, comment TEXT, FOREIGN KEY(ticket_id) REFERENCES tickets(id)
);
