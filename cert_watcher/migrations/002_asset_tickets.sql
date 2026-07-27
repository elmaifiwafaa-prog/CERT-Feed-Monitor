CREATE TABLE IF NOT EXISTS vulnerability_tickets (
    ticket_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    severity TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    content_fingerprint TEXT NOT NULL,
    responsible_contacts TEXT NOT NULL,
    report_path TEXT,
    UNIQUE(cve_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_tickets_asset ON vulnerability_tickets(asset_id, status);
CREATE TABLE IF NOT EXISTS ticket_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    channel TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    report_path TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    gmail_message_id TEXT,
    UNIQUE(ticket_id, revision, recipient, channel),
    FOREIGN KEY(ticket_id) REFERENCES vulnerability_tickets(ticket_id)
);
