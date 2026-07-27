-- A dry-run is an audit event, not a real Gmail delivery. Preserve both events.
CREATE TABLE ticket_deliveries_next (
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
    UNIQUE(ticket_id, revision, recipient, channel, mode),
    FOREIGN KEY(ticket_id) REFERENCES vulnerability_tickets(ticket_id)
);
INSERT INTO ticket_deliveries_next
    (id, ticket_id, revision, recipient, channel, mode, status, report_path, sent_at, gmail_message_id)
SELECT id, ticket_id, revision, recipient, channel, mode, status, report_path, sent_at, gmail_message_id
FROM ticket_deliveries;
DROP TABLE ticket_deliveries;
ALTER TABLE ticket_deliveries_next RENAME TO ticket_deliveries;
