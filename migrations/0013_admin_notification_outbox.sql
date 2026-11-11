CREATE TABLE admin_notification_outbox (
    id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL
);
CREATE INDEX idx_admin_notification_outbox_due ON admin_notification_outbox(next_attempt_at);
