CREATE TABLE certificate_suspensions (
    certificate_id TEXT PRIMARY KEY REFERENCES certificates(id),
    suspended_by_account_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    suspended_at INTEGER NOT NULL
);
