CREATE TABLE notifications (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL,
	kind TEXT NOT NULL
		CHECK (kind IN ('info', 'success', 'warning', 'action_required')),
	title TEXT NOT NULL,
	message TEXT NOT NULL,
	action_url TEXT,
	source TEXT NOT NULL,
	source_id TEXT,
	created_at INTEGER NOT NULL,
	read_at INTEGER
);

CREATE INDEX idx_notifications_account_created
ON notifications(account_id, created_at DESC);

CREATE INDEX idx_notifications_account_unread
ON notifications(account_id, read_at, created_at DESC);
