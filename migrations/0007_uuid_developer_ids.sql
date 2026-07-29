PRAGMA defer_foreign_keys = ON;

UPDATE developer_members SET developer_id = replace(developer_id, '-', '');
UPDATE certificate_requests SET developer_id = replace(developer_id, '-', '');
UPDATE certificates SET developer_id = replace(developer_id, '-', '');
UPDATE certificate_issue_idempotency SET developer_id = replace(developer_id, '-', '');
UPDATE certificate_issuance_attempts SET developer_id = replace(developer_id, '-', '');
UPDATE developers
SET id = replace(id, '-', ''),
    certificate_developer_id = replace(id, '-', '');

-- audit_logs is intentionally append-only, so its UPDATE/DELETE guards must not
-- be weakened for an in-place rewrite. Rebuild the table atomically instead.
CREATE TABLE audit_logs_uuid (
    id TEXT PRIMARY KEY,
    developer_id TEXT REFERENCES developers(id),
    actor_account_id TEXT,
    event_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

INSERT INTO audit_logs_uuid
    (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
SELECT id,
       CASE WHEN developer_id IS NULL THEN NULL ELSE replace(developer_id, '-', '') END,
       actor_account_id,
       event_type,
       metadata_json,
       created_at
FROM audit_logs;

DROP TABLE audit_logs;
ALTER TABLE audit_logs_uuid RENAME TO audit_logs;

CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs
BEGIN SELECT RAISE(ABORT, 'audit logs are append-only'); END;
CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs
BEGIN SELECT RAISE(ABORT, 'audit logs are append-only'); END;
