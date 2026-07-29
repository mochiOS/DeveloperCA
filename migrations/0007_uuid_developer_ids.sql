PRAGMA defer_foreign_keys = ON;

UPDATE developer_members SET developer_id = replace(developer_id, '-', '');
UPDATE certificate_requests SET developer_id = replace(developer_id, '-', '');
UPDATE certificates SET developer_id = replace(developer_id, '-', '');
UPDATE audit_logs SET developer_id = replace(developer_id, '-', '') WHERE developer_id IS NOT NULL;
UPDATE certificate_issue_idempotency SET developer_id = replace(developer_id, '-', '');
UPDATE certificate_issuance_attempts SET developer_id = replace(developer_id, '-', '');
UPDATE developers
SET id = replace(id, '-', ''),
    certificate_developer_id = replace(id, '-', '');
