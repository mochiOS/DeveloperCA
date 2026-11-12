CREATE TABLE developer_enrollment_account_guard (
	account_id TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO developer_enrollment_account_guard (account_id, created_at)
SELECT applicant_account_id, MIN(created_at)
FROM developer_enrollments
GROUP BY applicant_account_id;
