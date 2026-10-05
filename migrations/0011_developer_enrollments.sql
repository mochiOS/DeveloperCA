CREATE TABLE developer_enrollments (
	id TEXT PRIMARY KEY,
	applicant_account_id TEXT NOT NULL,
	developer_type TEXT NOT NULL
		CHECK (developer_type IN ('individual', 'organization')),
	organization_type TEXT
		CHECK (
			organization_type IS NULL
			OR organization_type IN ('company', 'nonprofit', 'community', 'other')
		),
	display_legal_name TEXT NOT NULL,
	organization_name TEXT,
	country_region TEXT NOT NULL,
	website TEXT,
	account_holder_account_id TEXT,
	agreement_version TEXT NOT NULL,
	state TEXT NOT NULL
		CHECK (
			state IN (
				'draft',
				'submitted',
				'in_review',
				'information_required',
				'approved',
				'rejected'
			)
		),
	submitted_at INTEGER,
	reviewed_at INTEGER,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,

	CHECK (
		(
			developer_type = 'individual'
			AND organization_type IS NULL
			AND organization_name IS NULL
			AND account_holder_account_id IS NULL
		)
		OR
		(
			developer_type = 'organization'
			AND organization_type IS NOT NULL
			AND organization_name IS NOT NULL
			AND account_holder_account_id IS NOT NULL
		)
	)
);

CREATE INDEX idx_developer_enrollments_account
ON developer_enrollments(applicant_account_id, created_at DESC);

CREATE INDEX idx_developer_enrollments_state
ON developer_enrollments(state, submitted_at);

CREATE TABLE developer_enrollment_events (
	id TEXT PRIMARY KEY,
	enrollment_id TEXT NOT NULL
		REFERENCES developer_enrollments(id),
	actor_account_id TEXT,
	event_type TEXT NOT NULL,
	metadata_json TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE INDEX idx_developer_enrollment_events_enrollment
ON developer_enrollment_events(enrollment_id, created_at);

CREATE TRIGGER developer_enrollment_events_no_update
BEFORE UPDATE ON developer_enrollment_events
BEGIN
	SELECT RAISE(ABORT, 'developer enrollment events are append-only');
END;

CREATE TRIGGER developer_enrollment_events_no_delete
BEFORE DELETE ON developer_enrollment_events
BEGIN
	SELECT RAISE(ABORT, 'developer enrollment events are append-only');
END;

CREATE TABLE developer_enrollment_messages (
	id TEXT PRIMARY KEY,
	enrollment_id TEXT NOT NULL
		REFERENCES developer_enrollments(id),
	author_account_id TEXT NOT NULL,
	author_kind TEXT NOT NULL
		CHECK (author_kind IN ('developer', 'reviewer')),
	message TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE INDEX idx_developer_enrollment_messages_enrollment
ON developer_enrollment_messages(enrollment_id, created_at);

CREATE TRIGGER developer_enrollment_messages_no_update
BEFORE UPDATE ON developer_enrollment_messages
BEGIN
	SELECT RAISE(ABORT, 'developer enrollment messages are append-only');
END;

CREATE TRIGGER developer_enrollment_messages_no_delete
BEFORE DELETE ON developer_enrollment_messages
BEGIN
	SELECT RAISE(ABORT, 'developer enrollment messages are append-only');
END;
