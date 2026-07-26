CREATE TABLE developers (
    id TEXT PRIMARY KEY,
    developer_type TEXT NOT NULL CHECK (developer_type IN ('individual', 'organization')),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    verification_status TEXT NOT NULL CHECK (verification_status IN ('pending', 'verified', 'rejected')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE developer_members (
    id TEXT PRIMARY KEY,
    developer_id TEXT NOT NULL REFERENCES developers(id),
    account_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    status TEXT NOT NULL CHECK (status IN ('active', 'invited', 'suspended', 'removed')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(developer_id, account_id)
);

CREATE TABLE developer_creation_requests (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    requested_display_name TEXT NOT NULL,
    requested_developer_type TEXT NOT NULL CHECK (requested_developer_type IN ('individual', 'organization')),
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'consumed')),
    reviewed_by_account_id TEXT,
    reviewed_at INTEGER,
    rejection_reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE certificate_requests (
    id TEXT PRIMARY KEY,
    developer_id TEXT NOT NULL REFERENCES developers(id),
    requested_by_account_id TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    subject_public_key TEXT NOT NULL,
    subject_key_id TEXT NOT NULL,
    package_id_scopes_json TEXT NOT NULL,
    allowed_capabilities_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'issued', 'rejected')),
    processed_by_account_id TEXT,
    processed_at INTEGER,
    rejection_reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    certificate_request_id TEXT NOT NULL UNIQUE REFERENCES certificate_requests(id),
    developer_id TEXT NOT NULL REFERENCES developers(id),
    serial_number TEXT NOT NULL UNIQUE,
    issuer_key_id TEXT NOT NULL,
    subject_key_id TEXT NOT NULL,
    certificate_json TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at INTEGER NOT NULL
);

CREATE TABLE revocations (
    id TEXT PRIMARY KEY,
    certificate_id TEXT NOT NULL UNIQUE REFERENCES certificates(id),
    serial_number TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_by_account_id TEXT NOT NULL,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    developer_id TEXT REFERENCES developers(id),
    actor_account_id TEXT,
    event_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_members_account ON developer_members(account_id, status);
CREATE INDEX idx_members_developer ON developer_members(developer_id, status);
CREATE INDEX idx_creation_requests_account ON developer_creation_requests(account_id, status);
CREATE INDEX idx_cert_requests_developer ON certificate_requests(developer_id, status);
CREATE INDEX idx_certificates_developer ON certificates(developer_id, status);

CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs
BEGIN SELECT RAISE(ABORT, 'audit logs are append-only'); END;
CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs
BEGIN SELECT RAISE(ABORT, 'audit logs are append-only'); END;

CREATE TRIGGER prevent_last_owner_removal
BEFORE UPDATE OF role, status ON developer_members
WHEN OLD.role = 'owner' AND OLD.status = 'active'
 AND (NEW.role != 'owner' OR NEW.status != 'active')
 AND NOT EXISTS (
   SELECT 1 FROM developer_members
   WHERE developer_id = OLD.developer_id AND id != OLD.id AND role = 'owner' AND status = 'active'
 )
BEGIN SELECT RAISE(ABORT, 'developer must retain an active owner'); END;

