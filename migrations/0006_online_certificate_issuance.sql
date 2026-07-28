CREATE TABLE IF NOT EXISTS issuers (
    key_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('future', 'active', 'retired', 'revoked')),
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    allowed_key_usages_json TEXT NOT NULL,
    trust_snapshot_version INTEGER NOT NULL,
    root_signed_record TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    retired_at INTEGER,
    revoked_at INTEGER,
    revocation_reason TEXT,
    CHECK (not_after > not_before)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_issuers_single_active ON issuers(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_issuers_snapshot ON issuers(trust_snapshot_version);

CREATE TABLE IF NOT EXISTS trust_snapshots (
    snapshot_version INTEGER PRIMARY KEY,
    generated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    root_key_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    etag TEXT NOT NULL UNIQUE,
    is_current INTEGER NOT NULL DEFAULT 0 CHECK (is_current IN (0, 1)),
    registered_by_account_id TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    admin_token_jti TEXT NOT NULL UNIQUE,
    CHECK (snapshot_version > 0),
    CHECK (expires_at > generated_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trust_snapshots_single_current
ON trust_snapshots(is_current) WHERE is_current = 1;

CREATE TABLE IF NOT EXISTS revocation_snapshots (
    snapshot_version INTEGER PRIMARY KEY,
    generated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    issuer_key_id TEXT NOT NULL REFERENCES issuers(key_id),
    snapshot_json TEXT NOT NULL,
    etag TEXT NOT NULL UNIQUE,
    is_current INTEGER NOT NULL DEFAULT 0 CHECK (is_current IN (0, 1)),
    created_at INTEGER NOT NULL,
    CHECK (snapshot_version > 0),
    CHECK (expires_at > generated_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_revocation_snapshots_single_current
ON revocation_snapshots(is_current) WHERE is_current = 1;

CREATE TRIGGER IF NOT EXISTS issuers_no_public_key_replacement
BEFORE UPDATE OF public_key ON issuers
WHEN OLD.public_key != NEW.public_key
BEGIN SELECT RAISE(ABORT, 'issuer public key is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trust_snapshots_no_update
BEFORE UPDATE OF snapshot_json, etag, snapshot_version ON trust_snapshots
BEGIN SELECT RAISE(ABORT, 'signed trust snapshots are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trust_snapshots_no_delete
BEFORE DELETE ON trust_snapshots
BEGIN SELECT RAISE(ABORT, 'signed trust snapshots are append-only'); END;

CREATE TRIGGER IF NOT EXISTS revocation_snapshots_no_update
BEFORE UPDATE OF snapshot_json, etag, snapshot_version ON revocation_snapshots
BEGIN SELECT RAISE(ABORT, 'signed revocation snapshots are immutable'); END;

CREATE TRIGGER IF NOT EXISTS revocation_snapshots_no_delete
BEFORE DELETE ON revocation_snapshots
BEGIN SELECT RAISE(ABORT, 'signed revocation snapshots are append-only'); END;

ALTER TABLE certificate_requests ADD COLUMN request_hash TEXT;
ALTER TABLE certificate_requests ADD COLUMN idempotency_key TEXT;
ALTER TABLE certificate_requests ADD COLUMN issuance_path TEXT NOT NULL DEFAULT 'legacy';

ALTER TABLE certificates ADD COLUMN issuance_source TEXT NOT NULL DEFAULT 'legacy_root';
ALTER TABLE certificates ADD COLUMN issued_by_account_id TEXT;

CREATE TABLE certificate_serial_sequence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_serial INTEGER NOT NULL CHECK (next_serial > 0)
);

INSERT INTO certificate_serial_sequence(singleton, next_serial)
SELECT 1, COALESCE(MAX(CAST(serial_number AS INTEGER)), 0) + 1 FROM certificates;

CREATE TABLE certificate_issue_idempotency (
    developer_id TEXT NOT NULL REFERENCES developers(id),
    account_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    certificate_id TEXT REFERENCES certificates(id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'complete')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(developer_id, account_id, idempotency_key)
);

CREATE TABLE certificate_issuance_attempts (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    developer_id TEXT NOT NULL REFERENCES developers(id),
    subject_key_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_certificate_attempts_account
ON certificate_issuance_attempts(account_id, created_at);
CREATE INDEX idx_certificate_attempts_developer
ON certificate_issuance_attempts(developer_id, created_at);
CREATE INDEX idx_certificate_attempts_key
ON certificate_issuance_attempts(subject_key_id, created_at);
