CREATE TABLE issuers (
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

CREATE UNIQUE INDEX idx_issuers_single_active
    ON issuers(status) WHERE status = 'active';
CREATE INDEX idx_issuers_snapshot ON issuers(trust_snapshot_version);

CREATE TABLE trust_snapshots (
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

CREATE UNIQUE INDEX idx_trust_snapshots_single_current
    ON trust_snapshots(is_current) WHERE is_current = 1;

CREATE TABLE revocation_snapshots (
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

CREATE UNIQUE INDEX idx_revocation_snapshots_single_current
    ON revocation_snapshots(is_current) WHERE is_current = 1;

ALTER TABLE revocations ADD COLUMN reason_code TEXT NOT NULL DEFAULT 'unspecified'
    CHECK (reason_code IN (
        'key_compromise',
        'developer_suspended',
        'certificate_replaced',
        'scope_violation',
        'administrative',
        'unspecified'
    ));

CREATE TABLE developer_package_scopes (
    id TEXT PRIMARY KEY,
    developer_id TEXT NOT NULL REFERENCES developers(id),
    scope TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    granted_by_account_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    UNIQUE(developer_id, scope)
);

CREATE INDEX idx_developer_package_scopes_active
    ON developer_package_scopes(developer_id, status);

CREATE TABLE developer_capability_grants (
    id TEXT PRIMARY KEY,
    developer_id TEXT NOT NULL REFERENCES developers(id),
    capability TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    granted_by_account_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    UNIQUE(developer_id, capability)
);

CREATE INDEX idx_developer_capabilities_active
    ON developer_capability_grants(developer_id, status);

CREATE TABLE global_issuable_capabilities (
    capability TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE authentication_replay_cache (
    jti TEXT PRIMARY KEY,
    subject_account_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER NOT NULL
);

CREATE INDEX idx_authentication_replay_expiry
    ON authentication_replay_cache(expires_at);

CREATE TRIGGER issuers_no_public_key_replacement
BEFORE UPDATE OF public_key ON issuers
WHEN OLD.public_key != NEW.public_key
BEGIN SELECT RAISE(ABORT, 'issuer public key is immutable'); END;

CREATE TRIGGER trust_snapshots_no_update
BEFORE UPDATE OF snapshot_json, etag, snapshot_version ON trust_snapshots
BEGIN SELECT RAISE(ABORT, 'signed trust snapshots are immutable'); END;

CREATE TRIGGER trust_snapshots_no_delete
BEFORE DELETE ON trust_snapshots
BEGIN SELECT RAISE(ABORT, 'signed trust snapshots are append-only'); END;

CREATE TRIGGER revocation_snapshots_no_update
BEFORE UPDATE OF snapshot_json, etag, snapshot_version ON revocation_snapshots
BEGIN SELECT RAISE(ABORT, 'signed revocation snapshots are immutable'); END;

CREATE TRIGGER revocation_snapshots_no_delete
BEFORE DELETE ON revocation_snapshots
BEGIN SELECT RAISE(ABORT, 'signed revocation snapshots are append-only'); END;
