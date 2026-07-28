use rusqlite::{Connection, params};

const INITIAL: &str = include_str!("../migrations/0001_developer_ca.sql");
const TRUST: &str = include_str!("../migrations/0002_trust_issuers_policy.sql");
const AUTOMATIC_ISSUANCE: &str =
    include_str!("../migrations/0003_automatic_certificate_issuance.sql");
const ROOT_DIRECT: &str = include_str!("../migrations/0004_root_direct_trust.sql");
const CERTIFICATE_DEVELOPER_ID: &str =
    include_str!("../migrations/0005_certificate_developer_id.sql");
const ONLINE_ISSUANCE: &str = include_str!("../migrations/0006_online_certificate_issuance.sql");

fn existing_database() -> Connection {
    let connection = Connection::open_in_memory().expect("open fixture database");
    connection
        .execute_batch("PRAGMA foreign_keys=ON;")
        .expect("enable foreign keys");
    connection
        .execute_batch(INITIAL)
        .expect("apply initial schema");
    connection
        .execute(
            "INSERT INTO developers VALUES (?1, 'individual', 'Existing', 'active', 'verified', 1, 1)",
            ["developer-1"],
        )
        .expect("insert developer");
    connection
        .execute(
            "INSERT INTO certificate_requests
             (id, developer_id, requested_by_account_id, signature_algorithm,
              subject_public_key, subject_key_id, package_id_scopes_json,
              allowed_capabilities_json, status, created_at, updated_at)
             VALUES ('request-1', 'developer-1', 'account-1', 'ed25519', 'public', 'subject',
                     '[\"org.mochios.example\"]', '[\"window.create\"]', 'issued', 1, 1)",
            [],
        )
        .expect("insert request");
    connection
        .execute(
            "INSERT INTO certificate_requests
             (id, developer_id, requested_by_account_id, signature_algorithm,
              subject_public_key, subject_key_id, package_id_scopes_json,
              allowed_capabilities_json, status, created_at, updated_at)
             VALUES ('request-pending', 'developer-1', 'account-1', 'ed25519', 'public',
                     'subject-pending', '[\"org.mochios.pending\"]', '[]', 'pending', 2, 2)",
            [],
        )
        .expect("insert pending request");
    connection
        .execute(
            "INSERT INTO certificates VALUES
             ('certificate-1', 'request-1', 'developer-1', '42', 'issuer-1', 'subject',
              'wire', 1, 100, 'revoked', 1)",
            [],
        )
        .expect("insert certificate");
    connection
        .execute(
            "INSERT INTO revocations VALUES
             ('revocation-1', 'certificate-1', '42', 'existing reason', 'account-1', 2)",
            [],
        )
        .expect("insert revocation");
    connection
        .execute(
            "INSERT INTO audit_logs VALUES
             ('audit-1', 'developer-1', 'account-1', 'fixture', '{}', 2)",
            [],
        )
        .expect("insert audit");
    connection
}

#[test]
fn automatic_issuance_migration_closes_legacy_reviews_and_removes_policy_tables() {
    let connection = existing_database();
    connection
        .execute_batch(TRUST)
        .expect("apply trust migration");
    connection
        .execute_batch(AUTOMATIC_ISSUANCE)
        .expect("apply automatic issuance migration");

    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM certificate_requests WHERE id='request-pending'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("pending request status"),
        "rejected"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM certificates", [], |row| row
                .get::<_, i64>(0))
            .expect("certificate count"),
        1
    );
    for table in [
        "developer_package_scopes",
        "developer_capability_grants",
        "global_issuable_capabilities",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get::<_, i64>(0),
                )
                .expect("table lookup"),
            0,
            "obsolete table remains: {table}"
        );
    }
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .expect("integrity check"),
        "ok"
    );
}

#[test]
fn trust_migration_preserves_existing_certificate_revocation_and_audit() {
    let connection = existing_database();
    connection
        .execute_batch(TRUST)
        .expect("apply trust migration");

    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM certificates", [], |row| row
                .get::<_, i64>(0))
            .expect("certificate count"),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT reason_code FROM revocations WHERE certificate_id='certificate-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("reason code"),
        "unspecified"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM audit_logs", [], |row| row
                .get::<_, i64>(0))
            .expect("audit count"),
        1
    );
    for table in [
        "issuers",
        "trust_snapshots",
        "revocation_snapshots",
        "developer_package_scopes",
        "developer_capability_grants",
        "global_issuable_capabilities",
        "authentication_replay_cache",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get::<_, i64>(0),
                )
                .expect("table lookup"),
            1,
            "missing table {table}"
        );
    }
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .expect("integrity check"),
        "ok"
    );
}

#[test]
fn failed_migration_transaction_can_be_rolled_back_and_retried() {
    let connection = existing_database();
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .expect("begin migration");
    connection
        .execute_batch(TRUST)
        .expect("apply migration in transaction");
    assert!(
        connection
            .execute("INSERT INTO table_that_does_not_exist VALUES (1)", [])
            .is_err()
    );
    connection
        .execute_batch("ROLLBACK")
        .expect("rollback failed migration");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='issuers'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("table lookup"),
        0
    );
    connection.execute_batch(TRUST).expect("retry migration");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM certificates", [], |row| row
                .get::<_, i64>(0))
            .expect("certificate count"),
        1
    );
}

#[test]
fn online_issuance_migration_preserves_trust_and_existing_records() {
    let connection = existing_database();
    connection
        .execute_batch(TRUST)
        .expect("apply trust migration");
    connection
        .execute_batch(AUTOMATIC_ISSUANCE)
        .expect("apply automatic issuance migration");
    connection
        .execute_batch(ROOT_DIRECT)
        .expect("apply Root-direct migration");
    connection
        .execute_batch(CERTIFICATE_DEVELOPER_ID)
        .expect("add certificate Developer ID");
    connection
        .execute_batch(ONLINE_ISSUANCE)
        .expect("apply online issuance migration");

    for table in ["issuers", "trust_snapshots", "revocation_snapshots"] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get::<_, i64>(0),
                )
                .expect("table lookup"),
            1,
            "trust table is missing: {table}"
        );
    }
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM certificates", [], |row| row
                .get::<_, i64>(0))
            .expect("certificate count"),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM revocations", [], |row| row
                .get::<_, i64>(0))
            .expect("revocation count"),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT certificate_developer_id FROM developers WHERE id='developer-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("certificate Developer ID"),
        "org.mochios.developer.developer1"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT issuance_source FROM certificates WHERE id='certificate-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("legacy certificate issuance source"),
        "legacy_root"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT next_serial FROM certificate_serial_sequence WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("next certificate serial"),
        43
    );
    for table in [
        "certificate_issue_idempotency",
        "certificate_issuance_attempts",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get::<_, i64>(0),
                )
                .expect("table lookup"),
            1,
            "issuance table is missing: {table}"
        );
    }
}

#[test]
fn online_issuance_schema_prevents_serial_and_idempotency_reuse() {
    let connection = existing_database();
    connection
        .execute_batch(TRUST)
        .expect("apply trust migration");
    connection
        .execute_batch(AUTOMATIC_ISSUANCE)
        .expect("apply automatic issuance migration");
    connection
        .execute_batch(ROOT_DIRECT)
        .expect("apply Root-direct migration");
    connection
        .execute_batch(CERTIFICATE_DEVELOPER_ID)
        .expect("add certificate Developer ID");
    connection
        .execute_batch(ONLINE_ISSUANCE)
        .expect("apply online issuance migration");

    connection
        .execute(
            "INSERT INTO certificate_issue_idempotency
             (developer_id,account_id,idempotency_key,request_hash,status,created_at,updated_at)
             VALUES ('developer-1','account-1','idempotency-key-1','hash-1','pending',10,10)",
            [],
        )
        .expect("insert idempotency claim");
    assert!(
        connection
            .execute(
                "INSERT INTO certificate_issue_idempotency
                 (developer_id,account_id,idempotency_key,request_hash,status,created_at,updated_at)
                 VALUES ('developer-1','account-1','idempotency-key-1','hash-1','pending',11,11)",
                [],
            )
            .is_err(),
        "the same idempotency key was accepted twice"
    );

    let serial: i64 = connection
        .query_row(
            "UPDATE certificate_serial_sequence
             SET next_serial=next_serial+1 WHERE singleton=1
             RETURNING next_serial-1",
            [],
            |row| row.get(0),
        )
        .expect("reserve serial");
    assert_eq!(serial, 43);
    assert_eq!(
        connection
            .query_row(
                "SELECT next_serial FROM certificate_serial_sequence WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("next serial"),
        44
    );
    assert!(
        connection
            .execute(
                "INSERT INTO certificates
                 (id,certificate_request_id,developer_id,serial_number,issuer_key_id,
                  subject_key_id,certificate_json,not_before,not_after,status,created_at,
                  issuance_source,issued_by_account_id)
                 SELECT 'duplicate-serial',id,developer_id,'42','issuer-2',subject_key_id,
                        'wire-2',2,101,'active',2,'online_intermediate','account-1'
                 FROM certificate_requests WHERE id='request-1'",
                [],
            )
            .is_err(),
        "an existing serial was reused"
    );
}
