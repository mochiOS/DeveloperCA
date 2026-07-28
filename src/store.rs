use serde::{Deserialize, de::DeserializeOwned};
use uuid::{NoContext, Timestamp, Uuid};
use worker::{D1Database, Result, wasm_bindgen::JsValue};

use crate::certificate::CertificateRequestInput;
use crate::model::{
    CertificateRow, CreationRequest, Developer, IssuerRow, Member, Revocation,
    RevocationSnapshotRow, TrustSnapshotRow,
};

fn value(value: impl AsRef<str>) -> JsValue {
    JsValue::from_str(value.as_ref())
}
fn number(value: i64) -> JsValue {
    JsValue::from_f64(value as f64)
}
fn nullable(value_: Option<&str>) -> JsValue {
    value_.map(value).unwrap_or(JsValue::NULL)
}
pub fn id(now: i64) -> String {
    let timestamp = Timestamp::from_unix(NoContext, now.max(0) as u64, 0);
    Uuid::new_v7(timestamp).to_string()
}

fn audit(
    db: &D1Database,
    developer_id: Option<&str>,
    actor: Option<&str>,
    event: &str,
    now: i64,
) -> Result<worker::D1PreparedStatement> {
    db.prepare("INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at) VALUES (?1, ?2, ?3, ?4, '{}', ?5)")
        .bind(&[value(id(now)), nullable(developer_id), nullable(actor), value(event), number(now)])
}

pub async fn consume_authentication_jti(
    db: &D1Database,
    jti: &str,
    subject: &str,
    operation: &str,
    expires_at: i64,
    now: i64,
) -> Result<bool> {
    db.prepare("DELETE FROM authentication_replay_cache WHERE expires_at <= ?1")
        .bind(&[number(now)])?
        .run()
        .await?;
    db.prepare(
        "DELETE FROM authentication_replay_cache WHERE jti IN (
           SELECT jti FROM authentication_replay_cache ORDER BY expires_at DESC, used_at DESC
           LIMIT -1 OFFSET 9999
         )",
    )
    .run()
    .await?;
    let result = db
        .prepare(
            "INSERT OR IGNORE INTO authentication_replay_cache
             (jti, subject_account_id, operation, expires_at, used_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&[
            value(jti),
            value(subject),
            value(operation),
            number(expires_at),
            number(now),
        ])?
        .run()
        .await?;
    Ok(result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .is_some_and(|changes| changes == 1))
}

pub async fn record_admin_audit(
    db: &D1Database,
    developer_id: Option<&str>,
    actor: &str,
    operation: &str,
    jti: &str,
    now: i64,
) -> Result<()> {
    let metadata = serde_json::to_string(&serde_json::json!({"jti": jti}))?;
    db.prepare(
        "INSERT INTO audit_logs
         (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&[
        value(id(now)),
        nullable(developer_id),
        value(actor),
        value(operation),
        value(metadata),
        number(now),
    ])?
    .run()
    .await?;
    Ok(())
}

async fn all<T: DeserializeOwned>(statement: worker::D1PreparedStatement) -> Result<Vec<T>> {
    statement.all().await?.results()
}

pub async fn developer(db: &D1Database, developer_id: &str) -> Result<Option<Developer>> {
    db.prepare("SELECT id, certificate_developer_id, developer_type, display_name, status, verification_status, created_at, updated_at FROM developers WHERE id = ?1")
        .bind(&[value(developer_id)])?.first(None).await
}

pub async fn list_developers(db: &D1Database, account_id: &str) -> Result<Vec<Developer>> {
    all(db.prepare(
        "SELECT d.id, d.certificate_developer_id, d.developer_type, d.display_name, d.status, d.verification_status, d.created_at, d.updated_at
         FROM developer_members m JOIN developers d ON d.id = m.developer_id
         WHERE m.account_id = ?1 AND m.status = 'active' AND d.status != 'deleted' ORDER BY d.created_at",
    ).bind(&[value(account_id)])?).await
}

pub async fn pending_developer_reviews(db: &D1Database) -> Result<Vec<Developer>> {
    all(db.prepare(
        "SELECT id, certificate_developer_id, developer_type, display_name, status, verification_status, created_at, updated_at
         FROM developers WHERE status='active' AND verification_status='pending' ORDER BY created_at",
    )).await
}

pub async fn member_for_account(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
) -> Result<Option<Member>> {
    db.prepare(
        "SELECT id, developer_id, account_id, role, status, created_at, updated_at FROM developer_members
         WHERE developer_id = ?1 AND account_id = ?2 AND status = 'active'",
    ).bind(&[value(developer_id), value(account_id)])?.first(None).await
}

pub async fn create_developer(
    db: &D1Database,
    account_id: &str,
    developer_type: &str,
    display_name: &str,
    request_id: Option<&str>,
    now: i64,
) -> Result<Option<Developer>> {
    let developer_id = id(now);
    let certificate_developer_id =
        format!("org.mochios.developer.{}", developer_id.replace('-', ""));
    let request = nullable(request_id);
    db.batch(vec![
        db.prepare(
            "INSERT INTO developers (id, certificate_developer_id, developer_type, display_name, status, verification_status, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, 'active', 'pending', ?5, ?5
             WHERE NOT EXISTS (
               SELECT 1 FROM developer_members m JOIN developers d ON d.id=m.developer_id
               WHERE m.account_id=?6 AND m.role='owner' AND m.status='active' AND d.status='active'
             ) OR EXISTS (
               SELECT 1 FROM developer_creation_requests r WHERE r.id=?7 AND r.account_id=?6
               AND r.status='approved' AND r.requested_display_name=?4 AND r.requested_developer_type=?3
             )",
        ).bind(&[value(&developer_id), value(&certificate_developer_id), value(developer_type), value(display_name), number(now), value(account_id), request.clone()])?,
        db.prepare(
            "INSERT INTO developer_members (id, developer_id, account_id, role, status, created_at, updated_at)
             SELECT ?1, ?2, ?3, 'owner', 'active', ?4, ?4 FROM developers WHERE id=?2",
        ).bind(&[value(id(now)), value(&developer_id), value(account_id), number(now)])?,
        db.prepare(
            "UPDATE developer_creation_requests SET status='consumed', updated_at=?1
             WHERE id=?2 AND account_id=?3 AND status='approved' AND EXISTS (SELECT 1 FROM developers WHERE id=?4)",
        ).bind(&[number(now), request, value(account_id), value(&developer_id)])?,
        db.prepare(
            "INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
             SELECT ?1, ?2, ?3, 'developer.created', '{}', ?4 FROM developers WHERE id=?2",
        ).bind(&[value(id(now)), value(&developer_id), value(account_id), number(now)])?,
    ]).await?;
    developer(db, &developer_id).await
}

pub async fn members(db: &D1Database, developer_id: &str) -> Result<Vec<Member>> {
    all(db.prepare(
        "SELECT id, developer_id, account_id, role, status, created_at, updated_at FROM developer_members
         WHERE developer_id=?1 AND status!='removed' ORDER BY created_at",
    ).bind(&[value(developer_id)])?).await
}

pub async fn add_member(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
    role: &str,
    now: i64,
    actor: &str,
) -> Result<Option<Member>> {
    let member_id = id(now);
    db.batch(vec![
        db.prepare(
            "INSERT INTO developer_members (id, developer_id, account_id, role, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5)
             ON CONFLICT(developer_id, account_id) DO UPDATE SET role=excluded.role, status='active', updated_at=excluded.updated_at",
        ).bind(&[value(&member_id), value(developer_id), value(account_id), value(role), number(now)])?,
        audit(db, Some(developer_id), Some(actor), "member.added", now)?,
    ]).await?;
    db.prepare("SELECT id, developer_id, account_id, role, status, created_at, updated_at FROM developer_members WHERE developer_id=?1 AND account_id=?2")
        .bind(&[value(developer_id), value(account_id)])?.first(None).await
}

pub async fn update_member(
    db: &D1Database,
    developer_id: &str,
    member_id: &str,
    role: Option<&str>,
    status: Option<&str>,
    now: i64,
    actor: &str,
) -> Result<Option<Member>> {
    db.batch(vec![
        db.prepare(
            "UPDATE developer_members SET role=COALESCE(?1, role), status=COALESCE(?2, status), updated_at=?3
             WHERE id=?4 AND developer_id=?5",
        ).bind(&[nullable(role), nullable(status), number(now), value(member_id), value(developer_id)])?,
        audit(db, Some(developer_id), Some(actor), "member.updated", now)?,
    ]).await?;
    db.prepare("SELECT id, developer_id, account_id, role, status, created_at, updated_at FROM developer_members WHERE id=?1 AND developer_id=?2")
        .bind(&[value(member_id), value(developer_id)])?.first(None).await
}

pub async fn creation_request(
    db: &D1Database,
    request_id: &str,
) -> Result<Option<CreationRequest>> {
    db.prepare(
        "SELECT id, account_id, requested_display_name, requested_developer_type, reason, status,
         reviewed_by_account_id, reviewed_at, rejection_reason, created_at, updated_at
         FROM developer_creation_requests WHERE id=?1",
    )
    .bind(&[value(request_id)])?
    .first(None)
    .await
}

pub async fn create_creation_request(
    db: &D1Database,
    account_id: &str,
    name: &str,
    developer_type: &str,
    reason: &str,
    now: i64,
) -> Result<CreationRequest> {
    let request_id = id(now);
    db.prepare(
        "INSERT INTO developer_creation_requests
         (id, account_id, requested_display_name, requested_developer_type, reason, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?6)",
    ).bind(&[value(&request_id), value(account_id), value(name), value(developer_type), value(reason), number(now)])?.run().await?;
    creation_request(db, &request_id)
        .await?
        .ok_or_else(|| "creation request disappeared".into())
}

pub async fn list_creation_requests(
    db: &D1Database,
    account_id: &str,
) -> Result<Vec<CreationRequest>> {
    all(db.prepare(
        "SELECT id, account_id, requested_display_name, requested_developer_type, reason, status,
         reviewed_by_account_id, reviewed_at, rejection_reason, created_at, updated_at
         FROM developer_creation_requests WHERE account_id=?1 ORDER BY created_at DESC",
    ).bind(&[value(account_id)])?).await
}

pub async fn pending_creation_reviews(db: &D1Database) -> Result<Vec<CreationRequest>> {
    all(db.prepare(
        "SELECT id, account_id, requested_display_name, requested_developer_type, reason, status,
         reviewed_by_account_id, reviewed_at, rejection_reason, created_at, updated_at
         FROM developer_creation_requests WHERE status='pending' ORDER BY created_at",
    ))
    .await
}

pub async fn review_creation_request(
    db: &D1Database,
    request_id: &str,
    status: &str,
    reviewer: &str,
    reason: Option<&str>,
    now: i64,
) -> Result<Option<CreationRequest>> {
    db.batch(vec![
        db.prepare(
            "UPDATE developer_creation_requests SET status=?1, reviewed_by_account_id=?2, reviewed_at=?3,
             rejection_reason=?4, updated_at=?3 WHERE id=?5 AND status='pending'",
        ).bind(&[value(status), value(reviewer), number(now), nullable(reason), value(request_id)])?,
        audit(db, None, Some(reviewer), &format!("developer_creation_request.{status}"), now)?,
    ]).await?;
    creation_request(db, request_id).await
}

pub async fn update_verification(
    db: &D1Database,
    developer_id: &str,
    status: &str,
    actor: &str,
    now: i64,
) -> Result<Option<Developer>> {
    db.batch(vec![
        db.prepare("UPDATE developers SET verification_status=?1, updated_at=?2 WHERE id=?3 AND status!='deleted'")
            .bind(&[value(status), number(now), value(developer_id)])?,
        audit(db, Some(developer_id), Some(actor), "developer.verification_changed", now)?,
    ]).await?;
    developer(db, developer_id).await
}

pub async fn suspend_developer(
    db: &D1Database,
    developer_id: &str,
    actor: &str,
    now: i64,
) -> Result<Option<Developer>> {
    db.batch(vec![
        db.prepare("UPDATE developers SET status='suspended', updated_at=?1 WHERE id=?2 AND status='active'")
            .bind(&[number(now), value(developer_id)])?,
        audit(db, Some(developer_id), Some(actor), "developer.suspended", now)?,
    ]).await?;
    developer(db, developer_id).await
}

pub struct IssuedCertificateRecord<'a> {
    pub request_id: &'a str,
    pub certificate_id: &'a str,
    pub serial: &'a str,
    pub issuer: &'a str,
    pub certificate_json: &'a str,
    pub not_before: i64,
    pub not_after: i64,
    pub now: i64,
    pub request_hash: &'a str,
    pub idempotency_key: &'a str,
    pub issuance_source: &'a str,
}

#[derive(Debug, Deserialize)]
struct SerialRow {
    serial: i64,
}

#[derive(Debug, Deserialize)]
struct IdempotencyRow {
    request_hash: String,
    certificate_id: Option<String>,
    status: String,
    updated_at: i64,
}

pub enum IssueClaim {
    Claimed,
    Complete(Box<CertificateRow>),
    Pending,
    Conflict,
}

pub async fn reserve_certificate_serial(db: &D1Database) -> Result<u64> {
    let row = db
        .prepare(
            "UPDATE certificate_serial_sequence SET next_serial=next_serial+1
             WHERE singleton=1 RETURNING next_serial-1 AS serial",
        )
        .first::<SerialRow>(None)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("certificate serial sequence unavailable".into())
        })?;
    u64::try_from(row.serial)
        .ok()
        .filter(|serial| *serial > 0)
        .ok_or_else(|| worker::Error::RustError("certificate serial range exhausted".into()))
}

pub async fn claim_certificate_issue(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    now: i64,
) -> Result<IssueClaim> {
    let inserted = db
        .prepare(
            "INSERT OR IGNORE INTO certificate_issue_idempotency
             (developer_id,account_id,idempotency_key,request_hash,status,created_at,updated_at)
             VALUES(?1,?2,?3,?4,'pending',?5,?5)",
        )
        .bind(&[
            value(developer_id),
            value(account_id),
            value(idempotency_key),
            value(request_hash),
            number(now),
        ])?
        .run()
        .await?
        .meta()?
        .and_then(|metadata| metadata.changes)
        .is_some_and(|changes| changes == 1);
    if inserted {
        return Ok(IssueClaim::Claimed);
    }
    let row = db
        .prepare(
            "SELECT request_hash,certificate_id,status,updated_at
             FROM certificate_issue_idempotency
             WHERE developer_id=?1 AND account_id=?2 AND idempotency_key=?3",
        )
        .bind(&[
            value(developer_id),
            value(account_id),
            value(idempotency_key),
        ])?
        .first::<IdempotencyRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("idempotency state unavailable".into()))?;
    if row.request_hash != request_hash {
        return Ok(IssueClaim::Conflict);
    }
    if row.status == "complete"
        && let Some(certificate_id) = row.certificate_id
        && let Some(certificate) = certificate(db, &certificate_id).await?
    {
        return Ok(IssueClaim::Complete(Box::new(certificate)));
    }
    if row.updated_at > now.saturating_sub(300) {
        return Ok(IssueClaim::Pending);
    }
    let reclaimed = db
        .prepare(
            "UPDATE certificate_issue_idempotency SET updated_at=?1
             WHERE developer_id=?2 AND account_id=?3 AND idempotency_key=?4
               AND status='pending' AND updated_at<=?5",
        )
        .bind(&[
            number(now),
            value(developer_id),
            value(account_id),
            value(idempotency_key),
            number(now.saturating_sub(300)),
        ])?
        .run()
        .await?
        .meta()?
        .and_then(|metadata| metadata.changes)
        .is_some_and(|changes| changes == 1);
    Ok(if reclaimed {
        IssueClaim::Claimed
    } else {
        IssueClaim::Pending
    })
}

pub async fn abandon_certificate_issue(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
    idempotency_key: &str,
    request_hash: &str,
) -> Result<()> {
    db.prepare(
        "DELETE FROM certificate_issue_idempotency
         WHERE developer_id=?1 AND account_id=?2 AND idempotency_key=?3
           AND request_hash=?4 AND status='pending'",
    )
    .bind(&[
        value(developer_id),
        value(account_id),
        value(idempotency_key),
        value(request_hash),
    ])?
    .run()
    .await?;
    Ok(())
}

pub async fn record_certificate_issue_attempt(
    db: &D1Database,
    account_id: &str,
    developer_id: &str,
    subject_key_id: &str,
    request_hash: &str,
    now: i64,
) -> Result<bool> {
    db.prepare("DELETE FROM certificate_issuance_attempts WHERE created_at<=?1")
        .bind(&[number(now.saturating_sub(86_400))])?
        .run()
        .await?;
    let result = db
        .prepare(
            "INSERT INTO certificate_issuance_attempts
             (id,account_id,developer_id,subject_key_id,request_hash,created_at)
             SELECT ?1,?2,?3,?4,?5,?6
             WHERE (SELECT COUNT(*) FROM certificate_issuance_attempts
                    WHERE account_id=?2 AND created_at>?7) < 20
               AND (SELECT COUNT(*) FROM certificate_issuance_attempts
                    WHERE developer_id=?3 AND created_at>?7) < 20
               AND (SELECT COUNT(*) FROM certificate_issuance_attempts
                    WHERE subject_key_id=?4 AND created_at>?7) < 10",
        )
        .bind(&[
            value(id(now)),
            value(account_id),
            value(developer_id),
            value(subject_key_id),
            value(request_hash),
            number(now),
            number(now.saturating_sub(3_600)),
        ])?
        .run()
        .await?;
    Ok(result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .is_some_and(|changes| changes == 1))
}

pub async fn issue_certificate(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
    input: &CertificateRequestInput,
    issued: IssuedCertificateRecord<'_>,
) -> Result<Option<CertificateRow>> {
    let subject_key_id = input.subject_key_id().map_err(worker::Error::RustError)?;
    let audit_metadata = serde_json::to_string(&serde_json::json!({
        "certificate_id": issued.certificate_id,
        "serial_number": issued.serial,
        "issuer_key_id": issued.issuer,
        "subject_key_id": subject_key_id,
        "package_id_scopes": input.package_id_scopes,
        "allowed_capabilities": input.allowed_capabilities,
        "issuance_source": issued.issuance_source,
        "idempotency_key": issued.idempotency_key,
    }))?;
    db.batch(vec![
        db.prepare(
            "INSERT INTO certificate_requests
             (id, developer_id, requested_by_account_id, signature_algorithm, subject_public_key,
              subject_key_id, package_id_scopes_json, allowed_capabilities_json, status,
              processed_by_account_id, processed_at, created_at, updated_at,
              request_hash,idempotency_key,issuance_path)
             SELECT ?1, developer.id, ?2, ?3, ?4, ?5, ?6, ?7, 'issued', ?2, ?8, ?8, ?8,
                    ?9,?10,'console_public_key'
             FROM developers developer
             JOIN developer_members member ON member.developer_id=developer.id
             WHERE developer.id=?11 AND developer.status='active'
               AND developer.verification_status='verified' AND member.account_id=?2
               AND member.status='active' AND member.role IN ('owner', 'admin', 'developer')",
        ).bind(&[
            value(issued.request_id), value(account_id), value(&input.signature_algorithm),
            value(&input.subject_public_key), value(&subject_key_id),
            value(serde_json::to_string(&input.package_id_scopes)?),
            value(serde_json::to_string(&input.allowed_capabilities)?), number(issued.now),
            value(issued.request_hash), value(issued.idempotency_key), value(developer_id),
        ])?,
        db.prepare(
            "INSERT INTO certificates
             (id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
              certificate_json, not_before, not_after, status, created_at,
              issuance_source,issued_by_account_id)
             SELECT ?1, request.id, request.developer_id, ?2, ?3, request.subject_key_id,
                    ?4, ?5, ?6, 'active', ?7, ?10, ?9
             FROM certificate_requests request
             WHERE request.id=?8 AND request.status='issued'
               AND request.requested_by_account_id=?9",
        ).bind(&[
            value(issued.certificate_id), value(issued.serial), value(issued.issuer),
            value(issued.certificate_json), number(issued.not_before), number(issued.not_after),
            number(issued.now), value(issued.request_id), value(account_id), value(issued.issuance_source),
        ])?,
        db.prepare(
            "UPDATE certificate_issue_idempotency
             SET certificate_id=?1,status='complete',updated_at=?2
             WHERE developer_id=?3 AND account_id=?4 AND idempotency_key=?5
               AND request_hash=?6 AND status='pending'
               AND EXISTS (SELECT 1 FROM certificates WHERE id=?1)",
        ).bind(&[
            value(issued.certificate_id), number(issued.now), value(developer_id), value(account_id),
            value(issued.idempotency_key), value(issued.request_hash),
        ])?,
        db.prepare(
            "INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
             SELECT ?1, ?2, ?3, 'certificate.issued', ?4, ?5
             FROM certificates WHERE id=?6",
        ).bind(&[
            value(id(issued.now)), value(developer_id), value(account_id), value(audit_metadata),
            number(issued.now), value(issued.certificate_id),
        ])?,
    ]).await?;
    certificate(db, issued.certificate_id).await
}

pub async fn certificate(db: &D1Database, certificate_id: &str) -> Result<Option<CertificateRow>> {
    db.prepare(
        "SELECT id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
         certificate_json, not_before, not_after, status, created_at, issuance_source,
         issued_by_account_id FROM certificates WHERE id=?1",
    ).bind(&[value(certificate_id)])?.first(None).await
}

pub async fn list_certificates(db: &D1Database, developer_id: &str) -> Result<Vec<CertificateRow>> {
    all(db.prepare(
        "SELECT id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
         certificate_json, not_before, not_after, status, created_at, issuance_source,
         issued_by_account_id FROM certificates WHERE developer_id=?1 ORDER BY created_at DESC",
    ).bind(&[value(developer_id)])?).await
}

pub async fn active_certificates(db: &D1Database) -> Result<Vec<CertificateRow>> {
    all(db.prepare(
        "SELECT id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
         certificate_json, not_before, not_after, status, created_at, issuance_source,
         issued_by_account_id FROM certificates
         WHERE status='active' ORDER BY created_at DESC LIMIT 100",
    ))
    .await
}

pub struct RevocationSnapshotRecord<'a> {
    pub version: i64,
    pub generated_at: i64,
    pub expires_at: i64,
    pub issuer_key_id: &'a str,
    pub snapshot_json: &'a str,
    pub etag: &'a str,
}

pub async fn revoke_certificate(
    db: &D1Database,
    certificate_id: &str,
    actor: &str,
    reason: &str,
    reason_code: &str,
    snapshot: RevocationSnapshotRecord<'_>,
    now: i64,
) -> Result<Option<CertificateRow>> {
    let Some(cert) = certificate(db, certificate_id).await? else {
        return Ok(None);
    };
    db.batch(vec![
        db.prepare("UPDATE certificates SET status='revoked' WHERE id=?1 AND status='active'")
            .bind(&[value(certificate_id)])?,
        db.prepare(
            "INSERT INTO revocations
             (id, certificate_id, serial_number, reason, reason_code, revoked_by_account_id, revoked_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
             WHERE EXISTS (SELECT 1 FROM certificates WHERE id=?2 AND status='revoked')
             ON CONFLICT(certificate_id) DO NOTHING",
        ).bind(&[
            value(id(now)), value(certificate_id), value(&cert.serial_number), value(reason),
            value(reason_code), value(actor), number(now)
        ])?,
        db.prepare("UPDATE revocation_snapshots SET is_current=0 WHERE is_current=1"),
        db.prepare(
            "INSERT INTO revocation_snapshots
             (snapshot_version, generated_at, expires_at, issuer_key_id, snapshot_json, etag,
              is_current, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
        ).bind(&[
            number(snapshot.version), number(snapshot.generated_at), number(snapshot.expires_at),
            value(snapshot.issuer_key_id), value(snapshot.snapshot_json), value(snapshot.etag), number(now)
        ])?,
        audit(db, Some(&cert.developer_id), Some(actor), "certificate.revoked", now)?,
    ]).await?;
    certificate(db, certificate_id).await
}

pub async fn revocations(db: &D1Database) -> Result<Vec<Revocation>> {
    all(db.prepare(
        "SELECT id, certificate_id, serial_number, reason, reason_code, revoked_by_account_id,
         revoked_at FROM revocations ORDER BY serial_number",
    ))
    .await
}

pub async fn revocation_for_certificate(
    db: &D1Database,
    certificate_id: &str,
) -> Result<Option<Revocation>> {
    db.prepare(
        "SELECT id, certificate_id, serial_number, reason, reason_code, revoked_by_account_id,
         revoked_at FROM revocations WHERE certificate_id=?1",
    )
    .bind(&[value(certificate_id)])?
    .first(None)
    .await
}

pub async fn save_revocation_snapshot(
    db: &D1Database,
    snapshot: RevocationSnapshotRecord<'_>,
    actor: &str,
    now: i64,
) -> Result<()> {
    db.batch(vec![
        db.prepare("UPDATE revocation_snapshots SET is_current=0 WHERE is_current=1"),
        db.prepare(
            "INSERT INTO revocation_snapshots
             (snapshot_version, generated_at, expires_at, issuer_key_id, snapshot_json, etag,
              is_current, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
        )
        .bind(&[
            number(snapshot.version),
            number(snapshot.generated_at),
            number(snapshot.expires_at),
            value(snapshot.issuer_key_id),
            value(snapshot.snapshot_json),
            value(snapshot.etag),
            number(now),
        ])?,
        audit(db, None, Some(actor), "revocation_snapshot.generated", now)?,
    ])
    .await?;
    Ok(())
}

pub async fn issuers(db: &D1Database) -> Result<Vec<IssuerRow>> {
    all(db.prepare(
        "SELECT key_id, public_key, status, not_before, not_after, allowed_key_usages_json,
         trust_snapshot_version, root_signed_record, created_at, activated_at, retired_at,
         revoked_at, revocation_reason FROM issuers ORDER BY key_id",
    ))
    .await
}

pub async fn issuer(db: &D1Database, key_id: &str) -> Result<Option<IssuerRow>> {
    db.prepare(
        "SELECT key_id, public_key, status, not_before, not_after, allowed_key_usages_json,
         trust_snapshot_version, root_signed_record, created_at, activated_at, retired_at,
         revoked_at, revocation_reason FROM issuers WHERE key_id=?1",
    )
    .bind(&[value(key_id)])?
    .first(None)
    .await
}

pub async fn current_trust_snapshot(db: &D1Database) -> Result<Option<TrustSnapshotRow>> {
    db.prepare(
        "SELECT snapshot_version, generated_at, expires_at, root_key_id, snapshot_json, etag,
         is_current, registered_by_account_id, registered_at, admin_token_jti
         FROM trust_snapshots WHERE is_current=1 LIMIT 1",
    )
    .first(None)
    .await
}

pub async fn trust_snapshot(
    db: &D1Database,
    snapshot_version: i64,
) -> Result<Option<TrustSnapshotRow>> {
    db.prepare(
        "SELECT snapshot_version, generated_at, expires_at, root_key_id, snapshot_json, etag,
         is_current, registered_by_account_id, registered_at, admin_token_jti
         FROM trust_snapshots WHERE snapshot_version=?1",
    )
    .bind(&[number(snapshot_version)])?
    .first(None)
    .await
}

pub async fn register_trust_snapshot(
    db: &D1Database,
    snapshot: &mochios_developer_ca_trust::TrustSnapshot,
    snapshot_json: &str,
    etag: &str,
    actor: &str,
    jti: &str,
    now: i64,
) -> Result<()> {
    let mut statements = vec![
        db.prepare("UPDATE trust_snapshots SET is_current=0 WHERE is_current=1"),
        db.prepare(
            "INSERT INTO trust_snapshots
             (snapshot_version, generated_at, expires_at, root_key_id, snapshot_json, etag,
              is_current, registered_by_account_id, registered_at, admin_token_jti)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9)",
        )
        .bind(&[
            number(snapshot.content.snapshot_version as i64),
            number(snapshot.content.generated_at as i64),
            number(snapshot.content.expires_at as i64),
            value(&snapshot.content.root_key_id),
            value(snapshot_json),
            value(etag),
            value(actor),
            number(now),
            value(jti),
        ])?,
    ];
    for issuer in &snapshot.content.issuers {
        let status = issuer.status.as_str();
        statements.push(
            db.prepare(
                "INSERT INTO issuers
                 (key_id, public_key, status, not_before, not_after, allowed_key_usages_json,
                  trust_snapshot_version, root_signed_record, created_at, activated_at, retired_at,
                  revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                  CASE WHEN ?3='active' THEN ?9 ELSE NULL END,
                  CASE WHEN ?3='retired' THEN ?9 ELSE NULL END,
                  CASE WHEN ?3='revoked' THEN ?9 ELSE NULL END)
                 ON CONFLICT(key_id) DO UPDATE SET
                  status=excluded.status, not_before=excluded.not_before, not_after=excluded.not_after,
                  allowed_key_usages_json=excluded.allowed_key_usages_json,
                  trust_snapshot_version=excluded.trust_snapshot_version,
                  root_signed_record=excluded.root_signed_record,
                  activated_at=COALESCE(issuers.activated_at, excluded.activated_at),
                  retired_at=COALESCE(issuers.retired_at, excluded.retired_at),
                  revoked_at=COALESCE(issuers.revoked_at, excluded.revoked_at)
                 WHERE issuers.public_key=excluded.public_key
                   AND issuers.trust_snapshot_version < excluded.trust_snapshot_version",
            )
            .bind(&[
                value(&issuer.issuer_key_id),
                value(&issuer.public_key),
                value(status),
                number(issuer.not_before as i64),
                number(issuer.not_after as i64),
                value(serde_json::to_string(&issuer.allowed_key_usages)?),
                number(snapshot.content.snapshot_version as i64),
                value(snapshot_json),
                number(now),
            ])?,
        );
    }
    statements.push(audit(
        db,
        None,
        Some(actor),
        "trust_snapshot.registered",
        now,
    )?);
    db.batch(statements).await?;
    Ok(())
}

pub async fn set_issuer_status(
    db: &D1Database,
    key_id: &str,
    status: &str,
    reason: Option<&str>,
    actor: &str,
    now: i64,
) -> Result<Option<IssuerRow>> {
    let timestamp_column = match status {
        "active" => "activated_at",
        "retired" => "retired_at",
        "revoked" => "revoked_at",
        _ => return Ok(None),
    };
    let query = format!(
        "UPDATE issuers SET status=?1, {timestamp_column}=?2,
         revocation_reason=CASE WHEN ?1='revoked' THEN ?3 ELSE revocation_reason END WHERE key_id=?4"
    );
    db.batch(vec![
        db.prepare(&query)
            .bind(&[value(status), number(now), nullable(reason), value(key_id)])?,
        audit(db, None, Some(actor), &format!("issuer.{status}"), now)?,
    ])
    .await?;
    issuer(db, key_id).await
}

pub async fn current_revocation_snapshot(db: &D1Database) -> Result<Option<RevocationSnapshotRow>> {
    db.prepare(
        "SELECT snapshot_version, generated_at, expires_at, issuer_key_id, snapshot_json, etag,
         is_current, created_at FROM revocation_snapshots WHERE is_current=1 LIMIT 1",
    )
    .first(None)
    .await
}

pub async fn revocation_snapshot(
    db: &D1Database,
    snapshot_version: i64,
) -> Result<Option<RevocationSnapshotRow>> {
    db.prepare(
        "SELECT snapshot_version, generated_at, expires_at, issuer_key_id, snapshot_json, etag,
         is_current, created_at FROM revocation_snapshots WHERE snapshot_version=?1",
    )
    .bind(&[number(snapshot_version)])?
    .first(None)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_uuid_v7_without_system_clock_access() {
        let parsed = Uuid::parse_str(&id(1_700_000_000)).unwrap();
        assert_eq!(parsed.get_version_num(), 7);
    }
}
