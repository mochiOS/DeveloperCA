use serde::de::DeserializeOwned;
use uuid::{NoContext, Timestamp, Uuid};
use worker::{D1Database, Result, wasm_bindgen::JsValue};

use crate::certificate::CertificateRequestInput;
use crate::model::{
    CapabilityGrant, CertificateRequestRow, CertificateReviewRequest, CertificateRow,
    CreationRequest, Developer, GlobalCapability, IssuerRow, Member, PackageScopeGrant, Revocation,
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
    db.prepare("SELECT id, developer_type, display_name, status, verification_status, created_at, updated_at FROM developers WHERE id = ?1")
        .bind(&[value(developer_id)])?.first(None).await
}

pub async fn list_developers(db: &D1Database, account_id: &str) -> Result<Vec<Developer>> {
    all(db.prepare(
        "SELECT d.id, d.developer_type, d.display_name, d.status, d.verification_status, d.created_at, d.updated_at
         FROM developer_members m JOIN developers d ON d.id = m.developer_id
         WHERE m.account_id = ?1 AND m.status = 'active' AND d.status != 'deleted' ORDER BY d.created_at",
    ).bind(&[value(account_id)])?).await
}

pub async fn pending_developer_reviews(db: &D1Database) -> Result<Vec<Developer>> {
    all(db.prepare(
        "SELECT id, developer_type, display_name, status, verification_status, created_at, updated_at
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
    let request = nullable(request_id);
    db.batch(vec![
        db.prepare(
            "INSERT INTO developers (id, developer_type, display_name, status, verification_status, created_at, updated_at)
             SELECT ?1, ?2, ?3, 'active', 'pending', ?4, ?4
             WHERE NOT EXISTS (
               SELECT 1 FROM developer_members m JOIN developers d ON d.id=m.developer_id
               WHERE m.account_id=?5 AND m.role='owner' AND m.status='active' AND d.status='active'
             ) OR EXISTS (
               SELECT 1 FROM developer_creation_requests r WHERE r.id=?6 AND r.account_id=?5
               AND r.status='approved' AND r.requested_display_name=?3 AND r.requested_developer_type=?2
             )",
        ).bind(&[value(&developer_id), value(developer_type), value(display_name), number(now), value(account_id), request.clone()])?,
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

pub async fn create_certificate_request(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
    input: &CertificateRequestInput,
    now: i64,
) -> Result<CertificateRequestRow> {
    let request_id = id(now);
    let subject_key_id = input.subject_key_id().map_err(worker::Error::RustError)?;
    db.batch(vec![
        db.prepare(
            "INSERT INTO certificate_requests
             (id, developer_id, requested_by_account_id, signature_algorithm, subject_public_key, subject_key_id,
              package_id_scopes_json, allowed_capabilities_json, status, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?9
             FROM developers WHERE id=?2 AND status='active' AND verification_status='verified'",
        ).bind(&[
            value(&request_id), value(developer_id), value(account_id), value(&input.signature_algorithm),
            value(&input.subject_public_key), value(&subject_key_id),
            value(serde_json::to_string(&input.package_id_scopes)?), value(serde_json::to_string(&input.allowed_capabilities)?), number(now),
        ])?,
        db.prepare(
            "INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
             SELECT ?1, ?2, ?3, 'certificate_request.created', '{}', ?4
             FROM certificate_requests WHERE id=?5",
        ).bind(&[value(id(now)), value(developer_id), value(account_id), number(now), value(&request_id)])?,
    ]).await?;
    certificate_request(db, &request_id)
        .await?
        .ok_or_else(|| "developer is not eligible for certificate issuance".into())
}

pub async fn certificate_request(
    db: &D1Database,
    request_id: &str,
) -> Result<Option<CertificateRequestRow>> {
    db.prepare(
        "SELECT id, developer_id, requested_by_account_id, signature_algorithm, subject_public_key, subject_key_id,
         package_id_scopes_json, allowed_capabilities_json, status, created_at, updated_at
         FROM certificate_requests WHERE id=?1",
    ).bind(&[value(request_id)])?.first(None).await
}

pub async fn pending_certificate_reviews(db: &D1Database) -> Result<Vec<CertificateReviewRequest>> {
    all(db.prepare(
        "SELECT r.id, r.developer_id, d.display_name AS developer_display_name,
         r.requested_by_account_id, r.signature_algorithm, r.subject_key_id,
         r.package_id_scopes_json, r.allowed_capabilities_json, r.status, r.created_at, r.updated_at
         FROM certificate_requests r JOIN developers d ON d.id=r.developer_id
         WHERE r.status='pending' ORDER BY r.created_at",
    ))
    .await
}

pub struct IssuedCertificateRecord<'a> {
    pub certificate_id: &'a str,
    pub serial: &'a str,
    pub issuer: &'a str,
    pub certificate_json: &'a str,
    pub not_before: i64,
    pub not_after: i64,
    pub actor: &'a str,
    pub now: i64,
}

pub async fn issue_certificate(
    db: &D1Database,
    request: &CertificateRequestRow,
    issued: IssuedCertificateRecord<'_>,
) -> Result<Option<CertificateRow>> {
    db.batch(vec![
        db.prepare(
            "INSERT INTO certificates
             (id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
              certificate_json, not_before, not_after, status, created_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', ?10
             WHERE EXISTS (SELECT 1 FROM certificate_requests WHERE id=?2 AND status='pending')
             AND EXISTS (SELECT 1 FROM developers WHERE id=?3 AND status='active' AND verification_status='verified')
             AND EXISTS (
               SELECT 1 FROM certificate_requests request
               JOIN developer_members member
                 ON member.developer_id=request.developer_id
                AND member.account_id=request.requested_by_account_id
               WHERE request.id=?2 AND member.status='active'
                 AND member.role IN ('owner', 'admin', 'developer')
             )
             AND NOT EXISTS (
               SELECT 1 FROM certificate_requests request, json_each(request.package_id_scopes_json) requested
               WHERE request.id=?2 AND NOT EXISTS (
                 SELECT 1 FROM developer_package_scopes grant_scope
                 WHERE grant_scope.developer_id=request.developer_id
                   AND grant_scope.scope=requested.value AND grant_scope.status='active'
               )
             )
             AND NOT EXISTS (
               SELECT 1 FROM certificate_requests request, json_each(request.allowed_capabilities_json) requested
               WHERE request.id=?2 AND (
                 NOT EXISTS (
                   SELECT 1 FROM developer_capability_grants grant_capability
                   WHERE grant_capability.developer_id=request.developer_id
                     AND grant_capability.capability=requested.value
                     AND grant_capability.status='active'
                 ) OR NOT EXISTS (
                   SELECT 1 FROM global_issuable_capabilities global_capability
                   WHERE global_capability.capability=requested.value
                     AND global_capability.status='active'
                 )
               )
             )",
        ).bind(&[
            value(issued.certificate_id), value(&request.id), value(&request.developer_id), value(issued.serial), value(issued.issuer),
            value(&request.subject_key_id), value(issued.certificate_json), number(issued.not_before), number(issued.not_after), number(issued.now),
        ])?,
        db.prepare(
            "UPDATE certificate_requests SET status='issued', processed_by_account_id=?1, processed_at=?2, updated_at=?2
             WHERE id=?3 AND status='pending' AND EXISTS (SELECT 1 FROM certificates WHERE id=?4)",
        ).bind(&[value(issued.actor), number(issued.now), value(&request.id), value(issued.certificate_id)])?,
        audit(db, Some(&request.developer_id), Some(issued.actor), "certificate.issued", issued.now)?,
    ]).await?;
    certificate(db, issued.certificate_id).await
}

pub async fn reject_certificate_request(
    db: &D1Database,
    request_id: &str,
    actor: &str,
    reason: Option<&str>,
    now: i64,
) -> Result<Option<CertificateRequestRow>> {
    db.batch(vec![
        db.prepare(
            "UPDATE certificate_requests SET status='rejected', processed_by_account_id=?1, processed_at=?2,
             rejection_reason=?3, updated_at=?2 WHERE id=?4 AND status='pending'",
        ).bind(&[value(actor), number(now), nullable(reason), value(request_id)])?,
        audit(db, None, Some(actor), "certificate_request.rejected", now)?,
    ]).await?;
    certificate_request(db, request_id).await
}

pub async fn certificate(db: &D1Database, certificate_id: &str) -> Result<Option<CertificateRow>> {
    db.prepare(
        "SELECT id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
         certificate_json, not_before, not_after, status, created_at FROM certificates WHERE id=?1",
    ).bind(&[value(certificate_id)])?.first(None).await
}

pub async fn list_certificates(db: &D1Database, developer_id: &str) -> Result<Vec<CertificateRow>> {
    all(db.prepare(
        "SELECT id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
         certificate_json, not_before, not_after, status, created_at FROM certificates WHERE developer_id=?1 ORDER BY created_at DESC",
    ).bind(&[value(developer_id)])?).await
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

pub async fn package_scope_grants(
    db: &D1Database,
    developer_id: &str,
) -> Result<Vec<PackageScopeGrant>> {
    all(db
        .prepare(
            "SELECT id, developer_id, scope, status, granted_by_account_id, created_at, revoked_at
             FROM developer_package_scopes WHERE developer_id=?1 ORDER BY scope",
        )
        .bind(&[value(developer_id)])?)
    .await
}

pub async fn capability_grants(
    db: &D1Database,
    developer_id: &str,
) -> Result<Vec<CapabilityGrant>> {
    all(db
        .prepare(
            "SELECT id, developer_id, capability, status, granted_by_account_id, created_at,
             revoked_at FROM developer_capability_grants WHERE developer_id=?1 ORDER BY capability",
        )
        .bind(&[value(developer_id)])?)
    .await
}

pub async fn global_capabilities(db: &D1Database) -> Result<Vec<GlobalCapability>> {
    all(db.prepare(
        "SELECT capability, status, created_at, updated_at
         FROM global_issuable_capabilities ORDER BY capability",
    ))
    .await
}

pub async fn grant_package_scope(
    db: &D1Database,
    developer_id: &str,
    scope: &str,
    actor: &str,
    now: i64,
) -> Result<Option<PackageScopeGrant>> {
    let grant_id = id(now);
    db.batch(vec![
        db.prepare(
            "INSERT INTO developer_package_scopes
             (id, developer_id, scope, status, granted_by_account_id, created_at, revoked_at)
             SELECT ?1, ?2, ?3, 'active', ?4, ?5, NULL
             WHERE EXISTS (SELECT 1 FROM developers WHERE id=?2)
             ON CONFLICT(developer_id, scope) DO UPDATE SET status='active',
             granted_by_account_id=excluded.granted_by_account_id,
             created_at=excluded.created_at, revoked_at=NULL",
        )
        .bind(&[
            value(&grant_id),
            value(developer_id),
            value(scope),
            value(actor),
            number(now),
        ])?,
        audit(
            db,
            Some(developer_id),
            Some(actor),
            "policy.package_scope.granted",
            now,
        )?,
    ])
    .await?;
    db.prepare(
        "SELECT id, developer_id, scope, status, granted_by_account_id, created_at, revoked_at
         FROM developer_package_scopes WHERE developer_id=?1 AND scope=?2",
    )
    .bind(&[value(developer_id), value(scope)])?
    .first(None)
    .await
}

pub async fn revoke_package_scope(
    db: &D1Database,
    developer_id: &str,
    grant_id: &str,
    actor: &str,
    now: i64,
) -> Result<bool> {
    let result = db
        .prepare(
            "UPDATE developer_package_scopes SET status='revoked', revoked_at=?1
             WHERE id=?2 AND developer_id=?3 AND status='active'",
        )
        .bind(&[number(now), value(grant_id), value(developer_id)])?
        .run()
        .await?;
    let changed = result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .is_some_and(|changes| changes == 1);
    if changed {
        audit(
            db,
            Some(developer_id),
            Some(actor),
            "policy.package_scope.revoked",
            now,
        )?
        .run()
        .await?;
    }
    Ok(changed)
}

pub async fn grant_capability(
    db: &D1Database,
    developer_id: &str,
    capability: &str,
    actor: &str,
    now: i64,
) -> Result<Option<CapabilityGrant>> {
    let grant_id = id(now);
    db.batch(vec![
        db.prepare(
            "INSERT INTO developer_capability_grants
             (id, developer_id, capability, status, granted_by_account_id, created_at, revoked_at)
             SELECT ?1, ?2, ?3, 'active', ?4, ?5, NULL
             WHERE EXISTS (SELECT 1 FROM developers WHERE id=?2)
             ON CONFLICT(developer_id, capability) DO UPDATE SET status='active',
             granted_by_account_id=excluded.granted_by_account_id,
             created_at=excluded.created_at, revoked_at=NULL",
        )
        .bind(&[
            value(&grant_id),
            value(developer_id),
            value(capability),
            value(actor),
            number(now),
        ])?,
        audit(
            db,
            Some(developer_id),
            Some(actor),
            "policy.capability.granted",
            now,
        )?,
    ])
    .await?;
    db.prepare(
        "SELECT id, developer_id, capability, status, granted_by_account_id, created_at, revoked_at
         FROM developer_capability_grants WHERE developer_id=?1 AND capability=?2",
    )
    .bind(&[value(developer_id), value(capability)])?
    .first(None)
    .await
}

pub async fn revoke_capability(
    db: &D1Database,
    developer_id: &str,
    grant_id: &str,
    actor: &str,
    now: i64,
) -> Result<bool> {
    let result = db
        .prepare(
            "UPDATE developer_capability_grants SET status='revoked', revoked_at=?1
             WHERE id=?2 AND developer_id=?3 AND status='active'",
        )
        .bind(&[number(now), value(grant_id), value(developer_id)])?
        .run()
        .await?;
    let changed = result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .is_some_and(|changes| changes == 1);
    if changed {
        audit(
            db,
            Some(developer_id),
            Some(actor),
            "policy.capability.revoked",
            now,
        )?
        .run()
        .await?;
    }
    Ok(changed)
}

pub async fn set_global_capability(
    db: &D1Database,
    capability: &str,
    status: &str,
    actor: &str,
    now: i64,
) -> Result<Option<GlobalCapability>> {
    db.batch(vec![
        db.prepare(
            "INSERT INTO global_issuable_capabilities (capability, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(capability) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
        )
        .bind(&[value(capability), value(status), number(now)])?,
        audit(
            db,
            None,
            Some(actor),
            if status == "active" {
                "policy.global_capability.enabled"
            } else {
                "policy.global_capability.disabled"
            },
            now,
        )?,
    ])
    .await?;
    db.prepare(
        "SELECT capability, status, created_at, updated_at
         FROM global_issuable_capabilities WHERE capability=?1",
    )
    .bind(&[value(capability)])?
    .first(None)
    .await
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
