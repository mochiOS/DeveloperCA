use serde::de::DeserializeOwned;
use uuid::Uuid;
use worker::{D1Database, Result, wasm_bindgen::JsValue};

use crate::certificate::CertificateRequestInput;
use crate::model::{
    CertificateRequestRow, CertificateRow, CreationRequest, Developer, Member, Revocation,
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
pub fn id() -> String {
    Uuid::now_v7().to_string()
}

fn audit(
    db: &D1Database,
    developer_id: Option<&str>,
    actor: Option<&str>,
    event: &str,
    now: i64,
) -> Result<worker::D1PreparedStatement> {
    db.prepare("INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at) VALUES (?1, ?2, ?3, ?4, '{}', ?5)")
        .bind(&[value(id()), nullable(developer_id), nullable(actor), value(event), number(now)])
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
    let developer_id = id();
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
        ).bind(&[value(id()), value(&developer_id), value(account_id), number(now)])?,
        db.prepare(
            "UPDATE developer_creation_requests SET status='consumed', updated_at=?1
             WHERE id=?2 AND account_id=?3 AND status='approved' AND EXISTS (SELECT 1 FROM developers WHERE id=?4)",
        ).bind(&[number(now), request, value(account_id), value(&developer_id)])?,
        db.prepare(
            "INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
             SELECT ?1, ?2, ?3, 'developer.created', '{}', ?4 FROM developers WHERE id=?2",
        ).bind(&[value(id()), value(&developer_id), value(account_id), number(now)])?,
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
    let member_id = id();
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
    let request_id = id();
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
    let request_id = id();
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
        ).bind(&[value(id()), value(developer_id), value(account_id), number(now), value(&request_id)])?,
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
             AND EXISTS (SELECT 1 FROM developers WHERE id=?3 AND status='active' AND verification_status='verified')",
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

pub async fn revoke_certificate(
    db: &D1Database,
    certificate_id: &str,
    actor: &str,
    reason: &str,
    now: i64,
) -> Result<Option<CertificateRow>> {
    let Some(cert) = certificate(db, certificate_id).await? else {
        return Ok(None);
    };
    db.batch(vec![
        db.prepare("UPDATE certificates SET status='revoked' WHERE id=?1 AND status='active'")
            .bind(&[value(certificate_id)])?,
        db.prepare(
            "INSERT INTO revocations (id, certificate_id, serial_number, reason, revoked_by_account_id, revoked_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM certificates WHERE id=?2 AND status='revoked')
             ON CONFLICT(certificate_id) DO NOTHING",
        ).bind(&[value(id()), value(certificate_id), value(&cert.serial_number), value(reason), value(actor), number(now)])?,
        audit(db, Some(&cert.developer_id), Some(actor), "certificate.revoked", now)?,
    ]).await?;
    certificate(db, certificate_id).await
}

pub async fn revocations(db: &D1Database) -> Result<Vec<Revocation>> {
    all(db.prepare(
        "SELECT id, certificate_id, serial_number, reason, revoked_by_account_id, revoked_at FROM revocations ORDER BY revoked_at",
    )).await
}
