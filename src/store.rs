use serde::de::DeserializeOwned;
use uuid::{NoContext, Timestamp, Uuid};
use worker::{D1Database, Result, wasm_bindgen::JsValue};

use crate::certificate::CertificateRequestInput;
use crate::model::{CertificateRow, CreationRequest, Developer, Member, Revocation};

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

pub struct RegisteredCertificateRecord<'a> {
    pub request_id: &'a str,
    pub certificate_id: &'a str,
    pub serial: &'a str,
    pub issuer: &'a str,
    pub certificate_json: &'a str,
    pub not_before: i64,
    pub not_after: i64,
    pub now: i64,
}

pub async fn register_certificate(
    db: &D1Database,
    developer_id: &str,
    account_id: &str,
    input: &CertificateRequestInput,
    registered: RegisteredCertificateRecord<'_>,
) -> Result<Option<CertificateRow>> {
    let subject_key_id = input.subject_key_id().map_err(worker::Error::RustError)?;
    db.batch(vec![
        db.prepare(
            "INSERT INTO certificate_requests
             (id, developer_id, requested_by_account_id, signature_algorithm, subject_public_key,
              subject_key_id, package_id_scopes_json, allowed_capabilities_json, status,
              processed_by_account_id, processed_at, created_at, updated_at)
             SELECT ?1, developer.id, ?2, ?3, ?4, ?5, ?6, ?7, 'issued', ?2, ?8, ?8, ?8
             FROM developers developer
             JOIN developer_members member ON member.developer_id=developer.id
             WHERE developer.id=?9 AND developer.status='active'
               AND developer.verification_status='verified' AND member.account_id=?2
               AND member.status='active' AND member.role IN ('owner', 'admin', 'developer')",
        ).bind(&[
            value(registered.request_id), value(account_id), value(&input.signature_algorithm),
            value(&input.subject_public_key), value(&subject_key_id),
            value(serde_json::to_string(&input.package_id_scopes)?),
            value(serde_json::to_string(&input.allowed_capabilities)?), number(registered.now),
            value(developer_id),
        ])?,
        db.prepare(
            "INSERT INTO certificates
             (id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
              certificate_json, not_before, not_after, status, created_at)
             SELECT ?1, request.id, request.developer_id, ?2, ?3, request.subject_key_id,
                    ?4, ?5, ?6, 'active', ?7
             FROM certificate_requests request
             WHERE request.id=?8 AND request.status='issued'
               AND request.requested_by_account_id=?9",
        ).bind(&[
            value(registered.certificate_id), value(registered.serial), value(registered.issuer),
            value(registered.certificate_json), number(registered.not_before), number(registered.not_after),
            number(registered.now), value(registered.request_id), value(account_id),
        ])?,
        db.prepare(
            "INSERT INTO audit_logs (id, developer_id, actor_account_id, event_type, metadata_json, created_at)
             SELECT ?1, ?2, ?3, 'certificate.registered', '{}', ?4
             FROM certificates WHERE id=?5",
        ).bind(&[
            value(id(registered.now)), value(developer_id), value(account_id), number(registered.now),
            value(registered.certificate_id),
        ])?,
    ]).await?;
    certificate(db, registered.certificate_id).await
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

pub async fn active_certificates(db: &D1Database) -> Result<Vec<CertificateRow>> {
    all(db.prepare(
        "SELECT id, certificate_request_id, developer_id, serial_number, issuer_key_id, subject_key_id,
         certificate_json, not_before, not_after, status, created_at FROM certificates
         WHERE status='active' ORDER BY created_at DESC LIMIT 100",
    ))
    .await
}

pub async fn revoke_certificate(
    db: &D1Database,
    certificate_id: &str,
    actor: &str,
    reason: &str,
    reason_code: &str,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_uuid_v7_without_system_clock_access() {
        let parsed = Uuid::parse_str(&id(1_700_000_000)).unwrap();
        assert_eq!(parsed.get_version_num(), 7);
    }
}
