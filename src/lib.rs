mod auth;
pub mod certificate;
mod model;
mod store;

use certificate::{DeveloperCertificate, FORMAT_VERSION, SIGNATURE_ALGORITHM, UnsignedCertificate};
use model::*;
use serde::Serialize;
use serde_json::json;
use worker::*;

fn now() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}

fn json_response<T: Serialize>(value: &T, status: u16) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

fn error(code: &str, message: &str, status: u16) -> Result<Response> {
    json_response(
        &json!({"error": {"code": code, "message": message}}),
        status,
    )
}

fn param<'a>(ctx: &'a RouteContext<()>, name: &str) -> &'a str {
    ctx.param(name).map(String::as_str).unwrap_or("")
}

fn valid_developer_type(value: &str) -> bool {
    matches!(value, "individual" | "organization")
}
fn valid_role(value: &str) -> bool {
    matches!(value, "owner" | "admin" | "developer" | "viewer")
}
fn valid_member_status(value: &str) -> bool {
    matches!(value, "active" | "invited" | "suspended" | "removed")
}
fn can_manage(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}
fn can_request_certificate(role: &str) -> bool {
    matches!(role, "owner" | "admin" | "developer")
}

async fn user(req: &Request, env: &Env) -> Result<Option<String>> {
    auth::account(req, env).await
}

async fn membership(
    req: &Request,
    ctx: &RouteContext<()>,
    developer_id: &str,
) -> Result<Option<Member>> {
    let Some(account_id) = user(req, &ctx.env).await? else {
        return Ok(None);
    };
    store::member_for_account(&ctx.env.d1("DB")?, developer_id, &account_id).await
}

async fn create_developer(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(account_id) = user(&req, &ctx.env).await? else {
        return error("UNAUTHENTICATED", "Active Accounts session required", 401);
    };
    let input: CreateDeveloper = req.json().await?;
    let name = input.display_name.trim();
    if !valid_developer_type(&input.developer_type) || name.is_empty() || name.chars().count() > 120
    {
        return error(
            "DEVELOPER_INPUT_INVALID",
            "Developer type or display name is invalid",
            422,
        );
    }
    match store::create_developer(
        &ctx.env.d1("DB")?,
        &account_id,
        &input.developer_type,
        name,
        input.creation_request_id.as_deref(),
        now(),
    )
    .await
    {
        Ok(Some(developer)) => json_response(&json!({"developer": developer}), 201),
        _ => error(
            "DEVELOPER_LIMIT_REACHED",
            "An approved unused request is required for another Developer",
            403,
        ),
    }
}

async fn list_developers(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(account_id) = user(&req, &ctx.env).await? else {
        return error("UNAUTHENTICATED", "Active Accounts session required", 401);
    };
    json_response(
        &json!({"developers": store::list_developers(&ctx.env.d1("DB")?, &account_id).await?}),
        200,
    )
}

async fn get_developer(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    if membership(&req, &ctx, developer_id).await?.is_none() {
        return error("FORBIDDEN", "Active membership required", 403);
    }
    match store::developer(&ctx.env.d1("DB")?, developer_id).await? {
        Some(developer) => json_response(&json!({"developer": developer}), 200),
        None => error("DEVELOPER_NOT_FOUND", "Developer not found", 404),
    }
}

async fn list_members(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    if membership(&req, &ctx, developer_id).await?.is_none() {
        return error("FORBIDDEN", "Active membership required", 403);
    }
    json_response(
        &json!({"members": store::members(&ctx.env.d1("DB")?, developer_id).await?}),
        200,
    )
}

async fn add_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    let Some(actor) = membership(&req, &ctx, developer_id).await? else {
        return error("FORBIDDEN", "Active membership required", 403);
    };
    let input: CreateMember = req.json().await?;
    if !can_manage(&actor.role)
        || !valid_role(&input.role)
        || (input.role == "owner" && actor.role != "owner")
    {
        return error("FORBIDDEN", "Insufficient role for membership change", 403);
    }
    if !auth::account_is_active(&input.account_id, &ctx.env).await? {
        return error("ACCOUNT_INACTIVE", "Target Account must be active", 422);
    }
    let member = store::add_member(
        &ctx.env.d1("DB")?,
        developer_id,
        &input.account_id,
        &input.role,
        now(),
        &actor.account_id,
    )
    .await?;
    json_response(&json!({"member": member}), 201)
}

async fn patch_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    let member_id = param(&ctx, "member_id");
    let Some(actor) = membership(&req, &ctx, developer_id).await? else {
        return error("FORBIDDEN", "Active membership required", 403);
    };
    let input: UpdateMember = req.json().await?;
    let target = store::members(&ctx.env.d1("DB")?, developer_id)
        .await?
        .into_iter()
        .find(|member| member.id == member_id);
    let Some(target) = target else {
        return error("MEMBER_NOT_FOUND", "Member not found", 404);
    };
    let ownership_change = target.role == "owner" || input.role.as_deref() == Some("owner");
    if !can_manage(&actor.role)
        || (ownership_change && actor.role != "owner")
        || input.role.as_deref().is_some_and(|role| !valid_role(role))
        || input
            .status
            .as_deref()
            .is_some_and(|status| !valid_member_status(status))
    {
        return error(
            "FORBIDDEN",
            "Insufficient role or invalid membership change",
            403,
        );
    }
    let result = store::update_member(
        &ctx.env.d1("DB")?,
        developer_id,
        member_id,
        input.role.as_deref(),
        input.status.as_deref(),
        now(),
        &actor.account_id,
    )
    .await;
    match result {
        Ok(member) => json_response(&json!({"member": member}), 200),
        Err(_) => error(
            "LAST_OWNER_REQUIRED",
            "Developer must retain an active owner",
            409,
        ),
    }
}

async fn delete_member(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    let member_id = param(&ctx, "member_id");
    let Some(actor) = membership(&req, &ctx, developer_id).await? else {
        return error("FORBIDDEN", "Active membership required", 403);
    };
    let target = store::members(&ctx.env.d1("DB")?, developer_id)
        .await?
        .into_iter()
        .find(|member| member.id == member_id);
    let Some(target) = target else {
        return error("MEMBER_NOT_FOUND", "Member not found", 404);
    };
    if !can_manage(&actor.role) || (target.role == "owner" && actor.role != "owner") {
        return error("FORBIDDEN", "Insufficient role", 403);
    }
    match store::update_member(
        &ctx.env.d1("DB")?,
        developer_id,
        member_id,
        None,
        Some("removed"),
        now(),
        &actor.account_id,
    )
    .await
    {
        Ok(_) => Ok(Response::empty()?.with_status(204)),
        Err(_) => error(
            "LAST_OWNER_REQUIRED",
            "Developer must retain an active owner",
            409,
        ),
    }
}

async fn create_creation_request(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(account_id) = user(&req, &ctx.env).await? else {
        return error("UNAUTHENTICATED", "Active Accounts session required", 401);
    };
    let input: CreateCreationRequest = req.json().await?;
    if !valid_developer_type(&input.requested_developer_type)
        || input.requested_display_name.trim().is_empty()
        || input.reason.trim().is_empty()
    {
        return error(
            "REQUEST_INVALID",
            "Display name, type, and reason are required",
            422,
        );
    }
    let value = store::create_creation_request(
        &ctx.env.d1("DB")?,
        &account_id,
        input.requested_display_name.trim(),
        &input.requested_developer_type,
        input.reason.trim(),
        now(),
    )
    .await?;
    json_response(&json!({"developer_creation_request": value}), 201)
}

async fn list_creation_requests(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(account_id) = user(&req, &ctx.env).await? else {
        return error("UNAUTHENTICATED", "Active Accounts session required", 401);
    };
    json_response(
        &json!({"developer_creation_requests": store::list_creation_requests(&ctx.env.d1("DB")?, &account_id).await?}),
        200,
    )
}

async fn create_certificate_request(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    let Some(member) = membership(&req, &ctx, developer_id).await? else {
        return error("FORBIDDEN", "Active membership required", 403);
    };
    if !can_request_certificate(&member.role) {
        return error("FORBIDDEN", "Role cannot request certificates", 403);
    }
    let input: certificate::CertificateRequestInput = req.json().await?;
    if let Err(reason) = input.validate() {
        return error("CERTIFICATE_REQUEST_INVALID", &reason, 422);
    }
    match store::create_certificate_request(
        &ctx.env.d1("DB")?,
        developer_id,
        &member.account_id,
        &input,
        now(),
    )
    .await
    {
        Ok(value) => json_response(&json!({"certificate_request": value}), 201),
        Err(_) => error(
            "DEVELOPER_NOT_ELIGIBLE",
            "Developer must be active and verified",
            409,
        ),
    }
}

async fn list_certificates(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    if membership(&req, &ctx, developer_id).await?.is_none() {
        return error("FORBIDDEN", "Active membership required", 403);
    }
    let rows = store::list_certificates(&ctx.env.d1("DB")?, developer_id).await?;
    json_response(
        &json!({"certificates": rows.into_iter().map(certificate_view).collect::<Result<Vec<_>>>()?}),
        200,
    )
}

fn certificate_view(row: CertificateRow) -> Result<serde_json::Value> {
    let certificate: DeveloperCertificate = serde_json::from_str(&row.certificate_json)?;
    Ok(json!({"id": row.id, "status": row.status, "certificate": certificate}))
}

async fn get_certificate(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match store::certificate(&ctx.env.d1("DB")?, param(&ctx, "certificate_id")).await? {
        Some(row) => {
            if membership(&req, &ctx, &row.developer_id).await?.is_none() {
                return error("FORBIDDEN", "Active membership required", 403);
            }
            json_response(&certificate_view(row)?, 200)
        }
        None => error("CERTIFICATE_NOT_FOUND", "Certificate not found", 404),
    }
}

async fn trust_store(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let key = certificate::signing_key(&ctx.env.secret("INTERMEDIATE_PRIVATE_KEY")?.to_string())
        .map_err(Error::RustError)?;
    json_response(
        &json!({
            "format_version": 1,
            "issuers": [{"issuer_key_id": ctx.env.var("ISSUER_KEY_ID")?.to_string(), "signature_algorithm": SIGNATURE_ALGORITHM,
                         "public_key": certificate::encoded_public_key(&key.verifying_key())}]
        }),
        200,
    )
}

async fn revocations(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    json_response(
        &json!({"format_version": 1, "generated_at": now(), "revocations": store::revocations(&ctx.env.d1("DB")?).await?}),
        200,
    )
}

async fn certificate_status(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let certificate_id = param(&ctx, "certificate_id");
    let Some(row) = store::certificate(&ctx.env.d1("DB")?, certificate_id).await? else {
        return error("CERTIFICATE_NOT_FOUND", "Certificate not found", 404);
    };
    let Some(developer) = store::developer(&ctx.env.d1("DB")?, &row.developer_id).await? else {
        return error("CERTIFICATE_INVALID", "Developer not found", 409);
    };
    let key = certificate::signing_key(&ctx.env.secret("INTERMEDIATE_PRIVATE_KEY")?.to_string())
        .map_err(Error::RustError)?;
    let parsed: DeveloperCertificate = serde_json::from_str(&row.certificate_json)?;
    let valid = row.status == "active"
        && developer.status == "active"
        && developer.verification_status == "verified"
        && parsed.content.developer_id == row.developer_id
        && parsed.content.serial_number == row.serial_number
        && parsed.content.issuer_key_id == row.issuer_key_id
        && parsed.content.subject_key_id == row.subject_key_id
        && parsed.content.not_before == row.not_before
        && parsed.content.not_after == row.not_after
        && parsed.content.issuer_key_id == ctx.env.var("ISSUER_KEY_ID")?.to_string()
        && parsed.verify(&key.verifying_key(), now()).is_ok();
    json_response(
        &json!({"certificate_id": certificate_id, "status": if valid {"valid"} else {"invalid"}, "valid": valid}),
        200,
    )
}

async fn require_admin(req: &Request, env: &Env) -> Result<Option<String>> {
    auth::admin(req, env).await
}

async fn admin_verification(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let input: VerificationInput = req.json().await?;
    if !matches!(
        input.verification_status.as_str(),
        "pending" | "verified" | "rejected"
    ) {
        return error("STATUS_INVALID", "Invalid verification status", 422);
    }
    let developer = store::update_verification(
        &ctx.env.d1("DB")?,
        param(&ctx, "developer_id"),
        &input.verification_status,
        &actor,
        now(),
    )
    .await?;
    json_response(&json!({"developer": developer}), 200)
}

async fn admin_suspend(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let developer = store::suspend_developer(
        &ctx.env.d1("DB")?,
        param(&ctx, "developer_id"),
        &actor,
        now(),
    )
    .await?;
    json_response(&json!({"developer": developer}), 200)
}

async fn admin_creation_review(
    mut req: Request,
    ctx: RouteContext<()>,
    status: &'static str,
) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let input: ReviewInput = req.json().await.unwrap_or(ReviewInput {
        rejection_reason: None,
    });
    if status == "rejected" && input.rejection_reason.as_deref().is_none_or(str::is_empty) {
        return error(
            "REJECTION_REASON_REQUIRED",
            "Rejection reason required",
            422,
        );
    }
    let value = store::review_creation_request(
        &ctx.env.d1("DB")?,
        param(&ctx, "request_id"),
        status,
        &actor,
        input.rejection_reason.as_deref(),
        now(),
    )
    .await?;
    json_response(&json!({"developer_creation_request": value}), 200)
}

async fn admin_issue(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let request_id = param(&ctx, "request_id");
    let Some(request) = store::certificate_request(&ctx.env.d1("DB")?, request_id).await? else {
        return error(
            "CERTIFICATE_REQUEST_NOT_FOUND",
            "Certificate request not found",
            404,
        );
    };
    if request.status != "pending" {
        return error(
            "CERTIFICATE_REQUEST_NOT_PENDING",
            "Certificate request is not pending",
            409,
        );
    }
    let developer = store::developer(&ctx.env.d1("DB")?, &request.developer_id).await?;
    if !developer
        .as_ref()
        .is_some_and(|d| d.status == "active" && d.verification_status == "verified")
    {
        return error(
            "DEVELOPER_NOT_ELIGIBLE",
            "Developer must be active and verified",
            409,
        );
    }
    let mut serial_bytes = [0_u8; 16];
    getrandom::fill(&mut serial_bytes)
        .map_err(|_| Error::RustError("secure random generation failed".into()))?;
    let serial = serial_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let certificate_id = store::id();
    let issued_at = now();
    let ttl = ctx
        .env
        .var("CERTIFICATE_TTL_SECONDS")?
        .to_string()
        .parse::<i64>()
        .unwrap_or(31_536_000);
    let issuer_key_id = ctx.env.var("ISSUER_KEY_ID")?.to_string();
    let input = certificate::CertificateRequestInput {
        signature_algorithm: request.signature_algorithm.clone(),
        subject_public_key: request.subject_public_key.clone(),
        package_id_scopes: serde_json::from_str(&request.package_id_scopes_json)?,
        allowed_capabilities: serde_json::from_str(&request.allowed_capabilities_json)?,
    };
    input.validate().map_err(Error::RustError)?;
    let content = UnsignedCertificate {
        format_version: FORMAT_VERSION,
        serial_number: serial.clone(),
        issuer_key_id: issuer_key_id.clone(),
        developer_id: request.developer_id.clone(),
        subject_key_id: request.subject_key_id.clone(),
        subject_public_key: request.subject_public_key.clone(),
        not_before: issued_at,
        not_after: issued_at + ttl.max(60),
        key_usage: vec!["manifest-signing".into()],
        package_id_scopes: input.package_id_scopes,
        allowed_capabilities: input.allowed_capabilities,
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
    };
    let key = certificate::signing_key(&ctx.env.secret("INTERMEDIATE_PRIVATE_KEY")?.to_string())
        .map_err(Error::RustError)?;
    let certificate = DeveloperCertificate::issue(content, &key).map_err(Error::RustError)?;
    let row = store::issue_certificate(
        &ctx.env.d1("DB")?,
        &request,
        store::IssuedCertificateRecord {
            certificate_id: &certificate_id,
            serial: &serial,
            issuer: &issuer_key_id,
            certificate_json: &serde_json::to_string(&certificate)?,
            not_before: issued_at,
            not_after: issued_at + ttl.max(60),
            actor: &actor,
            now: issued_at,
        },
    )
    .await?;
    match row {
        Some(row) => json_response(&certificate_view(row)?, 201),
        None => error(
            "CERTIFICATE_ISSUE_CONFLICT",
            "Certificate request changed or Developer became ineligible",
            409,
        ),
    }
}

async fn admin_reject_certificate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let input: ReviewInput = req.json().await.unwrap_or(ReviewInput {
        rejection_reason: None,
    });
    if input.rejection_reason.as_deref().is_none_or(str::is_empty) {
        return error(
            "REJECTION_REASON_REQUIRED",
            "Rejection reason required",
            422,
        );
    }
    let row = store::reject_certificate_request(
        &ctx.env.d1("DB")?,
        param(&ctx, "request_id"),
        &actor,
        input.rejection_reason.as_deref(),
        now(),
    )
    .await?;
    json_response(&json!({"certificate_request": row}), 200)
}

async fn admin_revoke(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let input: RevokeInput = req.json().await?;
    if input.reason.trim().is_empty() {
        return error(
            "REVOCATION_REASON_REQUIRED",
            "Revocation reason required",
            422,
        );
    }
    match store::revoke_certificate(
        &ctx.env.d1("DB")?,
        param(&ctx, "certificate_id"),
        &actor,
        input.reason.trim(),
        now(),
    )
    .await?
    {
        Some(row) => json_response(&certificate_view(row)?, 200),
        None => error("CERTIFICATE_NOT_FOUND", "Certificate not found", 404),
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get_async("/health", |_, _| async {
            json_response(&json!({"status":"ok","service":"developer-ca"}), 200)
        })
        .post_async("/v1/developers", create_developer)
        .get_async("/v1/developers", list_developers)
        .get_async("/v1/developers/:developer_id", get_developer)
        .get_async("/v1/developers/:developer_id/members", list_members)
        .post_async("/v1/developers/:developer_id/members", add_member)
        .patch_async(
            "/v1/developers/:developer_id/members/:member_id",
            patch_member,
        )
        .delete_async(
            "/v1/developers/:developer_id/members/:member_id",
            delete_member,
        )
        .post_async("/v1/developer-creation-requests", create_creation_request)
        .get_async("/v1/developer-creation-requests", list_creation_requests)
        .post_async(
            "/v1/developers/:developer_id/certificate-requests",
            create_certificate_request,
        )
        .get_async(
            "/v1/developers/:developer_id/certificates",
            list_certificates,
        )
        .get_async("/v1/certificates/:certificate_id", get_certificate)
        .get_async("/v1/trust-store", trust_store)
        .get_async("/v1/revocations", revocations)
        .get_async(
            "/v1/certificates/:certificate_id/status",
            certificate_status,
        )
        .post_async(
            "/v1/admin/developers/:developer_id/verification",
            admin_verification,
        )
        .post_async("/v1/admin/developers/:developer_id/suspend", admin_suspend)
        .post_async(
            "/v1/admin/developer-creation-requests/:request_id/approve",
            |req, ctx| admin_creation_review(req, ctx, "approved"),
        )
        .post_async(
            "/v1/admin/developer-creation-requests/:request_id/reject",
            |req, ctx| admin_creation_review(req, ctx, "rejected"),
        )
        .post_async(
            "/v1/admin/certificate-requests/:request_id/issue",
            admin_issue,
        )
        .post_async(
            "/v1/admin/certificate-requests/:request_id/reject",
            admin_reject_certificate,
        )
        .post_async(
            "/v1/admin/certificates/:certificate_id/revoke",
            admin_revoke,
        )
        .run(req, env)
        .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn schema_enforces_ownership_and_unique_serials() {
        let schema = include_str!("../migrations/0001_developer_ca.sql");
        assert!(schema.contains("prevent_last_owner_removal"));
        assert!(schema.contains("serial_number TEXT NOT NULL UNIQUE"));
        assert!(schema.contains("developer_id TEXT NOT NULL REFERENCES developers(id)"));
        assert!(schema.contains("audit_logs_no_update"));
    }

    #[test]
    fn service_has_no_upload_or_object_storage_configuration() {
        let manifest = include_str!("../Cargo.toml").to_ascii_lowercase();
        let config = include_str!("../wrangler.toml").to_ascii_lowercase();
        for forbidden in [
            "aws-sdk",
            "object_store",
            "r2_",
            "bucket_",
            "upload_",
            "storage_",
        ] {
            assert!(!manifest.contains(forbidden));
            assert!(!config.contains(forbidden));
        }
    }
}
