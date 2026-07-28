mod auth;
pub mod certificate;
mod model;
mod store;

use crate::model::RevocationReasonCode;
use model::*;
use serde::Serialize;
use serde_json::json;
use worker::*;

const STATUS_ORIGIN: &str = "https://status.mochios.org";

fn now() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}

fn json_response<T: Serialize>(value: &T, status: u16) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

fn with_health_cors(mut response: Response) -> Result<Response> {
    let headers = response.headers_mut();
    headers.set("Access-Control-Allow-Origin", STATUS_ORIGIN)?;
    headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    headers.set("Access-Control-Max-Age", "3600")?;
    headers.set("Cache-Control", "no-store")?;
    headers.set("Vary", "Origin")?;
    Ok(response)
}

fn health_response() -> Result<Response> {
    with_health_cors(Response::from_json(
        &json!({"status":"ok","service":"developer-ca"}),
    )?)
}

fn health_preflight() -> Result<Response> {
    with_health_cors(Response::empty()?.with_status(204))
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

fn root_public_keys(env: &Env) -> Option<Vec<[u8; 32]>> {
    env.secret("MOCHIOS_ROOT_PUBLIC_KEYS_HEX")
        .or_else(|_| env.secret("OFFLINE_ROOT_PUBLIC_KEY"))
        .ok()
        .and_then(|value| certificate::root_public_keys(&value.to_string()).ok())
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

async fn register_certificate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let developer_id = param(&ctx, "developer_id");
    let Some(member) = membership(&req, &ctx, developer_id).await? else {
        return error("FORBIDDEN", "Active membership required", 403);
    };
    if !can_request_certificate(&member.role) {
        return error("FORBIDDEN", "Role cannot request certificates", 403);
    }
    let input: certificate::CertificateRegistrationInput = req.json().await?;
    let wire = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        input.certificate.trim(),
    ) {
        Ok(value)
            if !value.is_empty() && value.len() <= mochios_certificate::MAX_CERTIFICATE_LEN =>
        {
            value
        }
        _ => {
            return error(
                "CERTIFICATE_INVALID",
                "Certificate must be a Base64 MCER v1 value",
                422,
            );
        }
    };
    let parsed = match certificate::decode(&wire) {
        Ok(value) => value,
        Err(reason) => return error("CERTIFICATE_INVALID", &reason, 422),
    };
    let Some(developer) = store::developer(&ctx.env.d1("DB")?, developer_id).await? else {
        return error("DEVELOPER_NOT_FOUND", "Developer not found", 404);
    };
    if parsed.developer_id != developer.certificate_developer_id {
        return error(
            "CERTIFICATE_DEVELOPER_MISMATCH",
            "Certificate developer ID does not match",
            422,
        );
    }
    let root_keys = match root_public_keys(&ctx.env) {
        Some(value) => value,
        None => {
            return error(
                "ROOT_KEY_UNAVAILABLE",
                "Root public key is unavailable",
                503,
            );
        }
    };
    let Some(root_key) = root_keys
        .iter()
        .find(|key| mochios_certificate::key_id(key) == parsed.issuer_key_id)
    else {
        return error(
            "CERTIFICATE_ISSUER_UNKNOWN",
            "Certificate issuer is not trusted",
            422,
        );
    };
    let registered_at = now();
    if let Err(reason) = certificate::verify(&parsed, root_key, registered_at as u64) {
        return error("CERTIFICATE_INVALID", &reason, 422);
    }
    let request = certificate::request_from_certificate(&parsed);
    let db = ctx.env.d1("DB")?;
    let certificate_id = store::id(registered_at);
    let request_id = store::id(registered_at);
    let certificate_wire = certificate::encode_base64(&wire);
    let row = store::register_certificate(
        &db,
        developer_id,
        &member.account_id,
        &request,
        store::RegisteredCertificateRecord {
            request_id: &request_id,
            certificate_id: &certificate_id,
            serial: &parsed.serial_number.to_string(),
            issuer: &certificate::hex(&parsed.issuer_key_id),
            certificate_json: &certificate_wire,
            not_before: parsed.not_before as i64,
            not_after: parsed.not_after as i64,
            now: registered_at,
        },
    )
    .await?;
    match row {
        Some(row) => json_response(&certificate_view(row)?, 201),
        None => error(
            "DEVELOPER_NOT_ELIGIBLE",
            "Developer must be active, verified, and registered by an eligible member",
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
    let certificate =
        certificate::decode_base64(&row.certificate_json).map_err(Error::RustError)?;
    Ok(json!({
        "id": row.id,
        "developer_id": row.developer_id,
        "status": row.status,
        "certificate": certificate::view(&certificate),
        "certificate_wire": row.certificate_json,
    }))
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
    let keys = match root_public_keys(&ctx.env) {
        Some(value) => value,
        None => {
            return error(
                "ROOT_KEY_UNAVAILABLE",
                "Root public key is unavailable",
                503,
            );
        }
    };
    let root_keys = keys
        .iter()
        .map(|key| json!({
            "key_id": certificate::hex(&mochios_certificate::key_id(key)),
            "public_key": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key),
        }))
        .collect::<Vec<_>>();
    let mut response = Response::from_json(&json!({
        "format": 1,
        "trust_model": "root-direct",
        "root_keys": root_keys,
    }))?;
    response
        .headers_mut()
        .set("Cache-Control", "public, max-age=300, must-revalidate")?;
    Ok(response)
}

async fn revocations(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let records = store::revocations(&ctx.env.d1("DB")?).await?;
    let mut serials = records
        .iter()
        .filter_map(|record| record.serial_number.parse::<u64>().ok())
        .collect::<Vec<_>>();
    serials.sort_unstable();
    serials.dedup();
    let mut response = Response::from_json(&json!({
        "format": 1,
        "generated_at": now(),
        "certificate_serials": serials,
        "distribution": "embed serials into signature.service with MOCHIOS_REVOKED_CERTIFICATE_SERIALS",
    }))?;
    response
        .headers_mut()
        .set("Cache-Control", "public, max-age=60, must-revalidate")?;
    Ok(response)
}

async fn certificate_status(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let certificate_id = param(&ctx, "certificate_id");
    let Some(row) = store::certificate(&ctx.env.d1("DB")?, certificate_id).await? else {
        return error("CERTIFICATE_NOT_FOUND", "Certificate not found", 404);
    };
    let db = ctx.env.d1("DB")?;
    let at = now();
    let invalid = |reason: &str| {
        json_response(
            &json!({"certificate_id": certificate_id, "status": "invalid", "valid": false, "reason": reason}),
            200,
        )
    };
    if row.status == "revoked"
        || store::revocation_for_certificate(&db, certificate_id)
            .await?
            .is_some()
    {
        return invalid("CERTIFICATE_REVOKED");
    }
    if row.status != "active" {
        return invalid("METADATA_MISMATCH");
    }
    if row.not_after <= at {
        return invalid("CERTIFICATE_EXPIRED");
    }
    let Some(developer) = store::developer(&db, &row.developer_id).await? else {
        return invalid("METADATA_MISMATCH");
    };
    if developer.status != "active" {
        return invalid("DEVELOPER_SUSPENDED");
    }
    if developer.verification_status != "verified" {
        return invalid("DEVELOPER_NOT_VERIFIED");
    }
    let Ok(parsed) = certificate::decode_base64(&row.certificate_json) else {
        return invalid("SIGNATURE_INVALID");
    };
    if parsed.developer_id != row.developer_id
        || parsed.serial_number.to_string() != row.serial_number
        || certificate::hex(&parsed.issuer_key_id) != row.issuer_key_id
        || certificate::hex(&parsed.subject_key_id) != row.subject_key_id
        || parsed.not_before != row.not_before as u64
        || parsed.not_after != row.not_after as u64
    {
        return invalid("METADATA_MISMATCH");
    }
    let Some(root_public_key) = root_public_keys(&ctx.env).and_then(|keys| {
        keys.into_iter()
            .find(|key| mochios_certificate::key_id(key) == parsed.issuer_key_id)
    }) else {
        return invalid("ISSUER_UNKNOWN");
    };
    if certificate::verify(&parsed, &root_public_key, at as u64).is_err() {
        return invalid(if parsed.not_after <= at as u64 {
            "CERTIFICATE_EXPIRED"
        } else {
            "SIGNATURE_INVALID"
        });
    }
    json_response(
        &json!({"certificate_id": certificate_id, "status": "valid", "valid": true, "reason": "VALID"}),
        200,
    )
}

async fn require_admin(req: &Request, env: &Env) -> Result<Option<auth::AdminActor>> {
    auth::admin(req, env).await
}

async fn consume_admin_action(
    actor: &auth::AdminActor,
    env: &Env,
    operation: &str,
) -> Result<bool> {
    store::consume_authentication_jti(
        &env.d1("DB")?,
        &actor.jti,
        &actor.account_id,
        operation,
        actor.expires_at,
        now(),
    )
    .await
}

async fn admin_review_queue(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if require_admin(&req, &ctx.env).await?.is_none() {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    }
    let db = ctx.env.d1("DB")?;
    let developers = store::pending_developer_reviews(&db).await?;
    let developer_creation_requests = store::pending_creation_reviews(&db).await?;
    let certificates = store::active_certificates(&db)
        .await?
        .into_iter()
        .map(certificate_view)
        .collect::<Result<Vec<_>>>()?;
    json_response(
        &json!({
            "developers": developers,
            "developer_creation_requests": developer_creation_requests,
            "certificates": certificates,
        }),
        200,
    )
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
    if !consume_admin_action(&actor, &ctx.env, "developer.verification").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    let developer = store::update_verification(
        &ctx.env.d1("DB")?,
        param(&ctx, "developer_id"),
        &input.verification_status,
        &actor.account_id,
        now(),
    )
    .await?;
    store::record_admin_audit(
        &ctx.env.d1("DB")?,
        Some(param(&ctx, "developer_id")),
        &actor.account_id,
        "admin.developer.verification",
        &actor.jti,
        now(),
    )
    .await?;
    json_response(&json!({"developer": developer}), 200)
}

async fn admin_suspend(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    if !consume_admin_action(&actor, &ctx.env, "developer.suspend").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    let developer = store::suspend_developer(
        &ctx.env.d1("DB")?,
        param(&ctx, "developer_id"),
        &actor.account_id,
        now(),
    )
    .await?;
    store::record_admin_audit(
        &ctx.env.d1("DB")?,
        Some(param(&ctx, "developer_id")),
        &actor.account_id,
        "admin.developer.suspend",
        &actor.jti,
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
    if !consume_admin_action(&actor, &ctx.env, "developer_creation_request.review").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    let value = store::review_creation_request(
        &ctx.env.d1("DB")?,
        param(&ctx, "request_id"),
        status,
        &actor.account_id,
        input.rejection_reason.as_deref(),
        now(),
    )
    .await?;
    store::record_admin_audit(
        &ctx.env.d1("DB")?,
        None,
        &actor.account_id,
        "admin.developer_creation_request.review",
        &actor.jti,
        now(),
    )
    .await?;
    json_response(&json!({"developer_creation_request": value}), 200)
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
    let revoked_at = now();
    let db = ctx.env.d1("DB")?;
    let certificate_id = param(&ctx, "certificate_id");
    let Some(certificate) = store::certificate(&db, certificate_id).await? else {
        return error("CERTIFICATE_NOT_FOUND", "Certificate not found", 404);
    };
    if certificate.status != "active" {
        return error("CERTIFICATE_NOT_ACTIVE", "Certificate is not active", 409);
    }
    let reason_code = input
        .reason_code
        .unwrap_or(RevocationReasonCode::Unspecified);
    if !consume_admin_action(&actor, &ctx.env, "certificate.revoke").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    match store::revoke_certificate(
        &db,
        certificate_id,
        &actor.account_id,
        input.reason.trim(),
        reason_code.as_str(),
        revoked_at,
    )
    .await?
    {
        Some(row) => {
            store::record_admin_audit(
                &ctx.env.d1("DB")?,
                Some(&row.developer_id),
                &actor.account_id,
                "admin.certificate.revoke",
                &actor.jti,
                now(),
            )
            .await?;
            json_response(&certificate_view(row)?, 200)
        }
        None => error("CERTIFICATE_NOT_FOUND", "Certificate not found", 404),
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get_async("/health", |_, _| async { health_response() })
        .options_async("/health", |_, _| async { health_preflight() })
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
            "/v1/developers/:developer_id/certificates/register",
            register_certificate,
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
        .get_async("/v1/admin/review-queue", admin_review_queue)
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

        let trust_schema = include_str!("../migrations/0002_trust_issuers_policy.sql");
        assert!(trust_schema.contains("authentication_replay_cache"));
        let root_direct = include_str!("../migrations/0004_root_direct_trust.sql");
        assert!(root_direct.contains("DROP TABLE revocation_snapshots"));
        assert!(root_direct.contains("DROP TABLE trust_snapshots"));
        assert!(root_direct.contains("DROP TABLE issuers"));
        let automatic_schema =
            include_str!("../migrations/0003_automatic_certificate_issuance.sql");
        assert!(automatic_schema.contains("Legacy pending request"));
        assert!(automatic_schema.contains("DROP TABLE developer_package_scopes"));
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

    #[test]
    fn certificate_registration_is_self_service_and_admin_can_only_revoke() {
        let source = include_str!("lib.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or_default();
        let store = include_str!("store.rs");
        assert!(production.contains("/v1/developers/:developer_id/certificates/register"));
        assert!(production.contains(".get_async(\"/v1/admin/review-queue\", admin_review_queue)"));
        assert!(production.contains("require_admin(&req, &ctx.env)"));
        assert!(production.contains("active_certificates(&db)"));
        assert!(production.contains("/v1/admin/certificates/:certificate_id/revoke"));
        assert!(!production.contains("/v1/admin/certificate-requests"));
        assert!(!production.contains("admin_developer_policy"));
        assert!(store.contains("member.role IN ('owner', 'admin', 'developer')"));
        assert!(store.contains("'certificate.registered'"));
    }
}
