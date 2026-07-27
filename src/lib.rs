mod auth;
pub mod certificate;
mod model;
mod store;

use mochios_developer_ca_trust::{
    IssuerStatus, MAX_SNAPSHOT_BYTES, REVOCATION_FORMAT_VERSION, RevocationReasonCode,
    RevocationSnapshot as SignedRevocationSnapshot, SIGNATURE_ALGORITHM, SnapshotRevocation,
    TrustSnapshot, UnsignedRevocationSnapshot,
};
use model::*;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
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

async fn issue_certificate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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
    let issued_at = now();
    let db = ctx.env.d1("DB")?;
    let (key, issuer) = match active_certificate_signer(&ctx.env, &db, issued_at as u64).await? {
        Ok(value) => value,
        Err(value) => return error(value.code, value.message, value.status),
    };
    let ttl = ctx
        .env
        .var("CERTIFICATE_TTL_SECONDS")?
        .to_string()
        .parse::<i64>()
        .unwrap_or(31_536_000);
    let not_after = issued_at.saturating_add(ttl.max(60)).min(issuer.not_after);
    if not_after <= issued_at.saturating_add(59) {
        return error(
            "ISSUER_VALIDITY_TOO_SHORT",
            "The active Intermediate expires too soon to issue a certificate",
            503,
        );
    }
    let mut serial_bytes = [0_u8; 8];
    getrandom::fill(&mut serial_bytes)
        .map_err(|_| Error::RustError("secure random generation failed".into()))?;
    let serial = u64::from_le_bytes(serial_bytes).max(1);
    let certificate_id = store::id(issued_at);
    let request_id = store::id(issued_at);
    let wire = certificate::issue(
        certificate::IssueCertificate {
            serial_number: serial,
            developer_id,
            not_before: issued_at as u64,
            not_after: not_after as u64,
            request: &input,
        },
        &key,
    )
    .map_err(Error::RustError)?;
    let certificate_wire = certificate::encode_base64(&wire);
    let row = store::issue_certificate(
        &db,
        developer_id,
        &member.account_id,
        &input,
        store::IssuedCertificateRecord {
            request_id: &request_id,
            certificate_id: &certificate_id,
            serial: &serial.to_string(),
            issuer: &issuer.key_id,
            certificate_json: &certificate_wire,
            not_before: issued_at,
            not_after,
            now: issued_at,
        },
    )
    .await?;
    match row {
        Some(row) => json_response(&certificate_view(row)?, 201),
        None => error(
            "DEVELOPER_NOT_ELIGIBLE",
            "Developer must be active, verified, and requested by an eligible member",
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

fn snapshot_response(
    request: &Request,
    snapshot_json: String,
    etag: &str,
    cache_control: &str,
) -> Result<Response> {
    let quoted_etag = format!("\"{etag}\"");
    let not_modified = request
        .headers()
        .get("If-None-Match")?
        .is_some_and(|header| etag_matches(&header, &quoted_etag));
    let mut response = if not_modified {
        Response::empty()?.with_status(304)
    } else {
        Response::from_bytes(snapshot_json.into_bytes())?.with_status(200)
    };
    response
        .headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")?;
    response.headers_mut().set("ETag", &quoted_etag)?;
    response.headers_mut().set("Cache-Control", cache_control)?;
    Ok(response)
}

fn etag_matches(header: &str, quoted_etag: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        candidate == "*"
            || candidate == quoted_etag
            || candidate
                .strip_prefix("W/")
                .is_some_and(|weak| weak == quoted_etag)
    })
}

async fn trust_store(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(snapshot) = store::current_trust_snapshot(&ctx.env.d1("DB")?).await? else {
        return error(
            "TRUST_SNAPSHOT_UNAVAILABLE",
            "No verified trust snapshot is registered",
            503,
        );
    };
    snapshot_response(
        &req,
        snapshot.snapshot_json,
        &snapshot.etag,
        "public, max-age=300, must-revalidate",
    )
}

async fn trust_store_version(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let version = match param(&ctx, "snapshot_version").parse::<i64>() {
        Ok(version) if version > 0 => version,
        _ => {
            return error(
                "SNAPSHOT_VERSION_INVALID",
                "Snapshot version is invalid",
                422,
            );
        }
    };
    let Some(snapshot) = store::trust_snapshot(&ctx.env.d1("DB")?, version).await? else {
        return error("TRUST_SNAPSHOT_NOT_FOUND", "Trust snapshot not found", 404);
    };
    snapshot_response(
        &req,
        snapshot.snapshot_json,
        &snapshot.etag,
        "public, max-age=86400, immutable",
    )
}

async fn revocations(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(snapshot) = store::current_revocation_snapshot(&ctx.env.d1("DB")?).await? else {
        return error(
            "REVOCATION_SNAPSHOT_UNAVAILABLE",
            "No signed revocation snapshot is available",
            503,
        );
    };
    snapshot_response(
        &req,
        snapshot.snapshot_json,
        &snapshot.etag,
        "public, max-age=60, must-revalidate",
    )
}

async fn revocations_version(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let version = match param(&ctx, "snapshot_version").parse::<i64>() {
        Ok(version) if version > 0 => version,
        _ => {
            return error(
                "SNAPSHOT_VERSION_INVALID",
                "Snapshot version is invalid",
                422,
            );
        }
    };
    let Some(snapshot) = store::revocation_snapshot(&ctx.env.d1("DB")?, version).await? else {
        return error(
            "REVOCATION_SNAPSHOT_NOT_FOUND",
            "Revocation snapshot not found",
            404,
        );
    };
    snapshot_response(
        &req,
        snapshot.snapshot_json,
        &snapshot.etag,
        "public, max-age=86400, immutable",
    )
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
    let Some(trust_row) = store::current_trust_snapshot(&db).await? else {
        return invalid("ISSUER_UNKNOWN");
    };
    let Ok(trust): std::result::Result<TrustSnapshot, _> =
        serde_json::from_str(&trust_row.snapshot_json)
    else {
        return invalid("ISSUER_UNKNOWN");
    };
    let Some(root_public_key) = ctx
        .env
        .secret("OFFLINE_ROOT_PUBLIC_KEY")
        .ok()
        .and_then(|value| mochios_developer_ca_trust::decode_public_key(&value.to_string()).ok())
    else {
        return invalid("ISSUER_UNKNOWN");
    };
    if trust.verify(&root_public_key, at as u64).is_err() {
        return invalid("ISSUER_UNKNOWN");
    }
    let Some(signed_issuer) = trust
        .content
        .issuers
        .iter()
        .find(|issuer| issuer.issuer_key_id == row.issuer_key_id)
    else {
        return invalid("ISSUER_UNKNOWN");
    };
    if signed_issuer.status == IssuerStatus::Revoked {
        return invalid("ISSUER_REVOKED");
    }
    if !matches!(
        signed_issuer.status,
        IssuerStatus::Active | IssuerStatus::Retired
    ) || !signed_issuer
        .allowed_key_usages
        .iter()
        .any(|usage| usage == "developer-certificate-signing")
        || parsed.not_before < signed_issuer.not_before
        || parsed.not_before >= signed_issuer.not_after
    {
        return invalid("ISSUER_UNKNOWN");
    }
    let Some(registry_issuer) = store::issuer(&db, &row.issuer_key_id).await? else {
        return invalid("ISSUER_UNKNOWN");
    };
    if registry_issuer.status == "revoked" {
        return invalid("ISSUER_REVOKED");
    }
    if registry_issuer.public_key != signed_issuer.public_key
        || registry_issuer.status != signed_issuer.status.as_str()
        || registry_issuer.trust_snapshot_version != trust_row.snapshot_version
    {
        return invalid("METADATA_MISMATCH");
    }
    let Ok(public_key) = mochios_developer_ca_trust::decode_public_key(&registry_issuer.public_key)
    else {
        return invalid("ISSUER_UNKNOWN");
    };
    if certificate::verify(&parsed, &public_key, at as u64).is_err() {
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

fn transition_allowed(previous: &str, next: IssuerStatus) -> bool {
    matches!(
        (previous, next),
        (
            "future",
            IssuerStatus::Future | IssuerStatus::Active | IssuerStatus::Revoked
        ) | (
            "active",
            IssuerStatus::Active | IssuerStatus::Retired | IssuerStatus::Revoked
        ) | ("retired", IssuerStatus::Retired | IssuerStatus::Revoked)
            | ("revoked", IssuerStatus::Revoked)
    )
}

async fn admin_register_trust_snapshot(
    mut req: Request,
    ctx: RouteContext<()>,
) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    if req
        .headers()
        .get("Content-Length")?
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_SNAPSHOT_BYTES)
    {
        return error("SNAPSHOT_TOO_LARGE", "Trust snapshot is too large", 413);
    }
    let bytes = req.bytes().await?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return error("SNAPSHOT_TOO_LARGE", "Trust snapshot is too large", 413);
    }
    let snapshot_json = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "SNAPSHOT_JSON_INVALID",
                "Trust snapshot must be UTF-8 JSON",
                400,
            );
        }
    };
    let snapshot: TrustSnapshot = match serde_json::from_str(&snapshot_json) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "SNAPSHOT_JSON_INVALID",
                "Trust snapshot JSON is invalid",
                400,
            );
        }
    };
    let root_public_key = match ctx
        .env
        .secret("OFFLINE_ROOT_PUBLIC_KEY")
        .ok()
        .and_then(|value| mochios_developer_ca_trust::decode_public_key(&value.to_string()).ok())
    {
        Some(value) => value,
        None => {
            return error(
                "ROOT_KEY_UNAVAILABLE",
                "Offline Root public key is unavailable",
                503,
            );
        }
    };
    let expected_root_key_id = mochios_developer_ca_trust::key_id(&root_public_key);
    if ctx.env.secret("OFFLINE_ROOT_KEY_ID")?.to_string() != expected_root_key_id
        || snapshot.content.root_key_id != expected_root_key_id
        || snapshot.verify(&root_public_key, now() as u64).is_err()
    {
        return error(
            "ROOT_SIGNATURE_INVALID",
            "Trust snapshot Root signature is invalid",
            422,
        );
    }
    let db = ctx.env.d1("DB")?;
    if let Some(current) = store::current_trust_snapshot(&db).await? {
        let current_snapshot: TrustSnapshot = serde_json::from_str(&current.snapshot_json)?;
        if mochios_developer_ca_trust::validate_trust_successor(&current_snapshot, &snapshot)
            .is_err()
        {
            return error(
                "TRUST_SNAPSHOT_SUCCESSOR_INVALID",
                "Trust snapshot rolled back or changed existing issuer authority",
                409,
            );
        }
    }
    let existing = store::issuers(&db).await?;
    for issuer in &existing {
        let Some(replacement) = snapshot
            .content
            .issuers
            .iter()
            .find(|candidate| candidate.issuer_key_id == issuer.key_id)
        else {
            return error(
                "ISSUER_OMITTED",
                "Trust snapshot omitted an existing issuer",
                409,
            );
        };
        if replacement.public_key != issuer.public_key {
            return error(
                "ISSUER_KEY_CHANGED",
                "Issuer public key cannot be replaced",
                409,
            );
        }
        if !transition_allowed(&issuer.status, replacement.status) {
            return error(
                "ISSUER_TRANSITION_INVALID",
                "Issuer status transition is invalid",
                409,
            );
        }
    }
    if !consume_admin_action(&actor, &ctx.env, "trust_snapshot.register").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    let etag = format!("{:x}", Sha256::digest(snapshot_json.as_bytes()));
    store::register_trust_snapshot(
        &db,
        &snapshot,
        &snapshot_json,
        &etag,
        &actor.account_id,
        &actor.jti,
        now(),
    )
    .await?;
    snapshot_response(
        &req,
        snapshot_json,
        &etag,
        "public, max-age=300, must-revalidate",
    )
    .map(|response| response.with_status(201))
}

fn issuer_view(issuer: IssuerRow) -> Result<serde_json::Value> {
    Ok(json!({
        "issuer_key_id": issuer.key_id,
        "public_key": issuer.public_key,
        "status": issuer.status,
        "not_before": issuer.not_before,
        "not_after": issuer.not_after,
        "allowed_key_usages": serde_json::from_str::<serde_json::Value>(&issuer.allowed_key_usages_json)?,
        "trust_snapshot_version": issuer.trust_snapshot_version,
        "activated_at": issuer.activated_at,
        "retired_at": issuer.retired_at,
        "revoked_at": issuer.revoked_at,
        "revocation_reason": issuer.revocation_reason,
    }))
}

async fn admin_list_issuers(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if require_admin(&req, &ctx.env).await?.is_none() {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    }
    let issuers = store::issuers(&ctx.env.d1("DB")?)
        .await?
        .into_iter()
        .map(issuer_view)
        .collect::<Result<Vec<_>>>()?;
    json_response(&json!({"issuers": issuers}), 200)
}

async fn admin_change_issuer_status(
    mut req: Request,
    ctx: RouteContext<()>,
    desired: IssuerStatus,
) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let key_id = param(&ctx, "issuer_key_id");
    if key_id.len() != 64 || !key_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return error("ISSUER_KEY_ID_INVALID", "Issuer key ID is invalid", 422);
    }
    let db = ctx.env.d1("DB")?;
    let Some(current) = store::current_trust_snapshot(&db).await? else {
        return error(
            "TRUST_SNAPSHOT_UNAVAILABLE",
            "No current trust snapshot",
            409,
        );
    };
    let snapshot: TrustSnapshot = serde_json::from_str(&current.snapshot_json)?;
    let signed_status = snapshot
        .content
        .issuers
        .iter()
        .find(|issuer| issuer.issuer_key_id == key_id)
        .map(|issuer| issuer.status);
    if signed_status != Some(desired) {
        return error(
            "ISSUER_SNAPSHOT_CONFLICT",
            "Issuer transition is not authorized by the current Root-signed snapshot",
            409,
        );
    }
    let reason = if desired == IssuerStatus::Revoked {
        let input: RevokeInput = req.json().await?;
        let reason = input.reason.trim().to_owned();
        if reason.is_empty() || reason.len() > 500 {
            return error(
                "REVOCATION_REASON_INVALID",
                "Revocation reason is invalid",
                422,
            );
        }
        Some(reason)
    } else {
        None
    };
    let operation = format!("issuer.{}", desired.as_str());
    if !consume_admin_action(&actor, &ctx.env, &operation).await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    let issuer = store::set_issuer_status(
        &db,
        key_id,
        desired.as_str(),
        reason.as_deref(),
        &actor.account_id,
        now(),
    )
    .await?;
    match issuer {
        Some(issuer) => json_response(&json!({"issuer": issuer_view(issuer)?}), 200),
        None => error("ISSUER_NOT_FOUND", "Issuer not found", 404),
    }
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

async fn active_certificate_signer(
    env: &Env,
    db: &D1Database,
    issued_at: u64,
) -> Result<std::result::Result<(ed25519_dalek::SigningKey, IssuerRow), SnapshotBuildError>> {
    let Some(trust_row) = store::current_trust_snapshot(db).await? else {
        return Ok(Err(SnapshotBuildError {
            code: "TRUST_SNAPSHOT_UNAVAILABLE",
            message: "No current Root-signed trust snapshot is available",
            status: 503,
        }));
    };
    let Ok(trust): std::result::Result<TrustSnapshot, _> =
        serde_json::from_str(&trust_row.snapshot_json)
    else {
        return Ok(Err(SnapshotBuildError {
            code: "TRUST_SNAPSHOT_INVALID",
            message: "The current trust snapshot is invalid",
            status: 503,
        }));
    };
    let Some(root_public_key) = env
        .secret("OFFLINE_ROOT_PUBLIC_KEY")
        .ok()
        .and_then(|value| mochios_developer_ca_trust::decode_public_key(&value.to_string()).ok())
    else {
        return Ok(Err(SnapshotBuildError {
            code: "ROOT_KEY_UNAVAILABLE",
            message: "Offline Root public key is unavailable",
            status: 503,
        }));
    };
    if trust.verify(&root_public_key, issued_at).is_err() {
        return Ok(Err(SnapshotBuildError {
            code: "TRUST_SNAPSHOT_INVALID",
            message: "The current trust snapshot is expired or has an invalid Root signature",
            status: 503,
        }));
    }
    let Some(private_key) = env.secret("INTERMEDIATE_PRIVATE_KEY").ok() else {
        return Ok(Err(SnapshotBuildError {
            code: "ISSUER_KEY_UNAVAILABLE",
            message: "The online Intermediate key is unavailable",
            status: 503,
        }));
    };
    let Ok(signing_key) = certificate::signing_key(&private_key.to_string()) else {
        return Ok(Err(SnapshotBuildError {
            code: "ISSUER_KEY_INVALID",
            message: "The online Intermediate key is invalid",
            status: 503,
        }));
    };
    let key_id = certificate::issuer_key_id(&signing_key.verifying_key());
    let Some(signed_issuer) = trust
        .content
        .issuers
        .iter()
        .find(|issuer| issuer.issuer_key_id == key_id)
    else {
        return Ok(Err(SnapshotBuildError {
            code: "ISSUER_NOT_TRUSTED",
            message: "The online Intermediate is absent from the current trust snapshot",
            status: 503,
        }));
    };
    if signed_issuer.status != IssuerStatus::Active
        || !signed_issuer
            .allowed_key_usages
            .iter()
            .any(|usage| usage == "developer-certificate-signing")
        || issued_at < signed_issuer.not_before
        || issued_at >= signed_issuer.not_after
    {
        return Ok(Err(SnapshotBuildError {
            code: "ISSUER_NOT_AUTHORIZED",
            message: "The online Intermediate is not active for certificate issuance",
            status: 503,
        }));
    }
    let Some(registry_issuer) = store::issuer(db, &key_id).await? else {
        return Ok(Err(SnapshotBuildError {
            code: "ISSUER_NOT_REGISTERED",
            message: "The online Intermediate is absent from the issuer registry",
            status: 503,
        }));
    };
    if registry_issuer.public_key != signed_issuer.public_key
        || registry_issuer.status != "active"
        || registry_issuer.not_before != signed_issuer.not_before as i64
        || registry_issuer.not_after != signed_issuer.not_after as i64
        || registry_issuer.trust_snapshot_version != trust_row.snapshot_version
    {
        return Ok(Err(SnapshotBuildError {
            code: "ISSUER_REGISTRY_MISMATCH",
            message: "The issuer registry does not match the current trust snapshot",
            status: 503,
        }));
    }
    Ok(Ok((signing_key, registry_issuer)))
}

struct GeneratedRevocationSnapshot {
    snapshot: SignedRevocationSnapshot,
    json: String,
    etag: String,
}

struct SnapshotBuildError {
    code: &'static str,
    message: &'static str,
    status: u16,
}

fn snapshot_build_error(
    code: &'static str,
    message: &'static str,
    status: u16,
) -> std::result::Result<GeneratedRevocationSnapshot, SnapshotBuildError> {
    Err(SnapshotBuildError {
        code,
        message,
        status,
    })
}

async fn build_revocation_snapshot(
    env: &Env,
    db: &D1Database,
    additional: Option<SnapshotRevocation>,
    generated_at: u64,
) -> Result<std::result::Result<GeneratedRevocationSnapshot, SnapshotBuildError>> {
    let Some(trust_row) = store::current_trust_snapshot(db).await? else {
        return Ok(snapshot_build_error(
            "TRUST_SNAPSHOT_UNAVAILABLE",
            "No current Root-signed trust snapshot is available",
            503,
        ));
    };
    let Ok(trust): std::result::Result<TrustSnapshot, _> =
        serde_json::from_str(&trust_row.snapshot_json)
    else {
        return Ok(snapshot_build_error(
            "TRUST_SNAPSHOT_INVALID",
            "The current trust snapshot is invalid",
            503,
        ));
    };
    let Some(root_public_key) = env
        .secret("OFFLINE_ROOT_PUBLIC_KEY")
        .ok()
        .and_then(|value| mochios_developer_ca_trust::decode_public_key(&value.to_string()).ok())
    else {
        return Ok(snapshot_build_error(
            "ROOT_KEY_UNAVAILABLE",
            "Offline Root public key is unavailable",
            503,
        ));
    };
    if trust.verify(&root_public_key, generated_at).is_err() {
        return Ok(snapshot_build_error(
            "TRUST_SNAPSHOT_INVALID",
            "The current trust snapshot is expired or has an invalid Root signature",
            503,
        ));
    }
    let Some(private_key) = env.secret("INTERMEDIATE_PRIVATE_KEY").ok() else {
        return Ok(snapshot_build_error(
            "ISSUER_KEY_UNAVAILABLE",
            "The online Intermediate key is unavailable",
            503,
        ));
    };
    let Ok(signing_key) = certificate::signing_key(&private_key.to_string()) else {
        return Ok(snapshot_build_error(
            "ISSUER_KEY_INVALID",
            "The online Intermediate key is invalid",
            503,
        ));
    };
    let issuer_key_id = certificate::issuer_key_id(&signing_key.verifying_key());
    let Some(signed_issuer) = trust
        .content
        .issuers
        .iter()
        .find(|issuer| issuer.issuer_key_id == issuer_key_id)
    else {
        return Ok(snapshot_build_error(
            "ISSUER_NOT_TRUSTED",
            "The online Intermediate is absent from the current trust snapshot",
            503,
        ));
    };
    if !matches!(
        signed_issuer.status,
        IssuerStatus::Active | IssuerStatus::Retired
    ) || !signed_issuer
        .allowed_key_usages
        .iter()
        .any(|usage| usage == "revocation-signing")
        || generated_at < signed_issuer.not_before
        || generated_at >= signed_issuer.not_after
    {
        return Ok(snapshot_build_error(
            "ISSUER_NOT_AUTHORIZED",
            "The online Intermediate is not authorized for revocation signing",
            503,
        ));
    }
    let Some(registry_issuer) = store::issuer(db, &issuer_key_id).await? else {
        return Ok(snapshot_build_error(
            "ISSUER_NOT_REGISTERED",
            "The online Intermediate is absent from the issuer registry",
            503,
        ));
    };
    if registry_issuer.public_key != signed_issuer.public_key
        || registry_issuer.status != signed_issuer.status.as_str()
        || registry_issuer.trust_snapshot_version != trust_row.snapshot_version
    {
        return Ok(snapshot_build_error(
            "ISSUER_REGISTRY_MISMATCH",
            "The issuer registry does not match the current trust snapshot",
            503,
        ));
    }

    let current = store::current_revocation_snapshot(db).await?;
    let version = current
        .as_ref()
        .map_or(1, |snapshot| snapshot.snapshot_version.saturating_add(1));
    let generated_at = current.as_ref().map_or(generated_at, |snapshot| {
        generated_at.max(snapshot.generated_at as u64)
    });
    let mut revocations = Vec::new();
    for row in store::revocations(db).await? {
        let Some(reason_code) = RevocationReasonCode::parse(&row.reason_code) else {
            return Ok(snapshot_build_error(
                "REVOCATION_DATA_INVALID",
                "A stored revocation has an invalid public reason code",
                503,
            ));
        };
        revocations.push(SnapshotRevocation {
            certificate_serial: row.serial_number,
            revoked_at: row.revoked_at as u64,
            reason_code,
        });
    }
    if let Some(additional) = additional {
        if revocations
            .iter()
            .any(|item| item.certificate_serial == additional.certificate_serial)
        {
            return Ok(snapshot_build_error(
                "REVOCATION_CONFLICT",
                "The certificate already has a revocation record",
                409,
            ));
        }
        revocations.push(additional);
    }
    revocations.sort_by(|left, right| left.certificate_serial.cmp(&right.certificate_serial));
    let snapshot = match SignedRevocationSnapshot::issue(
        UnsignedRevocationSnapshot {
            format_version: REVOCATION_FORMAT_VERSION,
            snapshot_version: version as u64,
            generated_at,
            expires_at: generated_at.saturating_add(60 * 60),
            issuer_key_id,
            revocations,
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
        },
        &signing_key,
    ) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Ok(snapshot_build_error(
                "REVOCATION_SNAPSHOT_INVALID",
                "The cumulative revocation snapshot could not be generated",
                503,
            ));
        }
    };
    if let Some(current) = current {
        let Ok(previous): std::result::Result<SignedRevocationSnapshot, _> =
            serde_json::from_str(&current.snapshot_json)
        else {
            return Ok(snapshot_build_error(
                "REVOCATION_SNAPSHOT_INVALID",
                "The current revocation snapshot is invalid",
                503,
            ));
        };
        if mochios_developer_ca_trust::validate_revocation_successor(&previous, &snapshot).is_err()
        {
            return Ok(snapshot_build_error(
                "REVOCATION_SNAPSHOT_ROLLBACK",
                "The cumulative revocation snapshot failed anti-rollback validation",
                503,
            ));
        }
    }
    let json = serde_json::to_string(&snapshot)?;
    if json.len() > MAX_SNAPSHOT_BYTES {
        return Ok(snapshot_build_error(
            "REVOCATION_SNAPSHOT_TOO_LARGE",
            "The revocation snapshot exceeds the service limit",
            503,
        ));
    }
    let etag = format!("{:x}", Sha256::digest(json.as_bytes()));
    Ok(Ok(GeneratedRevocationSnapshot {
        snapshot,
        json,
        etag,
    }))
}

async fn admin_rebuild_revocation_snapshot(
    req: Request,
    ctx: RouteContext<()>,
) -> Result<Response> {
    let Some(actor) = require_admin(&req, &ctx.env).await? else {
        return error("ADMIN_AUTH_REQUIRED", "Admin authentication required", 401);
    };
    let generated_at = now();
    let db = ctx.env.d1("DB")?;
    let generated =
        match build_revocation_snapshot(&ctx.env, &db, None, generated_at as u64).await? {
            Ok(value) => value,
            Err(value) => return error(value.code, value.message, value.status),
        };
    if !consume_admin_action(&actor, &ctx.env, "revocation_snapshot.rebuild").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    store::save_revocation_snapshot(
        &db,
        store::RevocationSnapshotRecord {
            version: generated.snapshot.content.snapshot_version as i64,
            generated_at: generated.snapshot.content.generated_at as i64,
            expires_at: generated.snapshot.content.expires_at as i64,
            issuer_key_id: &generated.snapshot.content.issuer_key_id,
            snapshot_json: &generated.json,
            etag: &generated.etag,
        },
        &actor.account_id,
        generated_at,
    )
    .await?;
    snapshot_response(
        &req,
        generated.json,
        &generated.etag,
        "public, max-age=60, must-revalidate",
    )
    .map(|response| response.with_status(201))
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
    let generated = match build_revocation_snapshot(
        &ctx.env,
        &db,
        Some(SnapshotRevocation {
            certificate_serial: certificate.serial_number.clone(),
            revoked_at: revoked_at as u64,
            reason_code,
        }),
        revoked_at as u64,
    )
    .await?
    {
        Ok(value) => value,
        Err(value) => return error(value.code, value.message, value.status),
    };
    if !consume_admin_action(&actor, &ctx.env, "certificate.revoke").await? {
        return error("ADMIN_TOKEN_REPLAYED", "Admin token was already used", 409);
    }
    match store::revoke_certificate(
        &db,
        certificate_id,
        &actor.account_id,
        input.reason.trim(),
        reason_code.as_str(),
        store::RevocationSnapshotRecord {
            version: generated.snapshot.content.snapshot_version as i64,
            generated_at: generated.snapshot.content.generated_at as i64,
            expires_at: generated.snapshot.content.expires_at as i64,
            issuer_key_id: &generated.snapshot.content.issuer_key_id,
            snapshot_json: &generated.json,
            etag: &generated.etag,
        },
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
            "/v1/developers/:developer_id/certificates",
            issue_certificate,
        )
        .get_async(
            "/v1/developers/:developer_id/certificates",
            list_certificates,
        )
        .get_async("/v1/certificates/:certificate_id", get_certificate)
        .get_async("/v1/trust-store", trust_store)
        .get_async("/v1/trust-store/:snapshot_version", trust_store_version)
        .get_async("/v1/revocations", revocations)
        .get_async("/v1/revocations/:snapshot_version", revocations_version)
        .get_async(
            "/v1/certificates/:certificate_id/status",
            certificate_status,
        )
        .get_async("/v1/admin/review-queue", admin_review_queue)
        .post_async("/v1/admin/trust-snapshots", admin_register_trust_snapshot)
        .get_async("/v1/admin/issuers", admin_list_issuers)
        .post_async(
            "/v1/admin/revocation-snapshots/rebuild",
            admin_rebuild_revocation_snapshot,
        )
        .post_async("/v1/admin/issuers/:issuer_key_id/activate", |req, ctx| {
            admin_change_issuer_status(req, ctx, IssuerStatus::Active)
        })
        .post_async("/v1/admin/issuers/:issuer_key_id/retire", |req, ctx| {
            admin_change_issuer_status(req, ctx, IssuerStatus::Retired)
        })
        .post_async("/v1/admin/issuers/:issuer_key_id/revoke", |req, ctx| {
            admin_change_issuer_status(req, ctx, IssuerStatus::Revoked)
        })
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
    use super::etag_matches;

    #[test]
    fn snapshot_etag_accepts_cloudflare_weak_and_list_validators() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(etag_matches("\"other\", W/\"abc\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(!etag_matches("W/\"other\"", "\"abc\""));
    }

    #[test]
    fn schema_enforces_ownership_and_unique_serials() {
        let schema = include_str!("../migrations/0001_developer_ca.sql");
        assert!(schema.contains("prevent_last_owner_removal"));
        assert!(schema.contains("serial_number TEXT NOT NULL UNIQUE"));
        assert!(schema.contains("developer_id TEXT NOT NULL REFERENCES developers(id)"));
        assert!(schema.contains("audit_logs_no_update"));

        let trust_schema = include_str!("../migrations/0002_trust_issuers_policy.sql");
        assert!(trust_schema.contains("idx_issuers_single_active"));
        assert!(trust_schema.contains("signed trust snapshots are append-only"));
        assert!(trust_schema.contains("signed revocation snapshots are append-only"));
        assert!(trust_schema.contains("issuer public key is immutable"));
        assert!(trust_schema.contains("authentication_replay_cache"));
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
    fn certificate_issuance_is_self_service_and_admin_can_only_revoke() {
        let source = include_str!("lib.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or_default();
        let store = include_str!("store.rs");
        assert!(production.contains("/v1/developers/:developer_id/certificates"));
        assert!(production.contains(".get_async(\"/v1/admin/review-queue\", admin_review_queue)"));
        assert!(production.contains("require_admin(&req, &ctx.env)"));
        assert!(production.contains("active_certificates(&db)"));
        assert!(production.contains("/v1/admin/certificates/:certificate_id/revoke"));
        assert!(!production.contains("/v1/admin/certificate-requests"));
        assert!(!production.contains("admin_developer_policy"));
        assert!(store.contains("member.role IN ('owner', 'admin', 'developer')"));
        assert!(store.contains("'certificate.issued'"));
    }
}
