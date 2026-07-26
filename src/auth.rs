use serde::Deserialize;
use subtle::ConstantTimeEq;
use worker::{Fetch, Headers, Method, Request, RequestInit, Result, wasm_bindgen::JsValue};

#[derive(Debug, Deserialize)]
struct Introspection {
    active: bool,
    account_id: Option<String>,
    account_status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccountEnvelope {
    account: AccountState,
}

#[derive(Debug, Deserialize)]
struct AccountState {
    id: String,
    status: String,
}

fn constant_time_eq(expected: &str, provided: &str) -> bool {
    expected.len() == provided.len() && bool::from(expected.as_bytes().ct_eq(provided.as_bytes()))
}

fn service_headers(env: &worker::Env) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("X-Service-Token", &env.secret("SERVICE_TOKEN")?.to_string())?;
    Ok(headers)
}

pub async fn account(req: &Request, env: &worker::Env) -> Result<Option<String>> {
    let authorization = req.headers().get("Authorization")?.unwrap_or_default();
    let Some(token) = authorization
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let base = env.var("ACCOUNTS_BASE_URL")?.to_string();
    let headers = service_headers(env)?;
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(
            &serde_json::json!({"token": token}).to_string(),
        )));
    let request = Request::new_with_init(
        &format!(
            "{}/v1/internal/sessions/introspect",
            base.trim_end_matches('/')
        ),
        &init,
    )?;
    let mut response = match Fetch::Request(request).send().await {
        Ok(response) if response.status_code() == 200 => response,
        _ => return Ok(None),
    };
    let result: Introspection = match response.json().await {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };
    Ok(
        (result.active && result.account_status.as_deref() == Some("active"))
            .then_some(result.account_id)
            .flatten(),
    )
}

pub async fn account_is_active(account_id: &str, env: &worker::Env) -> Result<bool> {
    let base = env.var("ACCOUNTS_BASE_URL")?.to_string();
    let mut init = RequestInit::new();
    init.with_headers(service_headers(env)?);
    let request = Request::new_with_init(
        &format!(
            "{}/v1/internal/accounts/{account_id}",
            base.trim_end_matches('/')
        ),
        &init,
    )?;
    let mut response = match Fetch::Request(request).send().await {
        Ok(response) if response.status_code() == 200 => response,
        _ => return Ok(false),
    };
    let envelope: AccountEnvelope = match response.json().await {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(envelope.account.id == account_id && envelope.account.status == "active")
}

pub async fn admin(req: &Request, env: &worker::Env) -> Result<Option<String>> {
    let expected = env.secret("ADMIN_TOKEN")?.to_string();
    let provided = req.headers().get("X-Admin-Token")?.unwrap_or_default();
    let account_id = req.headers().get("X-Admin-Account-ID")?.unwrap_or_default();
    if expected.is_empty() || account_id.is_empty() || !constant_time_eq(&expected, &provided) {
        return Ok(None);
    }
    Ok(account_is_active(&account_id, env)
        .await?
        .then_some(account_id))
}
