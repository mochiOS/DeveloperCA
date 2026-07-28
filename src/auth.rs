use base64::{Engine, engine::general_purpose::STANDARD};
use mochios_developer_ca_auth_token::{Claims, TOKEN_PREFIX, verify};
use serde::Deserialize;
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

fn active_introspection_account(result: Introspection) -> Option<String> {
    (result.active && result.account_status.as_deref() == Some("active"))
        .then_some(result.account_id)
        .flatten()
}

#[derive(Debug, Clone)]
pub struct AdminActor {
    pub account_id: String,
    pub jti: String,
    pub expires_at: i64,
}

fn service_headers(env: &worker::Env) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("X-Service-Token", &env.secret("SERVICE_TOKEN")?.to_string())?;
    Ok(headers)
}

pub async fn account(req: &Request, env: &worker::Env) -> Result<Option<String>> {
    let authorization = req.headers().get("Authorization")?.unwrap_or_default();
    let token = authorization
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if token.is_some_and(|value| value.starts_with(&format!("{TOKEN_PREFIX}."))) {
        return Ok(delegation(req, env, "developer-ca", "delegated_account")
            .await?
            .map(|claims| claims.sub));
    }
    if token.is_none() {
        return Ok(None);
    }
    let token = token.unwrap_or_default();
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
    Ok(active_introspection_account(result))
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

async fn delegation(
    req: &Request,
    env: &worker::Env,
    audience: &str,
    role: &str,
) -> Result<Option<Claims>> {
    let authorization = req.headers().get("Authorization")?.unwrap_or_default();
    let Some(token) = authorization.strip_prefix("Bearer ").map(str::trim) else {
        return Ok(None);
    };
    let bytes = STANDARD
        .decode(env.secret("CONSOLE_TOKEN_PUBLIC_KEY")?.to_string())
        .map_err(|_| worker::Error::RustError("invalid Console token public key".into()))?;
    let public_key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| worker::Error::RustError("invalid Console token public key".into()))?;
    let now = worker::Date::now().as_millis() / 1000;
    let claims = match verify(token, &public_key, now) {
        Ok(claims) if claims_match(&claims, audience, role) => claims,
        _ => return Ok(None),
    };
    Ok(account_is_active(&claims.sub, env).await?.then_some(claims))
}

fn claims_match(claims: &Claims, audience: &str, role: &str) -> bool {
    claims.iss == "console.mochios.org"
        && claims.aud == audience
        && claims.role == role
        && claims.act.as_deref() == Some("mochios-console")
}

pub async fn admin(req: &Request, env: &worker::Env) -> Result<Option<AdminActor>> {
    Ok(
        delegation(req, env, "developer-ca-admin", "developer_ca_reviewer")
            .await?
            .map(|claims| AdminActor {
                account_id: claims.sub,
                jti: claims.jti,
                expires_at: claims.exp as i64,
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        Claims {
            iss: "console.mochios.org".into(),
            sub: "018f0000-0000-7000-8000-000000000001".into(),
            aud: "developer-ca-admin".into(),
            iat: 100,
            exp: 160,
            jti: "fixture".into(),
            role: "developer_ca_reviewer".into(),
            act: Some("mochios-console".into()),
        }
    }

    #[test]
    fn admin_claims_require_fixed_issuer_audience_role_and_actor() {
        let valid = claims();
        assert!(claims_match(
            &valid,
            "developer-ca-admin",
            "developer_ca_reviewer"
        ));
        for invalid in [
            Claims {
                iss: "attacker.example".into(),
                ..valid.clone()
            },
            Claims {
                aud: "developer-ca".into(),
                ..valid.clone()
            },
            Claims {
                role: "delegated_account".into(),
                ..valid.clone()
            },
            Claims {
                act: Some("other-service".into()),
                ..valid.clone()
            },
        ] {
            assert!(!claims_match(
                &invalid,
                "developer-ca-admin",
                "developer_ca_reviewer"
            ));
        }
    }

    #[test]
    fn session_introspection_requires_an_active_account() {
        assert_eq!(
            active_introspection_account(Introspection {
                active: true,
                account_id: Some("account-1".into()),
                account_status: Some("active".into()),
            }),
            Some("account-1".into())
        );
        for result in [
            Introspection {
                active: false,
                account_id: Some("account-1".into()),
                account_status: Some("active".into()),
            },
            Introspection {
                active: true,
                account_id: Some("account-1".into()),
                account_status: Some("suspended".into()),
            },
            Introspection {
                active: true,
                account_id: None,
                account_status: Some("active".into()),
            },
        ] {
            assert_eq!(active_introspection_account(result), None);
        }
    }
}
