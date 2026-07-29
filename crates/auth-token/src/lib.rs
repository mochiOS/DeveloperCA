use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const TOKEN_PREFIX: &str = "mca1";
pub const DOMAIN_SEPARATOR: &[u8] = b"mochios-developer-ca-delegation-v1\0";
pub const MAX_TOKEN_BYTES: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 2048;
pub const MAX_TOKEN_LIFETIME_SECONDS: u64 = 900;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenError {
    TooLarge,
    Format,
    InvalidSignature,
    InvalidClaims,
    NotYetValid,
    Expired,
    LifetimeTooLong,
    Serialization,
}

impl core::fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid delegation token: {self:?}")
    }
}

impl std::error::Error for TokenError {}

pub fn issue(claims: &Claims, signing_key: &SigningKey) -> Result<String, TokenError> {
    validate_claims(claims, claims.iat)?;
    let payload = serde_json::to_vec(claims).map_err(|_| TokenError::Serialization)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(TokenError::TooLarge);
    }
    let message = signing_message(&payload)?;
    let signature = signing_key.sign(&message).to_bytes();
    let token = format!(
        "{TOKEN_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(signature)
    );
    if token.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::TooLarge);
    }
    Ok(token)
}

pub fn verify(token: &str, public_key: &[u8; 32], now: u64) -> Result<Claims, TokenError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::TooLarge);
    }
    let mut parts = token.split('.');
    if parts.next() != Some(TOKEN_PREFIX) {
        return Err(TokenError::Format);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(TokenError::Format)?)
        .map_err(|_| TokenError::Format)?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(TokenError::Format)?)
        .map_err(|_| TokenError::Format)?;
    if parts.next().is_some() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(TokenError::Format);
    }
    let verifier =
        VerifyingKey::from_bytes(public_key).map_err(|_| TokenError::InvalidSignature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| TokenError::InvalidSignature)?;
    verifier
        .verify_strict(&signing_message(&payload)?, &signature)
        .map_err(|_| TokenError::InvalidSignature)?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| TokenError::InvalidClaims)?;
    validate_claims(&claims, now)?;
    Ok(claims)
}

fn signing_message(payload: &[u8]) -> Result<Vec<u8>, TokenError> {
    let capacity = DOMAIN_SEPARATOR
        .len()
        .checked_add(4)
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(TokenError::TooLarge)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| TokenError::TooLarge)?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(DOMAIN_SEPARATOR);
    message.extend_from_slice(&payload_len.to_le_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn validate_claims(claims: &Claims, now: u64) -> Result<(), TokenError> {
    if !valid_text(&claims.iss, 255)
        || !valid_account_id(&claims.sub)
        || !valid_text(&claims.aud, 64)
        || !valid_text(&claims.jti, 128)
        || !valid_text(&claims.role, 64)
        || claims
            .act
            .as_deref()
            .is_some_and(|value| !valid_text(value, 128))
        || claims
            .client_id
            .as_deref()
            .is_some_and(|value| !valid_text(value, 64))
        || claims
            .scope
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 512)
        || claims
            .session_id
            .as_deref()
            .is_some_and(|value| !valid_text(value, 128))
        || claims.iat >= claims.exp
    {
        return Err(TokenError::InvalidClaims);
    }
    if claims.exp - claims.iat > MAX_TOKEN_LIFETIME_SECONDS {
        return Err(TokenError::LifetimeTooLong);
    }
    if claims.iat > now.saturating_add(30) {
        return Err(TokenError::NotYetValid);
    }
    if claims.exp <= now {
        return Err(TokenError::Expired);
    }
    Ok(())
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn valid_account_id(value: &str) -> bool {
    value.len() == 36
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
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
            jti: "test-jti-1".into(),
            role: "developer_ca_reviewer".into(),
            act: Some("mochios-console".into()),
            client_id: None,
            scope: None,
            session_id: None,
        }
    }

    #[test]
    fn signed_token_round_trips_and_rejects_tampering() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let token = issue(&claims(), &key).expect("issue fixture token");
        assert_eq!(
            verify(&token, &key.verifying_key().to_bytes(), 120).expect("verify fixture token"),
            claims()
        );
        let mut tampered = token.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ASCII token");
        assert_eq!(
            verify(&tampered, &key.verifying_key().to_bytes(), 120),
            Err(TokenError::InvalidSignature)
        );
    }

    #[test]
    fn token_rejects_expiration_and_oversized_lifetime() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let token = issue(&claims(), &key).expect("issue fixture token");
        assert_eq!(
            verify(&token, &key.verifying_key().to_bytes(), 160),
            Err(TokenError::Expired)
        );
        let mut invalid = claims();
        invalid.exp = 1000;
        assert_eq!(issue(&invalid, &key), Err(TokenError::LifetimeTooLong));
    }

    #[test]
    fn token_rejects_future_time_invalid_subject_and_unknown_claims() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let token = issue(&claims(), &key).expect("issue fixture token");
        assert_eq!(
            verify(&token, &key.verifying_key().to_bytes(), 60),
            Err(TokenError::NotYetValid)
        );
        let mut invalid = claims();
        invalid.sub = "client-supplied-actor".into();
        assert_eq!(issue(&invalid, &key), Err(TokenError::InvalidClaims));

        let payload = serde_json::json!({
            "iss": "console.mochios.org",
            "sub": "018f0000-0000-7000-8000-000000000001",
            "aud": "developer-ca-admin",
            "iat": 100,
            "exp": 160,
            "jti": "fixture",
            "role": "developer_ca_reviewer",
            "act": "mochios-console",
            "unknown": true
        });
        let payload = serde_json::to_vec(&payload).expect("serialize fixture");
        let signature = key.sign(&signing_message(&payload).expect("message"));
        let token = format!(
            "{TOKEN_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        assert_eq!(
            verify(&token, &key.verifying_key().to_bytes(), 120),
            Err(TokenError::InvalidClaims)
        );
    }
}
