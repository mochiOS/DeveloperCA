use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FORMAT_VERSION: u32 = 1;
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRequestInput {
    pub signature_algorithm: String,
    pub subject_public_key: String,
    pub package_id_scopes: Vec<String>,
    pub allowed_capabilities: Vec<String>,
}

impl CertificateRequestInput {
    pub fn validate(&self) -> Result<VerifyingKey, String> {
        if self.signature_algorithm != SIGNATURE_ALGORITHM {
            return Err("unsupported signature algorithm".into());
        }
        if self.package_id_scopes.is_empty()
            || self
                .package_id_scopes
                .iter()
                .any(|scope| !valid_package_scope(scope))
        {
            return Err("invalid package id scope".into());
        }
        if self
            .allowed_capabilities
            .iter()
            .any(|value| value.is_empty() || value.len() > 128)
        {
            return Err("invalid capability".into());
        }
        decode_public_key(&self.subject_public_key)
    }

    pub fn subject_key_id(&self) -> Result<String, String> {
        let key = self.validate()?;
        Ok(format!("sha256:{}", hex(&Sha256::digest(key.as_bytes()))))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedCertificate {
    pub format_version: u32,
    pub serial_number: String,
    pub issuer_key_id: String,
    pub developer_id: String,
    pub subject_key_id: String,
    pub subject_public_key: String,
    pub not_before: i64,
    pub not_after: i64,
    pub key_usage: Vec<String>,
    pub package_id_scopes: Vec<String>,
    pub allowed_capabilities: Vec<String>,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeveloperCertificate {
    #[serde(flatten)]
    pub content: UnsignedCertificate,
    pub signature: String,
}

impl DeveloperCertificate {
    pub fn issue(content: UnsignedCertificate, signing_key: &SigningKey) -> Result<Self, String> {
        validate_content(&content, content.not_before)?;
        let payload =
            serde_json::to_vec(&content).map_err(|_| "certificate serialization failed")?;
        let signature = STANDARD.encode(signing_key.sign(&payload).to_bytes());
        Ok(Self { content, signature })
    }

    pub fn verify(&self, issuer: &VerifyingKey, now: i64) -> Result<(), String> {
        validate_content(&self.content, now)?;
        decode_public_key(&self.content.subject_public_key)?;
        let bytes = STANDARD
            .decode(&self.signature)
            .map_err(|_| "invalid signature encoding")?;
        let signature = Signature::from_slice(&bytes).map_err(|_| "invalid signature")?;
        let payload =
            serde_json::to_vec(&self.content).map_err(|_| "certificate serialization failed")?;
        issuer
            .verify(&payload, &signature)
            .map_err(|_| "invalid signature".into())
    }

    pub fn authorize(
        &self,
        package_id: &str,
        requested_capabilities: &[String],
    ) -> Result<(), String> {
        if !self
            .content
            .package_id_scopes
            .iter()
            .any(|scope| scope_matches(scope, package_id))
        {
            return Err("package id is outside certificate scope".into());
        }
        if requested_capabilities
            .iter()
            .any(|capability| !self.content.allowed_capabilities.contains(capability))
        {
            return Err("capability is not allowed by certificate".into());
        }
        Ok(())
    }
}

pub fn signing_key(encoded: &str) -> Result<SigningKey, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid intermediate private key encoding")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "intermediate private key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn encoded_public_key(key: &VerifyingKey) -> String {
    STANDARD.encode(key.as_bytes())
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid public key encoding")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes")?;
    VerifyingKey::from_bytes(&key).map_err(|_| "invalid Ed25519 public key".into())
}

fn validate_content(content: &UnsignedCertificate, now: i64) -> Result<(), String> {
    if content.format_version != FORMAT_VERSION {
        return Err("unsupported certificate format".into());
    }
    if content.signature_algorithm != SIGNATURE_ALGORITHM {
        return Err("unsupported signature algorithm".into());
    }
    if content.not_after <= content.not_before
        || now < content.not_before
        || now >= content.not_after
    {
        return Err("certificate is not currently valid".into());
    }
    if content.key_usage != ["manifest-signing"] {
        return Err("unsupported key usage".into());
    }
    if content.package_id_scopes.is_empty()
        || content
            .package_id_scopes
            .iter()
            .any(|scope| !valid_package_scope(scope))
    {
        return Err("invalid package id scope".into());
    }
    if content
        .allowed_capabilities
        .iter()
        .any(|value| value.is_empty() || value.len() > 128)
    {
        return Err("invalid capability".into());
    }
    if content.serial_number.is_empty()
        || content.issuer_key_id.is_empty()
        || content.developer_id.is_empty()
        || content.subject_key_id.is_empty()
    {
        return Err("required certificate identity is missing".into());
    }
    Ok(())
}

fn valid_package_scope(scope: &str) -> bool {
    let parts: Vec<_> = scope.split('.').collect();
    !scope.is_empty()
        && scope.len() <= 255
        && parts.iter().enumerate().all(|(index, part)| {
            !part.is_empty()
                && (*part == "*" && index == parts.len() - 1
                    || part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        })
}

fn scope_matches(scope: &str, package_id: &str) -> bool {
    if let Some(prefix) = scope.strip_suffix(".*") {
        package_id.starts_with(&format!("{prefix}."))
    } else {
        scope == package_id
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CertificateRequestInput {
        let signing = SigningKey::from_bytes(&[7; 32]);
        CertificateRequestInput {
            signature_algorithm: "ed25519".into(),
            subject_public_key: encoded_public_key(&signing.verifying_key()),
            package_id_scopes: vec!["dev.mochi.*".into()],
            allowed_capabilities: vec!["network.client".into()],
        }
    }

    #[test]
    fn rejects_invalid_public_key() {
        let mut input = request();
        input.subject_public_key = "not-base64".into();
        assert!(input.validate().is_err());
    }

    #[test]
    fn certificate_is_bound_to_developer_and_detects_tampering() {
        let issuer = SigningKey::from_bytes(&[3; 32]);
        let input = request();
        let cert = DeveloperCertificate::issue(
            UnsignedCertificate {
                format_version: FORMAT_VERSION,
                serial_number: "01".into(),
                issuer_key_id: "intermediate-1".into(),
                developer_id: "018f0000-0000-7000-8000-000000000001".into(),
                subject_key_id: input.subject_key_id().unwrap(),
                subject_public_key: input.subject_public_key,
                not_before: 100,
                not_after: 200,
                key_usage: vec!["manifest-signing".into()],
                package_id_scopes: input.package_id_scopes,
                allowed_capabilities: input.allowed_capabilities,
                signature_algorithm: SIGNATURE_ALGORITHM.into(),
            },
            &issuer,
        )
        .unwrap();
        assert!(cert.verify(&issuer.verifying_key(), 150).is_ok());
        let mut tampered = cert;
        tampered.content.developer_id = "other".into();
        assert!(tampered.verify(&issuer.verifying_key(), 150).is_err());
    }

    #[test]
    fn expired_certificate_fails_closed() {
        let issuer = SigningKey::from_bytes(&[3; 32]);
        let input = request();
        let cert = DeveloperCertificate::issue(
            UnsignedCertificate {
                format_version: FORMAT_VERSION,
                serial_number: "02".into(),
                issuer_key_id: "i".into(),
                developer_id: "developer".into(),
                subject_key_id: input.subject_key_id().unwrap(),
                subject_public_key: input.subject_public_key,
                not_before: 100,
                not_after: 200,
                key_usage: vec!["manifest-signing".into()],
                package_id_scopes: input.package_id_scopes,
                allowed_capabilities: vec![],
                signature_algorithm: SIGNATURE_ALGORITHM.into(),
            },
            &issuer,
        )
        .unwrap();
        assert!(cert.verify(&issuer.verifying_key(), 200).is_err());
    }

    #[test]
    fn package_scope_and_capabilities_fail_closed() {
        let issuer = SigningKey::from_bytes(&[3; 32]);
        let input = request();
        let cert = DeveloperCertificate::issue(
            UnsignedCertificate {
                format_version: FORMAT_VERSION,
                serial_number: "03".into(),
                issuer_key_id: "i".into(),
                developer_id: "developer".into(),
                subject_key_id: input.subject_key_id().unwrap(),
                subject_public_key: input.subject_public_key,
                not_before: 100,
                not_after: 200,
                key_usage: vec!["manifest-signing".into()],
                package_id_scopes: input.package_id_scopes,
                allowed_capabilities: input.allowed_capabilities,
                signature_algorithm: SIGNATURE_ALGORITHM.into(),
            },
            &issuer,
        )
        .unwrap();
        assert!(
            cert.authorize("dev.mochi.paint", &["network.client".into()])
                .is_ok()
        );
        assert!(cert.authorize("other.paint", &[]).is_err());
        assert!(
            cert.authorize("dev.mochi.paint", &["system.admin".into()])
                .is_err()
        );
    }
}
