use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TRUST_FORMAT_VERSION: u32 = 1;
pub const REVOCATION_FORMAT_VERSION: u32 = 1;
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const TRUST_DOMAIN: &[u8] = b"mochios-issuer-trust-snapshot-v1\0";
pub const REVOCATION_DOMAIN: &[u8] = b"mochios-revocation-snapshot-v1\0";
pub const MAX_ISSUERS: usize = 64;
pub const MAX_REVOCATIONS: usize = 100_000;
pub const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_KEY_ID_LEN: usize = 64;
pub const MAX_REASON_CODE_LEN: usize = 32;
pub const MAX_TRUST_LIFETIME_SECONDS: u64 = 180 * 24 * 60 * 60;
pub const MAX_REVOCATION_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStatus {
    Future,
    Active,
    Retired,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerRecord {
    pub issuer_key_id: String,
    pub public_key: String,
    pub status: IssuerStatus,
    pub not_before: u64,
    pub not_after: u64,
    pub allowed_key_usages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedTrustSnapshot {
    pub format_version: u32,
    pub snapshot_version: u64,
    pub generated_at: u64,
    pub expires_at: u64,
    pub root_key_id: String,
    pub issuers: Vec<IssuerRecord>,
    pub signature_algorithm: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSnapshot {
    #[serde(flatten)]
    pub content: UnsignedTrustSnapshot,
    pub root_signature: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReasonCode {
    KeyCompromise,
    DeveloperSuspended,
    CertificateReplaced,
    ScopeViolation,
    Administrative,
    Unspecified,
}

impl RevocationReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyCompromise => "key_compromise",
            Self::DeveloperSuspended => "developer_suspended",
            Self::CertificateReplaced => "certificate_replaced",
            Self::ScopeViolation => "scope_violation",
            Self::Administrative => "administrative",
            Self::Unspecified => "unspecified",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRevocation {
    pub certificate_serial: String,
    pub revoked_at: u64,
    pub reason_code: RevocationReasonCode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedRevocationSnapshot {
    pub format_version: u32,
    pub snapshot_version: u64,
    pub generated_at: u64,
    pub expires_at: u64,
    pub issuer_key_id: String,
    pub revocations: Vec<SnapshotRevocation>,
    pub signature_algorithm: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSnapshot {
    #[serde(flatten)]
    pub content: UnsignedRevocationSnapshot,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustError {
    UnsupportedFormat,
    UnsupportedSignatureAlgorithm,
    InvalidVersion,
    InvalidValidity,
    LifetimeTooLong,
    TooManyIssuers,
    TooManyRevocations,
    InvalidKeyId,
    InvalidPublicKey,
    KeyIdMismatch,
    InvalidKeyUsage,
    DuplicateIssuer,
    UnsortedIssuers,
    MultipleActiveIssuers,
    InvalidSerial,
    InvalidReasonCode,
    DuplicateRevocation,
    UnsortedRevocations,
    InvalidSignature,
    SnapshotTooLarge,
    EncodingOverflow,
}

impl core::fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid trust material: {self:?}")
    }
}

impl std::error::Error for TrustError {}

impl TrustSnapshot {
    pub fn issue(
        content: UnsignedTrustSnapshot,
        root_key: &SigningKey,
    ) -> Result<Self, TrustError> {
        validate_trust(&content)?;
        if content.root_key_id != key_id(&root_key.verifying_key().to_bytes()) {
            return Err(TrustError::KeyIdMismatch);
        }
        let message = trust_signing_message(&content)?;
        Ok(Self {
            content,
            root_signature: STANDARD.encode(root_key.sign(&message).to_bytes()),
        })
    }

    pub fn verify(&self, root_public_key: &[u8; 32], now: u64) -> Result<(), TrustError> {
        validate_trust(&self.content)?;
        if self.content.root_key_id != key_id(root_public_key) {
            return Err(TrustError::KeyIdMismatch);
        }
        if self.content.generated_at > now.saturating_add(300) || self.content.expires_at <= now {
            return Err(TrustError::InvalidValidity);
        }
        verify_signature(
            root_public_key,
            &self.root_signature,
            &trust_signing_message(&self.content)?,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TrustError> {
        trust_signing_message(&self.content)
    }
}

impl RevocationSnapshot {
    pub fn issue(
        content: UnsignedRevocationSnapshot,
        issuer_key: &SigningKey,
    ) -> Result<Self, TrustError> {
        validate_revocations(&content)?;
        if content.issuer_key_id != key_id(&issuer_key.verifying_key().to_bytes()) {
            return Err(TrustError::KeyIdMismatch);
        }
        let message = revocation_signing_message(&content)?;
        Ok(Self {
            content,
            signature: STANDARD.encode(issuer_key.sign(&message).to_bytes()),
        })
    }

    pub fn verify(&self, issuer_public_key: &[u8; 32], now: u64) -> Result<(), TrustError> {
        validate_revocations(&self.content)?;
        if self.content.issuer_key_id != key_id(issuer_public_key) {
            return Err(TrustError::KeyIdMismatch);
        }
        if self.content.generated_at > now.saturating_add(300) || self.content.expires_at <= now {
            return Err(TrustError::InvalidValidity);
        }
        verify_signature(
            issuer_public_key,
            &self.signature,
            &revocation_signing_message(&self.content)?,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TrustError> {
        revocation_signing_message(&self.content)
    }
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    hex(&Sha256::digest(public_key))
}

pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], TrustError> {
    STANDARD
        .decode(encoded)
        .map_err(|_| TrustError::InvalidPublicKey)?
        .try_into()
        .map_err(|_| TrustError::InvalidPublicKey)
}

fn validate_trust(content: &UnsignedTrustSnapshot) -> Result<(), TrustError> {
    if content.format_version != TRUST_FORMAT_VERSION {
        return Err(TrustError::UnsupportedFormat);
    }
    validate_common(
        content.snapshot_version,
        content.generated_at,
        content.expires_at,
        MAX_TRUST_LIFETIME_SECONDS,
        &content.signature_algorithm,
    )?;
    if !valid_key_id(&content.root_key_id) || content.issuers.len() > MAX_ISSUERS {
        return Err(if content.issuers.len() > MAX_ISSUERS {
            TrustError::TooManyIssuers
        } else {
            TrustError::InvalidKeyId
        });
    }
    let mut active = 0usize;
    let mut previous: Option<&str> = None;
    for issuer in &content.issuers {
        validate_issuer(issuer)?;
        if issuer.status == IssuerStatus::Active {
            active += 1;
        }
        if let Some(previous) = previous {
            if previous == issuer.issuer_key_id {
                return Err(TrustError::DuplicateIssuer);
            }
            if previous > issuer.issuer_key_id.as_str() {
                return Err(TrustError::UnsortedIssuers);
            }
        }
        previous = Some(&issuer.issuer_key_id);
    }
    if active > 1 {
        return Err(TrustError::MultipleActiveIssuers);
    }
    Ok(())
}

fn validate_issuer(issuer: &IssuerRecord) -> Result<(), TrustError> {
    if !valid_key_id(&issuer.issuer_key_id) || issuer.not_before >= issuer.not_after {
        return Err(TrustError::InvalidKeyId);
    }
    let public_key = decode_public_key(&issuer.public_key)?;
    VerifyingKey::from_bytes(&public_key).map_err(|_| TrustError::InvalidPublicKey)?;
    if key_id(&public_key) != issuer.issuer_key_id {
        return Err(TrustError::KeyIdMismatch);
    }
    if issuer.allowed_key_usages.is_empty()
        || issuer.allowed_key_usages.len() > 4
        || issuer.allowed_key_usages.iter().any(|usage| {
            !matches!(
                usage.as_str(),
                "developer-certificate-signing" | "revocation-signing"
            )
        })
        || issuer
            .allowed_key_usages
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(TrustError::InvalidKeyUsage);
    }
    Ok(())
}

fn validate_revocations(content: &UnsignedRevocationSnapshot) -> Result<(), TrustError> {
    if content.format_version != REVOCATION_FORMAT_VERSION {
        return Err(TrustError::UnsupportedFormat);
    }
    validate_common(
        content.snapshot_version,
        content.generated_at,
        content.expires_at,
        MAX_REVOCATION_LIFETIME_SECONDS,
        &content.signature_algorithm,
    )?;
    if !valid_key_id(&content.issuer_key_id) {
        return Err(TrustError::InvalidKeyId);
    }
    if content.revocations.len() > MAX_REVOCATIONS {
        return Err(TrustError::TooManyRevocations);
    }
    let mut previous: Option<&SnapshotRevocation> = None;
    for revocation in &content.revocations {
        if revocation.certificate_serial.is_empty()
            || revocation.certificate_serial.len() > 32
            || !revocation.certificate_serial.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(TrustError::InvalidSerial);
        }
        if revocation.reason_code.as_str().len() > MAX_REASON_CODE_LEN {
            return Err(TrustError::InvalidReasonCode);
        }
        if let Some(previous) = previous {
            if previous.certificate_serial == revocation.certificate_serial {
                return Err(TrustError::DuplicateRevocation);
            }
            if previous.certificate_serial > revocation.certificate_serial {
                return Err(TrustError::UnsortedRevocations);
            }
        }
        previous = Some(revocation);
    }
    Ok(())
}

fn validate_common(
    version: u64,
    generated_at: u64,
    expires_at: u64,
    max_lifetime: u64,
    algorithm: &str,
) -> Result<(), TrustError> {
    if version == 0 {
        return Err(TrustError::InvalidVersion);
    }
    if generated_at >= expires_at {
        return Err(TrustError::InvalidValidity);
    }
    if expires_at - generated_at > max_lifetime {
        return Err(TrustError::LifetimeTooLong);
    }
    if algorithm != SIGNATURE_ALGORITHM {
        return Err(TrustError::UnsupportedSignatureAlgorithm);
    }
    Ok(())
}

fn trust_signing_message(content: &UnsignedTrustSnapshot) -> Result<Vec<u8>, TrustError> {
    validate_trust(content)?;
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(TRUST_DOMAIN);
    put_u32(&mut bytes, content.format_version);
    put_u64(&mut bytes, content.snapshot_version);
    put_u64(&mut bytes, content.generated_at);
    put_u64(&mut bytes, content.expires_at);
    put_string(&mut bytes, &content.root_key_id)?;
    put_u32(&mut bytes, to_u32(content.issuers.len())?);
    for issuer in &content.issuers {
        put_string(&mut bytes, &issuer.issuer_key_id)?;
        put_string(&mut bytes, &issuer.public_key)?;
        bytes.push(match issuer.status {
            IssuerStatus::Future => 1,
            IssuerStatus::Active => 2,
            IssuerStatus::Retired => 3,
            IssuerStatus::Revoked => 4,
        });
        put_u64(&mut bytes, issuer.not_before);
        put_u64(&mut bytes, issuer.not_after);
        put_u32(&mut bytes, to_u32(issuer.allowed_key_usages.len())?);
        for usage in &issuer.allowed_key_usages {
            put_string(&mut bytes, usage)?;
        }
    }
    put_string(&mut bytes, &content.signature_algorithm)?;
    bounded(bytes)
}

fn revocation_signing_message(
    content: &UnsignedRevocationSnapshot,
) -> Result<Vec<u8>, TrustError> {
    validate_revocations(content)?;
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(REVOCATION_DOMAIN);
    put_u32(&mut bytes, content.format_version);
    put_u64(&mut bytes, content.snapshot_version);
    put_u64(&mut bytes, content.generated_at);
    put_u64(&mut bytes, content.expires_at);
    put_string(&mut bytes, &content.issuer_key_id)?;
    put_u32(&mut bytes, to_u32(content.revocations.len())?);
    for revocation in &content.revocations {
        put_string(&mut bytes, &revocation.certificate_serial)?;
        put_u64(&mut bytes, revocation.revoked_at);
        put_string(&mut bytes, revocation.reason_code.as_str())?;
    }
    put_string(&mut bytes, &content.signature_algorithm)?;
    bounded(bytes)
}

fn verify_signature(public_key: &[u8; 32], encoded: &str, message: &[u8]) -> Result<(), TrustError> {
    let verifier = VerifyingKey::from_bytes(public_key).map_err(|_| TrustError::InvalidPublicKey)?;
    let signature = STANDARD
        .decode(encoded)
        .map_err(|_| TrustError::InvalidSignature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| TrustError::InvalidSignature)?;
    verifier
        .verify_strict(message, &signature)
        .map_err(|_| TrustError::InvalidSignature)
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), TrustError> {
    put_u32(bytes, to_u32(value.len())?);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn to_u32(value: usize) -> Result<u32, TrustError> {
    u32::try_from(value).map_err(|_| TrustError::EncodingOverflow)
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, TrustError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        Err(TrustError::SnapshotTooLarge)
    } else {
        Ok(bytes)
    }
}

fn valid_key_id(value: &str) -> bool {
    value.len() == MAX_KEY_ID_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust(root: &SigningKey, issuer: &SigningKey) -> TrustSnapshot {
        TrustSnapshot::issue(
            UnsignedTrustSnapshot {
                format_version: TRUST_FORMAT_VERSION,
                snapshot_version: 1,
                generated_at: 100,
                expires_at: 200,
                root_key_id: key_id(&root.verifying_key().to_bytes()),
                issuers: vec![IssuerRecord {
                    issuer_key_id: key_id(&issuer.verifying_key().to_bytes()),
                    public_key: STANDARD.encode(issuer.verifying_key().to_bytes()),
                    status: IssuerStatus::Active,
                    not_before: 90,
                    not_after: 300,
                    allowed_key_usages: vec![
                        "developer-certificate-signing".into(),
                        "revocation-signing".into(),
                    ],
                }],
                signature_algorithm: SIGNATURE_ALGORITHM.into(),
            },
            root,
        )
        .expect("fixture trust snapshot")
    }

    #[test]
    fn trust_signature_and_canonical_encoding_are_deterministic() {
        let root = SigningKey::from_bytes(&[3; 32]);
        let issuer = SigningKey::from_bytes(&[5; 32]);
        let snapshot = trust(&root, &issuer);
        snapshot
            .verify(&root.verifying_key().to_bytes(), 150)
            .expect("valid root signature");
        assert_eq!(
            snapshot.canonical_bytes().expect("canonical bytes"),
            snapshot.canonical_bytes().expect("canonical bytes")
        );
        assert!(snapshot.canonical_bytes().expect("canonical bytes").starts_with(TRUST_DOMAIN));
    }

    #[test]
    fn trust_rejects_tampering_and_multiple_active_issuers() {
        let root = SigningKey::from_bytes(&[3; 32]);
        let issuer = SigningKey::from_bytes(&[5; 32]);
        let mut snapshot = trust(&root, &issuer);
        snapshot.content.snapshot_version = 2;
        assert_eq!(
            snapshot.verify(&root.verifying_key().to_bytes(), 150),
            Err(TrustError::InvalidSignature)
        );
        let mut content = snapshot.content;
        content.issuers.push(content.issuers[0].clone());
        content.issuers[1].issuer_key_id = "f".repeat(64);
        content.issuers[1].public_key = STANDARD.encode([9; 32]);
        assert!(validate_trust(&content).is_err());
    }

    #[test]
    fn signed_revocations_are_cumulative_canonical_material() {
        let issuer = SigningKey::from_bytes(&[5; 32]);
        let snapshot = RevocationSnapshot::issue(
            UnsignedRevocationSnapshot {
                format_version: REVOCATION_FORMAT_VERSION,
                snapshot_version: 1,
                generated_at: 100,
                expires_at: 150,
                issuer_key_id: key_id(&issuer.verifying_key().to_bytes()),
                revocations: vec![SnapshotRevocation {
                    certificate_serial: "42".into(),
                    revoked_at: 101,
                    reason_code: RevocationReasonCode::KeyCompromise,
                }],
                signature_algorithm: SIGNATURE_ALGORITHM.into(),
            },
            &issuer,
        )
        .expect("fixture revocation snapshot");
        snapshot
            .verify(&issuer.verifying_key().to_bytes(), 120)
            .expect("valid revocation signature");
        assert!(
            snapshot
                .canonical_bytes()
                .expect("canonical bytes")
                .starts_with(REVOCATION_DOMAIN)
        );
    }
}
