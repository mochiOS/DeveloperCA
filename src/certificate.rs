use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mochios_certificate::{
    DeveloperCertificate, KEY_USAGE_PACKAGE_SIGNING, PackageIdScope, PackageScopeKind,
    SIGNATURE_LEN, is_valid_capability, key_id,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
        let scopes = parse_scopes(&self.package_id_scopes)?;
        if scopes.is_empty() {
            return Err("at least one package id scope is required".into());
        }
        let mut capabilities = self.allowed_capabilities.clone();
        if capabilities
            .iter()
            .any(|capability| !is_valid_capability(capability))
        {
            return Err("invalid capability".into());
        }
        capabilities.sort();
        if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("duplicate capability".into());
        }
        decode_public_key(&self.subject_public_key)
    }

    pub fn subject_key_id(&self) -> Result<String, String> {
        let key = self.validate()?;
        Ok(hex(&key_id(key.as_bytes())))
    }

    pub fn canonical_scopes(&self) -> Result<Vec<PackageIdScope>, String> {
        parse_scopes(&self.package_id_scopes)
    }

    pub fn canonical_capabilities(&self) -> Result<Vec<String>, String> {
        self.validate()?;
        let mut capabilities = self.allowed_capabilities.clone();
        capabilities.sort();
        Ok(capabilities)
    }

    pub fn subject_public_key_bytes(&self) -> Result<[u8; 32], String> {
        Ok(decode_public_key(&self.subject_public_key)?.to_bytes())
    }
}

pub struct IssueCertificate<'a> {
    pub serial_number: u64,
    pub developer_id: &'a str,
    pub not_before: u64,
    pub not_after: u64,
    pub request: &'a CertificateRequestInput,
}

pub fn issue(input: IssueCertificate<'_>, signing_key: &SigningKey) -> Result<Vec<u8>, String> {
    let issuer_public_key = signing_key.verifying_key().to_bytes();
    let subject_public_key = input.request.subject_public_key_bytes()?;
    let mut certificate = DeveloperCertificate {
        serial_number: input.serial_number,
        issuer_key_id: key_id(&issuer_public_key),
        developer_id: input.developer_id.into(),
        subject_key_id: key_id(&subject_public_key),
        subject_public_key,
        not_before: input.not_before,
        not_after: input.not_after,
        key_usage: KEY_USAGE_PACKAGE_SIGNING,
        package_id_scopes: input.request.canonical_scopes()?,
        allowed_capabilities: input.request.canonical_capabilities()?,
        signature: [0; SIGNATURE_LEN],
    };
    certificate.validate().map_err(|error| error.to_string())?;
    certificate.signature = signing_key
        .sign(
            &certificate
                .signing_message()
                .map_err(|error| error.to_string())?,
        )
        .to_bytes();
    let mut wire = vec![
        0;
        certificate
            .encoded_len()
            .map_err(|error| error.to_string())?
    ];
    certificate
        .encode(&mut wire)
        .map_err(|error| error.to_string())?;
    Ok(wire)
}

pub fn decode(wire: &[u8]) -> Result<DeveloperCertificate, String> {
    DeveloperCertificate::decode(wire).map_err(|error| error.to_string())
}

pub fn decode_base64(wire: &str) -> Result<DeveloperCertificate, String> {
    let bytes = STANDARD
        .decode(wire)
        .map_err(|_| "invalid certificate wire encoding".to_owned())?;
    decode(&bytes)
}

pub fn encode_base64(wire: &[u8]) -> String {
    STANDARD.encode(wire)
}

pub fn verify(
    certificate: &DeveloperCertificate,
    issuer_public_key: &[u8; 32],
    unix_time: u64,
) -> Result<(), String> {
    let package_id = certificate
        .package_id_scopes
        .first()
        .map(|scope| scope.package_id.as_str())
        .ok_or_else(|| "certificate has no package scope".to_owned())?;
    certificate
        .verify(issuer_public_key, unix_time, package_id)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub fn view(certificate: &DeveloperCertificate) -> Value {
    json!({
        "content": {
            "format_version": mochios_certificate::FORMAT_VERSION,
            "serial_number": certificate.serial_number.to_string(),
            "issuer_key_id": hex(&certificate.issuer_key_id),
            "developer_id": certificate.developer_id,
            "subject_key_id": hex(&certificate.subject_key_id),
            "subject_public_key": STANDARD.encode(certificate.subject_public_key),
            "not_before": certificate.not_before,
            "not_after": certificate.not_after,
            "key_usage": ["manifest-signing"],
            "package_id_scopes": certificate.package_id_scopes.iter().map(scope_string).collect::<Vec<_>>(),
            "allowed_capabilities": certificate.allowed_capabilities,
            "signature_algorithm": SIGNATURE_ALGORITHM,
        },
        "signature": STANDARD.encode(certificate.signature),
        "wire_format": "MCER",
    })
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

pub fn issuer_key_id(key: &VerifyingKey) -> String {
    hex(&key_id(key.as_bytes()))
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

fn parse_scopes(scopes: &[String]) -> Result<Vec<PackageIdScope>, String> {
    let mut parsed = scopes
        .iter()
        .map(|scope| {
            if let Some(prefix) = scope.strip_suffix(".*") {
                Ok(PackageIdScope::prefix(prefix))
            } else {
                Ok(PackageIdScope::exact(scope))
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    parsed.sort();
    if parsed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate package id scope".into());
    }
    let subject_key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
    let probe = DeveloperCertificate {
        serial_number: 1,
        issuer_key_id: [1; 32],
        developer_id: "developer".into(),
        subject_key_id: key_id(&subject_key),
        subject_public_key: subject_key,
        not_before: 1,
        not_after: 2,
        key_usage: KEY_USAGE_PACKAGE_SIGNING,
        package_id_scopes: parsed.clone(),
        allowed_capabilities: vec![],
        signature: [0; SIGNATURE_LEN],
    };
    probe.validate().map_err(|error| error.to_string())?;
    Ok(parsed)
}

fn scope_string(scope: &PackageIdScope) -> String {
    match scope.kind {
        PackageScopeKind::Exact => scope.package_id.clone(),
        PackageScopeKind::Prefix => format!("{}.*", scope.package_id),
    }
}

pub fn hex(bytes: &[u8]) -> String {
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

    fn request() -> CertificateRequestInput {
        let signing = SigningKey::from_bytes(&[7; 32]);
        CertificateRequestInput {
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
            subject_public_key: encoded_public_key(&signing.verifying_key()),
            package_id_scopes: vec!["dev.mochi.*".into()],
            allowed_capabilities: vec!["network.client".into()],
        }
    }

    #[test]
    fn shared_wire_round_trips_and_verifies() {
        let issuer = SigningKey::from_bytes(&[3; 32]);
        let wire = issue(
            IssueCertificate {
                serial_number: 7,
                developer_id: "018f0000-0000-7000-8000-000000000001",
                not_before: 100,
                not_after: 200,
                request: &request(),
            },
            &issuer,
        )
        .unwrap();
        let certificate = decode(&wire).unwrap();
        verify(&certificate, &issuer.verifying_key().to_bytes(), 150).unwrap();
        assert_eq!(certificate.allowed_capabilities, ["network.client"]);
    }

    #[test]
    fn rejects_duplicate_and_invalid_authority_requests() {
        let mut input = request();
        input.allowed_capabilities.push("network.client".into());
        assert!(input.validate().is_err());
        let mut input = request();
        input.package_id_scopes = vec!["dev.mochi.*".into(), "dev.mochi.*".into()];
        assert!(input.validate().is_err());
    }
}
