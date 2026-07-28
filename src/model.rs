use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Developer {
    pub id: String,
    pub certificate_developer_id: String,
    pub developer_type: String,
    pub display_name: String,
    pub status: String,
    pub verification_status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub developer_id: String,
    pub account_id: String,
    pub role: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationRequest {
    pub id: String,
    pub account_id: String,
    pub requested_display_name: String,
    pub requested_developer_type: String,
    pub reason: String,
    pub status: String,
    pub reviewed_by_account_id: Option<String>,
    pub reviewed_at: Option<i64>,
    pub rejection_reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDeveloper {
    pub developer_type: String,
    pub display_name: String,
    pub creation_request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMember {
    pub account_id: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMember {
    pub role: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCreationRequest {
    pub requested_display_name: String,
    pub requested_developer_type: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInput {
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationInput {
    pub verification_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeInput {
    pub reason: String,
    pub reason_code: Option<RevocationReasonCode>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
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
    pub fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRow {
    pub id: String,
    pub certificate_request_id: String,
    pub developer_id: String,
    pub serial_number: String,
    pub issuer_key_id: String,
    pub subject_key_id: String,
    pub certificate_json: String,
    pub not_before: i64,
    pub not_after: i64,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub id: String,
    pub certificate_id: String,
    pub serial_number: String,
    pub reason: String,
    pub reason_code: String,
    pub revoked_by_account_id: String,
    pub revoked_at: i64,
}
