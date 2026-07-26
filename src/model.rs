use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Developer {
    pub id: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequestRow {
    pub id: String,
    pub developer_id: String,
    pub requested_by_account_id: String,
    pub signature_algorithm: String,
    pub subject_public_key: String,
    pub subject_key_id: String,
    pub package_id_scopes_json: String,
    pub allowed_capabilities_json: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
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
    pub revoked_by_account_id: String,
    pub revoked_at: i64,
}
