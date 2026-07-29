use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use mochios_certificate::{PackageScopeKind, key_id as certificate_key_id};
use mochios_developer_ca::certificate::{
    CertificateIssueInput, IssueCertificate, decode, issue, verify,
};
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, REVOCATION_FORMAT_VERSION, RevocationReasonCode,
    RevocationSnapshot, SIGNATURE_ALGORITHM, SnapshotRevocation, TRUST_FORMAT_VERSION,
    TrustSnapshot, UnsignedRevocationSnapshot, UnsignedTrustSnapshot, key_id,
};

#[test]
fn online_intermediate_mcer_and_revocation_round_trip() {
    let root = SigningKey::from_bytes(&[11; 32]);
    let issuer = SigningKey::from_bytes(&[22; 32]);
    let subject = SigningKey::from_bytes(&[33; 32]);
    let root_public_key = root.verifying_key().to_bytes();
    let issuer_public_key = issuer.verifying_key().to_bytes();
    let subject_public_key = subject.verifying_key().to_bytes();

    let trust = TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: TRUST_FORMAT_VERSION,
            snapshot_version: 1,
            generated_at: 1_000,
            expires_at: 2_000,
            root_key_id: key_id(&root_public_key),
            issuers: vec![IssuerRecord {
                issuer_key_id: key_id(&issuer_public_key),
                public_key: STANDARD.encode(issuer_public_key),
                status: IssuerStatus::Active,
                not_before: 900,
                not_after: 3_000,
                allowed_key_usages: vec![
                    "developer-certificate-signing".into(),
                    "revocation-signing".into(),
                ],
            }],
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
        },
        &root,
    )
    .expect("issue Root-signed trust snapshot");
    trust
        .verify(&root_public_key, 1_100)
        .expect("verify Root-signed trust snapshot");
    assert_eq!(trust.content.issuers.len(), 1);
    assert_eq!(trust.content.issuers[0].status, IssuerStatus::Active);
    assert_eq!(
        trust.content.issuers[0].issuer_key_id,
        key_id(&issuer_public_key)
    );

    let request = CertificateIssueInput {
        subject_public_key: STANDARD.encode(subject_public_key),
        package_id: "org.mochios.example".into(),
        capabilities: vec!["window.create".into(), "fs.read.all".into()],
    }
    .into_request()
    .expect("canonical public issuance request");
    let wire = issue(
        IssueCertificate {
            serial_number: 42,
            developer_id: "org.mochios.developer.example",
            not_before: 1_100,
            not_after: 1_900,
            request: &request,
        },
        &issuer,
    )
    .expect("issue MCER with Online Intermediate");
    let certificate = decode(&wire).expect("decode issued MCER");
    verify(&certificate, &issuer_public_key, 1_200).expect("verify issued MCER");

    assert_eq!(certificate.serial_number, 42);
    assert_eq!(
        certificate.issuer_key_id,
        certificate_key_id(&issuer_public_key)
    );
    assert_eq!(
        certificate.subject_key_id,
        certificate_key_id(&subject_public_key)
    );
    assert_eq!(certificate.subject_public_key, subject_public_key);
    assert_eq!(certificate.developer_id, "org.mochios.developer.example");
    assert_eq!(certificate.package_id_scopes.len(), 1);
    assert_eq!(
        certificate.package_id_scopes[0].kind,
        PackageScopeKind::Exact
    );
    assert_eq!(
        certificate.package_id_scopes[0].package_id,
        "org.mochios.example"
    );
    assert_eq!(
        certificate.allowed_capabilities,
        ["fs.read.all", "window.create"]
    );

    let revocations = RevocationSnapshot::issue(
        UnsignedRevocationSnapshot {
            format_version: REVOCATION_FORMAT_VERSION,
            snapshot_version: 1,
            generated_at: 1_200,
            expires_at: 1_500,
            issuer_key_id: key_id(&issuer_public_key),
            revocations: vec![SnapshotRevocation {
                certificate_serial: certificate.serial_number.to_string(),
                revoked_at: 1_200,
                reason_code: RevocationReasonCode::CertificateReplaced,
            }],
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
        },
        &issuer,
    )
    .expect("issue signed revocation snapshot");
    revocations
        .verify(&issuer_public_key, 1_300)
        .expect("verify signed revocation snapshot");
    assert_eq!(
        revocations.content.revocations[0].certificate_serial,
        certificate.serial_number.to_string()
    );
}
