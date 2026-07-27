use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use mochios_developer_ca_trust::{
    IssuerRecord, IssuerStatus, SIGNATURE_ALGORITHM, TrustSnapshot, UnsignedTrustSnapshot, key_id,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "DeveloperCA Offline Root operation tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    Issuer {
        #[command(subcommand)]
        command: IssuerCommand,
    },
    TrustSnapshot {
        #[command(subcommand)]
        command: TrustSnapshotCommand,
    },
    RevocationSnapshot {
        #[command(subcommand)]
        command: RevocationSnapshotCommand,
    },
    AdminToken {
        #[command(subcommand)]
        command: AdminTokenCommand,
    },
}

#[derive(Subcommand)]
enum RootCommand {
    Create {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_record: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum IssuerStatusArg {
    Future,
    Active,
}

#[derive(Subcommand)]
enum IssuerCommand {
    Create {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        not_before: u64,
        #[arg(long)]
        not_after: u64,
        #[arg(long, value_enum, default_value = "future")]
        status: IssuerStatusArg,
        #[arg(
            long = "usage",
            required = true,
            value_parser = ["developer-certificate-signing", "revocation-signing"]
        )]
        usages: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TrustSnapshotCommand {
    Issue {
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        issuers: PathBuf,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        generated_at: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        #[arg(long)]
        snapshot: PathBuf,
    },
    Verify {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        root_public_record: PathBuf,
        #[arg(long)]
        at: u64,
    },
}

#[derive(Subcommand)]
enum RevocationSnapshotCommand {
    Inspect {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        issuer_public_record: Option<PathBuf>,
        #[arg(long, requires = "issuer_public_record")]
        at: Option<u64>,
    },
}

#[derive(Subcommand)]
enum AdminTokenCommand {
    Issue {
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        issued_at: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRecord {
    key_id: String,
    public_key: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Root { command } => match command {
            RootCommand::Create {
                private_key,
                public_record,
            } => create_key(&private_key, Some(&public_record), None)?,
        },
        Command::Issuer { command } => match command {
            IssuerCommand::Create {
                private_key,
                record,
                not_before,
                not_after,
                status,
                mut usages,
            } => {
                if not_before >= not_after {
                    bail!("not-before must precede not-after");
                }
                usages.sort();
                usages.dedup();
                let status = match status {
                    IssuerStatusArg::Future => IssuerStatus::Future,
                    IssuerStatusArg::Active => IssuerStatus::Active,
                };
                create_key(
                    &private_key,
                    None,
                    Some((&record, status, not_before, not_after, usages)),
                )?;
            }
        },
        Command::TrustSnapshot { command } => match command {
            TrustSnapshotCommand::Issue {
                root_key,
                issuers,
                version,
                generated_at,
                expires_at,
                output,
            } => issue_trust_snapshot(
                &root_key,
                &issuers,
                version,
                generated_at,
                expires_at,
                &output,
            )?,
            TrustSnapshotCommand::Inspect { snapshot } => {
                let snapshot: TrustSnapshot = read_json(&snapshot)?;
                snapshot
                    .canonical_bytes()
                    .context("invalid trust snapshot")?;
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            }
            TrustSnapshotCommand::Verify {
                snapshot,
                root_public_record,
                at,
            } => {
                let snapshot: TrustSnapshot = read_json(&snapshot)?;
                let root = read_public_key(&root_public_record)?;
                snapshot
                    .verify(&root, at)
                    .context("trust snapshot verification failed")?;
                println!(
                    "verified trust snapshot version {}",
                    snapshot.content.snapshot_version
                );
            }
        },
        Command::RevocationSnapshot { command } => match command {
            RevocationSnapshotCommand::Inspect {
                snapshot,
                issuer_public_record,
                at,
            } => {
                let snapshot: mochios_developer_ca_trust::RevocationSnapshot =
                    read_json(&snapshot)?;
                snapshot
                    .canonical_bytes()
                    .context("invalid revocation snapshot")?;
                if let Some(record) = issuer_public_record {
                    snapshot
                        .verify(&read_public_key(&record)?, at.unwrap_or_default())
                        .context("revocation snapshot verification failed")?;
                }
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            }
        },
        Command::AdminToken { command } => match command {
            AdminTokenCommand::Issue {
                signing_key,
                subject,
                issued_at,
                expires_at,
                output,
            } => issue_admin_token(&signing_key, &subject, issued_at, expires_at, &output)?,
        },
    }
    Ok(())
}

fn issue_admin_token(
    signing_key_path: &Path,
    subject: &str,
    issued_at: u64,
    expires_at: u64,
    output: &Path,
) -> Result<()> {
    let signing_key = read_signing_key(signing_key_path)?;
    let mut jti_bytes = [0_u8; 16];
    getrandom::fill(&mut jti_bytes)
        .map_err(|error| anyhow::anyhow!("secure random generation failed: {error}"))?;
    let jti = jti_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let token = mochios_developer_ca_auth_token::issue(
        &mochios_developer_ca_auth_token::Claims {
            iss: "console.mochios.org".into(),
            sub: subject.into(),
            aud: "developer-ca-admin".into(),
            iat: issued_at,
            exp: expires_at,
            jti,
            role: "developer_ca_reviewer".into(),
            act: Some("mochios-console".into()),
        },
        &signing_key,
    )
    .context("admin token issuance failed")?;
    write_secret(output, token.as_bytes())?;
    println!("admin token written to {}", output.display());
    Ok(())
}

fn create_key(
    private_path: &Path,
    public_path: Option<&Path>,
    issuer: Option<(&Path, IssuerStatus, u64, u64, Vec<String>)>,
) -> Result<()> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|error| anyhow::anyhow!("secure random generation failed: {error}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    write_secret(private_path, STANDARD.encode(seed.as_ref()).as_bytes())?;
    let public_key = signing_key.verifying_key().to_bytes();
    let key_id = key_id(&public_key);
    let public_key = STANDARD.encode(public_key);
    if let Some(path) = public_path {
        write_json(
            path,
            &PublicKeyRecord {
                key_id: key_id.clone(),
                public_key: public_key.clone(),
            },
        )?;
    }
    if let Some((path, status, not_before, not_after, allowed_key_usages)) = issuer {
        write_json(
            path,
            &IssuerRecord {
                issuer_key_id: key_id.clone(),
                public_key,
                status,
                not_before,
                not_after,
                allowed_key_usages,
            },
        )?;
    }
    println!("created key {}", key_id);
    println!("private key written to {}", private_path.display());
    Ok(())
}

fn issue_trust_snapshot(
    root_key_path: &Path,
    issuer_path: &Path,
    version: u64,
    generated_at: u64,
    expires_at: u64,
    output: &Path,
) -> Result<()> {
    let root_key = read_signing_key(root_key_path)?;
    let mut issuers: Vec<IssuerRecord> = read_json(issuer_path)?;
    issuers.sort_by(|left, right| left.issuer_key_id.cmp(&right.issuer_key_id));
    let snapshot = TrustSnapshot::issue(
        UnsignedTrustSnapshot {
            format_version: mochios_developer_ca_trust::TRUST_FORMAT_VERSION,
            snapshot_version: version,
            generated_at,
            expires_at,
            root_key_id: key_id(&root_key.verifying_key().to_bytes()),
            issuers,
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
        },
        &root_key,
    )
    .context("trust snapshot issuance failed")?;
    write_json(output, &snapshot)?;
    println!("issued trust snapshot version {}", version);
    println!("snapshot written to {}", output.display());
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let encoded = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("failed to read private key {}", path.display()))?,
    );
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded.trim())
            .context("private key is not valid base64")?,
    );
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must contain a 32-byte seed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn read_public_key(path: &Path) -> Result<[u8; 32]> {
    let record: PublicKeyRecord = read_json(path)?;
    let key = mochios_developer_ca_trust::decode_public_key(&record.public_key)
        .context("invalid public key")?;
    if key_id(&key) != record.key_id {
        bail!("public key ID does not match public key");
    }
    Ok(key)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new(path, &bytes, false)
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut content = Zeroizing::new(bytes.to_vec());
    content.push(b'\n');
    write_new(path, &content, true)
}

fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    #[cfg(not(unix))]
    let _ = secret;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_keys_and_issues_a_verifiable_snapshot_without_overwriting_secrets() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root_key = directory.path().join("root.seed");
        let root_public = directory.path().join("root-public.json");
        create_key(&root_key, Some(&root_public), None).expect("create root");
        assert!(create_key(&root_key, Some(&root_public), None).is_err());

        let issuer_key = directory.path().join("issuer.seed");
        let issuer_record = directory.path().join("issuer.json");
        create_key(
            &issuer_key,
            None,
            Some((
                &issuer_record,
                IssuerStatus::Active,
                90,
                300,
                vec![
                    "developer-certificate-signing".into(),
                    "revocation-signing".into(),
                ],
            )),
        )
        .expect("create issuer");
        let issuers = directory.path().join("issuers.json");
        write_json(
            &issuers,
            &vec![read_json::<IssuerRecord>(&issuer_record).expect("issuer record")],
        )
        .expect("write issuer list");
        let output = directory.path().join("trust.json");
        issue_trust_snapshot(&root_key, &issuers, 1, 100, 200, &output).expect("issue snapshot");
        let snapshot: TrustSnapshot = read_json(&output).expect("read snapshot");
        snapshot
            .verify(
                &read_public_key(&root_public).expect("root public key"),
                150,
            )
            .expect("verify snapshot");
    }
}
