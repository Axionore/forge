//! Agent enrollment and key distribution logic.

use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::PgPool;
use std::sync::Arc;

use thiserror::Error;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// One-time enrollment token issued by an operator or during node provisioning.
    pub enrollment_token: String,

    /// The agent's long-term Ed25519 public key (32 bytes).
    pub agent_public_key: Vec<u8>,

    /// Hostname of the node (for human identification).
    pub hostname: Option<String>,

    /// Optional cloud provider attestation data (AWS, GCP, Azure, etc.).
    #[serde(default)]
    pub cloud_attestation: Option<CloudAttestation>,

    /// Optional TPM attestation quote / event log (for TPM-backed keys).
    #[serde(default)]
    pub tpm_attestation: Option<TpmAttestation>,

    /// Agent's WireGuard public key (if it wants to participate in the mesh).
    #[serde(default)]
    pub wireguard_public_key: Option<String>,

    /// Tier 3-2: The agent's age recipient ("age1...") for secret envelope encryption.
    /// Public only. Stored so control plane can encrypt secrets the agent can decrypt.
    #[serde(default)]
    pub age_recipient: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAttestation {
    pub provider: String, // "aws" | "gcp" | "azure" | "hetzner" | ...
    pub document: String, // base64 or JSON document
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestation {
    pub quote: Vec<u8>,
    pub event_log: Option<Vec<u8>>,
    pub ak_public: Vec<u8>, // Attestation Key public
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub agent_id: Uuid,
    /// Control plane's Ed25519 public key (so the agent can verify signed jobs).
    pub control_plane_public_key: Vec<u8>,
    /// Long-lived token the agent should use for future WebSocket connections.
    pub agent_token: String,
    /// Initial WireGuard configuration for this agent (if mesh is enabled).
    #[serde(default)]
    pub wireguard_config: Option<WireGuardEnrollmentConfig>,
    /// Any additional credentials or configuration.
    #[serde(default)]
    pub metadata: serde_json::Value,

    // Auto-issued mTLS client certificate for the xDS ADS server (true zero-config mTLS).
    // The agent (and its Envoy sidecars) use this to authenticate to the control plane's xDS port.
    #[serde(default)]
    pub xds_client_cert_pem: Option<String>,
    #[serde(default)]
    pub xds_client_key_pem: Option<String>,
    #[serde(default)]
    pub xds_ca_cert_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardEnrollmentConfig {
    pub interface_name: String,
    pub private_key: Option<String>, // Only sent if control plane generated it (less common)
    pub public_key: String,
    pub address: String,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("invalid or already used enrollment token")]
    InvalidToken,
    // Returned once hardware/binary attestation verification is enforced at enrollment.
    #[allow(dead_code)]
    #[error("attestation verification failed: {0}")]
    AttestationFailed(String),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

pub struct EnrollmentService {
    pool: PgPool,
    /// The ONE control-plane Ed25519 signing key. Shared (same `Arc`) with `AppState`
    /// so the verifying key handed to agents at enrollment matches the key that signs
    /// their jobs. Loaded once at startup from a secret (env or persisted file) — see
    /// `crate::load_or_create_signing_key`. We only ever expose the verifying key here.
    control_plane_signing_key: Arc<SigningKey>,
}

impl EnrollmentService {
    pub fn new(pool: PgPool, control_plane_signing_key: Arc<SigningKey>) -> Self {
        Self {
            pool,
            control_plane_signing_key,
        }
    }

    pub async fn enroll(
        &self,
        req: EnrollmentRequest,
    ) -> Result<EnrollmentResponse, EnrollmentError> {
        // 1. Validate + consume enrollment token (atomic, supports multi-use + revocation)
        let token_hash = sha2::Sha256::digest(req.enrollment_token.as_bytes()).to_vec();
        let now = chrono::Utc::now();

        // Increment uses_count if under limit, not revoked/expired/fully used.
        // We set used_at when the token becomes fully consumed after this increment.
        let updated = sqlx::query(
            r#"
            UPDATE enrollment_tokens
            SET 
                uses_count = uses_count + 1,
                used_at = CASE 
                    WHEN (uses_count + 1) >= max_uses AND max_uses > 0 THEN NOW() 
                    ELSE used_at 
                END
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > $2)
              AND (max_uses = 0 OR uses_count < max_uses)
            RETURNING description, uses_count, max_uses
            "#,
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| EnrollmentError::Internal(e.into()))?;

        if updated.is_none() {
            return Err(EnrollmentError::InvalidToken);
        }

        // 2. Attestation verification (extensible)
        if let Some(cloud) = &req.cloud_attestation {
            self.verify_cloud_attestation(cloud).await?;
        }
        if let Some(tpm) = &req.tpm_attestation {
            self.verify_tpm_attestation(tpm, &req.agent_public_key)
                .await?;
        }

        // 3. Issue the agent's long-lived WS auth credential.
        // High-entropy CSPRNG token (256-bit, URL-safe base64). Only its SHA-256 is
        // ever persisted; the raw value is returned to the agent exactly once below.
        let agent_id = Uuid::now_v7();
        let agent_token = generate_secure_token(32);
        let agent_token_hash = sha2::Sha256::digest(agent_token.as_bytes()).to_vec();

        sqlx::query(
            "INSERT INTO agents (id, hostname, public_key, age_recipient, agent_token_hash, enrolled_at) VALUES ($1, $2, $3, $4, $5, NOW())"
        )
        .bind(agent_id)
        .bind(&req.hostname)
        .bind(&req.agent_public_key)
        .bind(&req.age_recipient)
        .bind(&agent_token_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| EnrollmentError::Internal(e.into()))?;

        // 4. Store WireGuard public key if provided (for mesh)
        if let Some(wg_pub) = &req.wireguard_public_key {
            sqlx::query(
                "INSERT INTO wireguard_peers (agent_id, public_key, allowed_ips) VALUES ($1, $2, ARRAY['10.42.0.0/16'])"
            )
            .bind(agent_id)
            .bind(wg_pub)
            .execute(&self.pool)
            .await
            .map_err(|e| EnrollmentError::Internal(e.into()))?;
        }

        // 6. Build WireGuard config response if applicable
        let wireguard_config = if req.wireguard_public_key.is_some() {
            Some(WireGuardEnrollmentConfig {
                interface_name: "wg0".to_string(),
                private_key: None, // Agent generates its own in best practice
                public_key: req.wireguard_public_key.unwrap(),
                address: format!("10.42.0.{}/32", (agent_id.as_u128() % 250) + 2),
                listen_port: 51820,
                peers: vec![], // Will be populated by later mesh sync
            })
        } else {
            None
        };

        // 7. xDS client cert fields are part of the public response contract.
        // Actual issuance (using the XdsMtlsAuthority created at startup) is performed in the
        // enroll_agent handler so that the EnrollmentService (lib) does not need visibility into
        // the xds module (declared only in the bin main.rs). This is the complete wiring.
        Ok(EnrollmentResponse {
            agent_id,
            control_plane_public_key: self
                .control_plane_signing_key
                .verifying_key()
                .as_bytes()
                .to_vec(),
            agent_token,
            wireguard_config,
            metadata: serde_json::json!({ "message": "Enrollment successful" }),
            xds_client_cert_pem: None,
            xds_client_key_pem: None,
            xds_ca_cert_pem: None,
        })
    }

    // --- Attestation verification (to be implemented with real libraries) ---

    async fn verify_cloud_attestation(
        &self,
        att: &CloudAttestation,
    ) -> Result<(), EnrollmentError> {
        info!(provider = %att.provider, "Cloud attestation received — verification not yet implemented with real SDKs");
        // TODO: Integrate AWS SDK, GCP, Azure, Hetzner for document validation + signature.
        Ok(())
    }

    async fn verify_tpm_attestation(
        &self,
        _tpm: &TpmAttestation,
        _agent_public_key: &[u8],
    ) -> Result<(), EnrollmentError> {
        info!("TPM attestation received — verification not yet implemented (tss-esapi)");
        // TODO: Use tss-esapi to validate quote against expected PCRs.
        Ok(())
    }

    // --- Real Token Issuance for Operators ---

    /// Creates a new one-time or multi-use enrollment token.
    /// The raw secret is returned ONLY ONCE — operator must copy it immediately.
    pub async fn create_enrollment_token(
        &self,
        description: Option<String>,
        expires_in_days: Option<i32>,
        max_uses: Option<i32>,
    ) -> Result<CreatedToken, EnrollmentError> {
        let raw_token = generate_secure_token(32);
        let token_hash = sha2::Sha256::digest(raw_token.as_bytes()).to_vec();

        let expires_at = expires_in_days
            .filter(|d| *d > 0)
            .map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));

        let max_uses = max_uses.unwrap_or(1).clamp(1, 10_000);

        sqlx::query!(
            r#"
            INSERT INTO enrollment_tokens (token_hash, description, expires_at, max_uses, uses_count)
            VALUES ($1, $2, $3, $4, 0)
            "#,
            token_hash,
            description,
            expires_at,
            max_uses
        )
        .execute(&self.pool)
        .await
        .map_err(|e| EnrollmentError::Internal(e.into()))?;

        Ok(CreatedToken {
            raw_token,
            description,
            expires_at,
            max_uses,
        })
    }

    /// Revokes an enrollment token (prevents any future use). Idempotent.
    pub async fn revoke_enrollment_token(
        &self,
        token_hash_prefix: &str,
    ) -> Result<(), EnrollmentError> {
        // We match on hex prefix for operator UX (they only ever see prefixes in UI)
        let prefix = token_hash_prefix.trim().to_lowercase();
        if prefix.len() < 4 {
            return Err(EnrollmentError::InvalidToken);
        }

        sqlx::query!(
            r#"
            UPDATE enrollment_tokens
            SET revoked_at = NOW()
            WHERE encode(token_hash, 'hex') LIKE $1 || '%'
              AND revoked_at IS NULL
            "#,
            prefix
        )
        .execute(&self.pool)
        .await
        .map_err(|e| EnrollmentError::Internal(e.into()))?;

        Ok(())
    }

    pub async fn list_enrollment_tokens(&self) -> Result<Vec<TokenSummary>, EnrollmentError> {
        let rows = sqlx::query!(
            r#"
            SELECT 
                encode(token_hash, 'hex') as token_hash_hex,
                description,
                created_at,
                expires_at,
                used_at,
                max_uses,
                uses_count,
                revoked_at
            FROM enrollment_tokens
            ORDER BY created_at DESC
            LIMIT 200
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| EnrollmentError::Internal(e.into()))?;

        let now = chrono::Utc::now();

        Ok(rows
            .into_iter()
            .map(|r| {
                let status = if r.revoked_at.is_some() {
                    "revoked".to_string()
                } else if r.used_at.is_some() || (r.max_uses > 0 && r.uses_count >= r.max_uses) {
                    "used".to_string()
                } else if r.expires_at.is_some_and(|e| e < now) {
                    "expired".to_string()
                } else {
                    "active".to_string()
                };

                TokenSummary {
                    token_hash_prefix: r
                        .token_hash_hex
                        .unwrap_or_default()
                        .chars()
                        .take(8)
                        .collect(),
                    description: r.description,
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                    used_at: r.used_at,
                    revoked_at: r.revoked_at,
                    max_uses: r.max_uses,
                    uses_count: r.uses_count,
                    status,
                }
            })
            .collect())
    }
}

#[derive(Debug)]
pub struct CreatedToken {
    pub raw_token: String,
    pub description: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_uses: i32,
}

#[derive(Debug, Serialize)]
pub struct TokenSummary {
    pub token_hash_prefix: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_uses: i32,
    pub uses_count: i32,
    pub status: String,
}

fn generate_secure_token(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod enrollment_tests {
    //! Enrollment security (OWASP A07/A04 + A08/A04). These prove:
    //! - the agent token is high-entropy CSPRNG (not `agent-<id>`), only its SHA-256
    //!   is persisted, and the returned raw token authenticates against that hash
    //!   (the enroll → WS-auth round-trip);
    //! - the verifying key handed to the agent matches the ONE live signing key, so a
    //!   job signed by that key verifies against the enrollment-returned public key.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use sqlx::PgPool;
    use std::sync::Arc;

    fn req_for(pubkey: &[u8], token: &str) -> EnrollmentRequest {
        EnrollmentRequest {
            enrollment_token: token.to_string(),
            agent_public_key: pubkey.to_vec(),
            hostname: Some("node-1".into()),
            cloud_attestation: None,
            tpm_attestation: None,
            wireguard_public_key: None,
            age_recipient: None,
        }
    }

    #[sqlx::test]
    async fn token_is_random_hashed_and_authenticates(pool: PgPool) {
        let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
        let svc = EnrollmentService::new(pool.clone(), signing_key.clone());

        let created = svc
            .create_enrollment_token(Some("test".into()), None, Some(1))
            .await
            .unwrap();

        let agent_pubkey = SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let resp = svc
            .enroll(req_for(&agent_pubkey, &created.raw_token))
            .await
            .unwrap();

        // Not the old guessable format.
        assert!(
            !resp.agent_token.starts_with("agent-"),
            "token must not be the predictable agent-<id> form"
        );
        assert!(resp.agent_token.len() >= 32, "token must be high-entropy");

        // Only the SHA-256 of the token is persisted, and it matches the raw value
        // returned — this is exactly what agent_ws WS auth checks.
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT agent_token_hash FROM agents WHERE id = $1")
                .bind(resp.agent_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let expected = sha2::Sha256::digest(resp.agent_token.as_bytes()).to_vec();
        assert_eq!(stored, expected, "stored hash matches SHA-256 of raw token");

        // A different token must NOT match the stored hash.
        let wrong = sha2::Sha256::digest(b"agent-guess").to_vec();
        assert_ne!(stored, wrong);
    }

    #[sqlx::test]
    async fn returned_pubkey_verifies_jobs_signed_by_live_key(pool: PgPool) {
        // The ONE signing key injected here is the same Arc AppState hands to agent_ws,
        // which signs every job. The enrollment response must expose its verifying key.
        let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
        let svc = EnrollmentService::new(pool.clone(), signing_key.clone());

        let created = svc
            .create_enrollment_token(None, None, Some(1))
            .await
            .unwrap();
        let agent_pubkey = SigningKey::generate(&mut rand::rngs::OsRng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let resp = svc
            .enroll(req_for(&agent_pubkey, &created.raw_token))
            .await
            .unwrap();

        let cp_pubkey: [u8; 32] = resp
            .control_plane_public_key
            .as_slice()
            .try_into()
            .expect("cp pubkey is 32 bytes");
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&cp_pubkey).unwrap();

        // Sign an arbitrary job payload with the live key (what agent_ws::JobSigner does).
        let payload = b"job:deploy:nginx:1";
        let sig = signing_key.sign(payload);

        verifying
            .verify(payload, &sig)
            .expect("job signed by the live key MUST verify against the enrollment pubkey");

        // Sanity: a signature from an unrelated key must NOT verify.
        let other = SigningKey::generate(&mut rand::rngs::OsRng).sign(payload);
        assert!(verifying.verify(payload, &other).is_err());
    }
}
