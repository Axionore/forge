//! Cloud provisioning service (Phase A.2).
//!
//! Turns the cloud-agnostic [`forge_providers::CloudProvider`] trait (Phase A.1) into a
//! control-plane capability: instantiate a provider from stored, age-encrypted credentials,
//! drive it to create/list/delete infrastructure, and record every created resource in the
//! `provisioned_resources` table (migration 0022) so the control plane can manage and clean
//! up what it built.
//!
//! Design:
//! - A [`ProviderRegistry`] maps a provider name to a constructor. Hetzner is fully wired
//!   (token decrypted via the shared age path); the other registered providers are scaffolds
//!   whose methods return [`ProviderError::NotImplemented`], surfaced to callers as a clean
//!   501. Unknown names return [`ProvisionError::UnknownProvider`].
//! - The [`ProviderFactory`] seam lets tests inject a mock `CloudProvider` (so the persistence
//!   + partial-failure recording logic is exercised without touching a real cloud API).
//! - Tokens are decrypted only in memory, only at the moment of use, and never logged.

use std::collections::BTreeMap;
use std::sync::Arc;

use forge_providers::{
    Capabilities, CloudProvider, Direction, DnsRecord, DnsRecordType, FirewallRule, LbService,
    Protocol, ProviderError, ServerId, ServerSpec,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// Provider names the control plane knows about. The first is fully implemented; the
/// rest are scaffolds that advertise no capabilities and return `NotImplemented`.
pub const KNOWN_PROVIDERS: [&str; 5] = ["hetzner", "aws", "gcp", "azure", "digitalocean"];

/// A resource kind tracked in `provisioned_resources`. Matches the migration CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Server,
    Firewall,
    Network,
    Volume,
    LoadBalancer,
    Ip,
    DnsRecord,
}

impl ResourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Firewall => "firewall",
            Self::Network => "network",
            Self::Volume => "volume",
            Self::LoadBalancer => "load_balancer",
            Self::Ip => "ip",
            Self::DnsRecord => "dns_record",
        }
    }
}

/// A row of `provisioned_resources` as returned to API callers. No secret material.
#[derive(Debug, Clone, Serialize)]
pub struct ProvisionedResource {
    pub id: Uuid,
    pub provider: String,
    pub kind: String,
    pub external_id: Option<String>,
    pub name: Option<String>,
    pub region: Option<String>,
    pub status: String,
    pub metadata: serde_json::Value,
    pub application_id: Option<Uuid>,
    pub created_by_principal_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Errors from the provisioning service. Maps to HTTP in `main.rs`. Never carries a token.
#[derive(Debug, Error)]
pub enum ProvisionError {
    #[error("unknown provider")]
    UnknownProvider,
    /// The provider is known but no usable credential is configured/decryptable.
    #[error("provider credential unavailable: {0}")]
    CredentialUnavailable(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("resource not found")]
    NotFound,
    /// A unique-constraint violation on the `provisioned_resources` table (e.g. duplicate
    /// `(provider, external_id)` from a concurrent create). Maps to 409 Conflict.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A provider call failed. Carries the typed provider error for HTTP mapping.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

/// Builds a concrete [`CloudProvider`] for a provider name on demand. The production
/// implementation decrypts stored credentials; tests inject a mock.
#[async_trait::async_trait]
pub trait ProviderFactory: Send + Sync {
    /// Return the capabilities advertised for `provider` without needing a credential
    /// (used by `GET /admin/providers` so the UI can grey out unsupported actions).
    fn capabilities(&self, provider: &str) -> Option<Capabilities>;

    /// Construct a live provider for `provider`, resolving + decrypting credentials.
    /// `credential_id` selects a specific saved credential; `None` uses the provider default.
    async fn build(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
    ) -> Result<Arc<dyn CloudProvider>, ProvisionError>;
}

/// Production factory: knows how to decrypt each provider's stored credentials and build
/// the matching `CloudProvider`. Hetzner is fully wired; the scaffold providers need no
/// credential and report no capabilities.
pub struct ProviderRegistry {
    pool: PgPool,
    /// Control-plane age secret (armored x25519 identity) used to decrypt provider tokens.
    cp_age_secret: Option<Arc<String>>,
}

impl ProviderRegistry {
    #[must_use]
    pub fn new(pool: PgPool, cp_age_secret: Option<Arc<String>>) -> Self {
        Self {
            pool,
            cp_age_secret,
        }
    }

    /// Decrypt one Hetzner credential by id (or the most recent enabled one if `None`).
    /// Returns the plaintext token. Never logs it.
    async fn hetzner_token(&self, credential_id: Option<Uuid>) -> Result<String, ProvisionError> {
        let cp_secret = self.cp_age_secret.as_ref().ok_or_else(|| {
            ProvisionError::CredentialUnavailable("control-plane age secret not configured".into())
        })?;

        let encrypted: Option<serde_json::Value> = if let Some(id) = credential_id {
            sqlx::query_scalar!(
                "SELECT encrypted_token FROM hetzner_credentials WHERE id = $1 AND enabled = true",
                id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ProvisionError::Internal(e.into()))?
        } else {
            sqlx::query_scalar!(
                "SELECT encrypted_token FROM hetzner_credentials WHERE enabled = true ORDER BY created_at DESC LIMIT 1"
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ProvisionError::Internal(e.into()))?
        };

        let blob = encrypted.ok_or_else(|| {
            ProvisionError::CredentialUnavailable("no enabled Hetzner credential found".into())
        })?;

        decrypt_cp_credential(&blob, cp_secret).map_err(|_| {
            ProvisionError::CredentialUnavailable("credential decryption failed".into())
        })
    }
}

#[async_trait::async_trait]
impl ProviderFactory for ProviderRegistry {
    fn capabilities(&self, provider: &str) -> Option<Capabilities> {
        match provider {
            "hetzner" => Some(
                forge_provider_hetzner::HetznerProvider::from_config(
                    // A capabilities() call never touches the network or the token; an empty
                    // token is fine here and is never used to authenticate.
                    forge_provider_hetzner::HetznerConfig {
                        api_token: String::new(),
                        dns_token: None,
                    },
                )
                .capabilities(),
            ),
            "aws" => Some(forge_provider_aws::AwsProvider.capabilities()),
            "gcp" => Some(forge_provider_gcp::GcpProvider.capabilities()),
            "azure" => Some(forge_provider_azure::AzureProvider.capabilities()),
            "digitalocean" => {
                Some(forge_provider_digitalocean::DigitalOceanProvider.capabilities())
            }
            _ => None,
        }
    }

    async fn build(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
    ) -> Result<Arc<dyn CloudProvider>, ProvisionError> {
        match provider {
            "hetzner" => {
                let token = self.hetzner_token(credential_id).await?;
                Ok(Arc::new(
                    forge_provider_hetzner::HetznerProvider::from_config(
                        forge_provider_hetzner::HetznerConfig {
                            api_token: token,
                            dns_token: None,
                        },
                    ),
                ))
            }
            "aws" => Ok(Arc::new(forge_provider_aws::AwsProvider)),
            "gcp" => Ok(Arc::new(forge_provider_gcp::GcpProvider)),
            "azure" => Ok(Arc::new(forge_provider_azure::AzureProvider)),
            "digitalocean" => Ok(Arc::new(forge_provider_digitalocean::DigitalOceanProvider)),
            _ => Err(ProvisionError::UnknownProvider),
        }
    }
}

/// Decrypt a control-plane credential envelope (age, armored) with the CP identity.
/// Coarse error on purpose — never surfaces key or plaintext.
fn decrypt_cp_credential(
    encrypted_blob: &serde_json::Value,
    cp_secret: &str,
) -> Result<String, anyhow::Error> {
    let ciphertext: forge_core::spec::SecretCiphertext =
        serde_json::from_value(encrypted_blob.clone())
            .map_err(|_| anyhow::anyhow!("malformed encrypted credential"))?;
    let identity = cp_secret
        .parse::<age::x25519::Identity>()
        .map_err(|_| anyhow::anyhow!("invalid control-plane age secret"))?;
    let plaintext = forge_agent::job::decrypt_secret(&ciphertext, &identity)
        .map_err(|_| anyhow::anyhow!("credential decryption failed"))?;
    String::from_utf8(plaintext).map_err(|_| anyhow::anyhow!("credential is not valid UTF-8"))
}

// ---------------------------------------------------------------------------
// Input validation helpers (A05 — length-bound + shape every external input).
// ---------------------------------------------------------------------------

/// A provider/region/size/image/network/firewall name token. Conservative bound; the
/// upstream APIs reject anything longer anyway, and we never echo it back unsanitized.
fn validate_token(field: &str, value: &str, max: usize) -> Result<(), ProvisionError> {
    let v = value.trim();
    if v.is_empty() || v.len() > max {
        return Err(ProvisionError::InvalidInput(format!(
            "{field} must be 1-{max} characters"
        )));
    }
    Ok(())
}

/// Spec for provisioning a server through the unified path.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerProvisionInput {
    pub name: String,
    pub size: String,
    pub image: String,
    pub region: String,
    /// Cloud-init user-data. When absent, the caller (handler) injects the agent
    /// enrollment cloud-init so the server auto-enrolls.
    #[serde(default)]
    pub user_data: Option<String>,
    #[serde(default)]
    pub ssh_key_ids: Vec<String>,
    #[serde(default)]
    pub network_ids: Vec<String>,
    #[serde(default)]
    pub firewall_ids: Vec<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub application_id: Option<Uuid>,
}

/// A single firewall rule as accepted over the API.
#[derive(Debug, Clone, Deserialize)]
pub struct FirewallRuleInput {
    pub direction: Direction,
    pub protocol: Protocol,
    #[serde(default)]
    pub port_range: Option<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// The provisioning service: persistence + provider orchestration.
pub struct ProvisioningService {
    pool: PgPool,
    factory: Arc<dyn ProviderFactory>,
}

impl ProvisioningService {
    #[must_use]
    pub fn new(pool: PgPool, factory: Arc<dyn ProviderFactory>) -> Self {
        Self { pool, factory }
    }

    /// Capabilities for a known provider, or `None` if the name is unknown.
    #[must_use]
    pub fn capabilities(&self, provider: &str) -> Option<Capabilities> {
        self.factory.capabilities(provider)
    }

    /// All known providers with their advertised capabilities (UI feature-gating).
    #[must_use]
    pub fn list_providers(&self) -> Vec<serde_json::Value> {
        KNOWN_PROVIDERS
            .iter()
            .filter_map(|name| {
                self.capabilities(name).map(|caps| {
                    serde_json::json!({
                        "name": name,
                        "implemented": *name == "hetzner",
                        "capabilities": caps,
                    })
                })
            })
            .collect()
    }

    // --- catalog ---

    /// Provider catalog: regions, sizes, images via the trait.
    pub async fn catalog(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
    ) -> Result<serde_json::Value, ProvisionError> {
        let p = self.factory.build(provider, credential_id).await?;
        let regions = p.list_regions().await?;
        let sizes = p.list_sizes().await?;
        let images = p.list_images().await?;
        Ok(serde_json::json!({
            "regions": regions,
            "sizes": sizes,
            "images": images,
        }))
    }

    // --- persistence ---

    /// Insert one resource row. `external_id`/`status` reflect the create outcome.
    // Each parameter maps to a distinct column in `provisioned_resources`; grouping them
    // into a struct would just push the field count into a builder pattern with no gain.
    #[allow(clippy::too_many_arguments)]
    async fn record_resource(
        &self,
        provider: &str,
        kind: ResourceKind,
        external_id: Option<&str>,
        name: Option<&str>,
        region: Option<&str>,
        status: &str,
        metadata: serde_json::Value,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        let id = Uuid::now_v7();
        let row = sqlx::query!(
            r#"
            INSERT INTO provisioned_resources
                (id, provider, kind, external_id, name, region, status, metadata,
                 application_id, created_by_principal_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, provider, kind, external_id, name, region, status, metadata,
                      application_id, created_by_principal_id, created_at, updated_at, deleted_at
            "#,
            id,
            provider,
            kind.as_str(),
            external_id,
            name,
            region,
            status,
            metadata,
            application_id,
            principal_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            // application_id FK violation → caller referenced a non-existent app.
            sqlx::Error::Database(ref db) if db.code().as_deref() == Some("23503") => {
                ProvisionError::InvalidInput("application_id does not exist".into())
            }
            // Unique violation on (provider, external_id) — concurrent duplicate create.
            sqlx::Error::Database(ref db) if db.code().as_deref() == Some("23505") => {
                ProvisionError::Conflict("a resource with that external id already exists".into())
            }
            other => ProvisionError::Internal(other.into()),
        })?;

        Ok(row_to_resource(
            row.id,
            row.provider,
            row.kind,
            row.external_id,
            row.name,
            row.region,
            row.status,
            row.metadata,
            row.application_id,
            row.created_by_principal_id,
            row.created_at,
            row.updated_at,
            row.deleted_at,
        ))
    }

    /// List live (non-deleted) resources for a provider.
    pub async fn list_resources(
        &self,
        provider: &str,
    ) -> Result<Vec<ProvisionedResource>, ProvisionError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, provider, kind, external_id, name, region, status, metadata,
                   application_id, created_by_principal_id, created_at, updated_at, deleted_at
            FROM provisioned_resources
            WHERE provider = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 500
            "#,
            provider
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ProvisionError::Internal(e.into()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                row_to_resource(
                    r.id,
                    r.provider,
                    r.kind,
                    r.external_id,
                    r.name,
                    r.region,
                    r.status,
                    r.metadata,
                    r.application_id,
                    r.created_by_principal_id,
                    r.created_at,
                    r.updated_at,
                    r.deleted_at,
                )
            })
            .collect())
    }

    /// Fetch one resource row scoped to a provider.
    pub async fn get_resource(
        &self,
        provider: &str,
        id: Uuid,
    ) -> Result<ProvisionedResource, ProvisionError> {
        let row = sqlx::query!(
            r#"
            SELECT id, provider, kind, external_id, name, region, status, metadata,
                   application_id, created_by_principal_id, created_at, updated_at, deleted_at
            FROM provisioned_resources
            WHERE id = $1 AND provider = $2
            "#,
            id,
            provider
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ProvisionError::Internal(e.into()))?;

        match row {
            Some(r) => Ok(row_to_resource(
                r.id,
                r.provider,
                r.kind,
                r.external_id,
                r.name,
                r.region,
                r.status,
                r.metadata,
                r.application_id,
                r.created_by_principal_id,
                r.created_at,
                r.updated_at,
                r.deleted_at,
            )),
            None => Err(ProvisionError::NotFound),
        }
    }

    // --- provisioning ---

    /// Provision a server and persist a `provisioned_resources` row. On a provider
    /// [`ProviderError::PartialFailure`], record a `partial` row carrying the created +
    /// leftover IDs so an operator can finish cleanup, then re-raise the error.
    pub async fn provision_server(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        input: ServerProvisionInput,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("name", &input.name, 63)?;
        validate_token("size", &input.size, 64)?;
        validate_token("image", &input.image, 128)?;
        validate_token("region", &input.region, 64)?;
        if let Some(ud) = &input.user_data {
            if ud.len() > 64 * 1024 {
                return Err(ProvisionError::InvalidInput(
                    "user_data exceeds 64 KiB".into(),
                ));
            }
        }

        let p = self.factory.build(provider, credential_id).await?;

        let spec = ServerSpec {
            name: input.name.trim().to_string(),
            size: input.size.trim().to_string(),
            image: input.image.trim().to_string(),
            region: input.region.trim().to_string(),
            user_data: input.user_data.clone(),
            ssh_key_ids: input.ssh_key_ids.clone(),
            network_ids: input.network_ids.clone(),
            firewall_ids: input.firewall_ids.clone(),
            labels: input.labels.clone(),
        };

        match p.provision_server(&spec).await {
            Ok(server) => {
                let metadata = serde_json::json!({
                    "public_ipv4": server.public_ipv4,
                    "public_ipv6": server.public_ipv6,
                    "private_ips": server.private_ips,
                    "size": server.size,
                    "image": server.image,
                    "status": server.status,
                });
                self.record_resource(
                    provider,
                    ResourceKind::Server,
                    Some(server.id.as_str()),
                    Some(&server.name),
                    Some(&server.region),
                    "active",
                    metadata,
                    input.application_id,
                    principal_id,
                )
                .await
            }
            Err(ProviderError::PartialFailure {
                message,
                created_resource_ids,
                leftover_resource_ids,
            }) => {
                // Record what was created so cleanup is possible, then surface the error.
                let metadata = serde_json::json!({
                    "partial_failure": message,
                    "created_resource_ids": created_resource_ids,
                    "leftover_resource_ids": leftover_resource_ids,
                });
                let _ = self
                    .record_resource(
                        provider,
                        ResourceKind::Server,
                        None,
                        Some(&spec.name),
                        Some(&spec.region),
                        "partial",
                        metadata,
                        input.application_id,
                        principal_id,
                    )
                    .await?;
                Err(ProvisionError::Provider(ProviderError::PartialFailure {
                    message,
                    created_resource_ids,
                    leftover_resource_ids,
                }))
            }
            Err(other) => Err(ProvisionError::Provider(other)),
        }
    }

    /// Create a private network and persist it.
    pub async fn create_network(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        name: &str,
        ip_range: &str,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("name", name, 63)?;
        validate_token("ip_range", ip_range, 64)?;
        let p = self.factory.build(provider, credential_id).await?;
        let net = p.create_network(name.trim(), ip_range.trim()).await?;
        self.record_resource(
            provider,
            ResourceKind::Network,
            Some(&net.id),
            Some(&net.name),
            None,
            "active",
            serde_json::json!({ "ip_range": net.ip_range }),
            application_id,
            principal_id,
        )
        .await
    }

    /// Create a firewall and persist it.
    pub async fn create_firewall(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        name: &str,
        rules: Vec<FirewallRuleInput>,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("name", name, 63)?;
        if rules.len() > 100 {
            return Err(ProvisionError::InvalidInput(
                "too many rules (max 100)".into(),
            ));
        }
        let rules: Vec<FirewallRule> = rules
            .into_iter()
            .map(|r| FirewallRule {
                direction: r.direction,
                protocol: r.protocol,
                port_range: r.port_range,
                cidrs: r.cidrs,
            })
            .collect();
        let p = self.factory.build(provider, credential_id).await?;
        let id = p.create_firewall(name.trim(), &rules).await?;
        self.record_resource(
            provider,
            ResourceKind::Firewall,
            Some(&id),
            Some(name.trim()),
            None,
            "active",
            serde_json::json!({ "rule_count": rules.len() }),
            application_id,
            principal_id,
        )
        .await
    }

    /// Create a block-storage volume and persist it.
    // Infra parameters (name, size_gb, region) plus the two cross-cutting tracking IDs
    // (application_id, principal_id) — all distinct, no natural sub-grouping.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_volume(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        name: &str,
        size_gb: u64,
        region: &str,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("name", name, 63)?;
        validate_token("region", region, 64)?;
        if size_gb == 0 || size_gb > 10_240 {
            return Err(ProvisionError::InvalidInput(
                "size_gb must be 1-10240".into(),
            ));
        }
        let p = self.factory.build(provider, credential_id).await?;
        let vol = p.create_volume(name.trim(), size_gb, region.trim()).await?;
        self.record_resource(
            provider,
            ResourceKind::Volume,
            Some(&vol.id),
            Some(&vol.name),
            Some(&vol.region),
            "active",
            serde_json::json!({ "size_gb": vol.size_gb }),
            application_id,
            principal_id,
        )
        .await
    }

    /// Create a load balancer and persist it.
    // Infra parameters (name, region, services) plus the two cross-cutting tracking IDs
    // (application_id, principal_id) — all distinct, no natural sub-grouping.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_load_balancer(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        name: &str,
        region: &str,
        services: Vec<LbService>,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("name", name, 63)?;
        validate_token("region", region, 64)?;
        if services.len() > 50 {
            return Err(ProvisionError::InvalidInput(
                "too many services (max 50)".into(),
            ));
        }
        let p = self.factory.build(provider, credential_id).await?;
        let lb = p
            .create_load_balancer(name.trim(), region.trim(), &services)
            .await?;
        self.record_resource(
            provider,
            ResourceKind::LoadBalancer,
            Some(&lb.id),
            Some(&lb.name),
            Some(&lb.region),
            "active",
            serde_json::json!({ "public_ipv4": lb.public_ipv4 }),
            application_id,
            principal_id,
        )
        .await
    }

    /// Allocate a floating/primary IP and persist it.
    pub async fn allocate_ip(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        region: &str,
        ipv6: bool,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("region", region, 64)?;
        let p = self.factory.build(provider, credential_id).await?;
        let (ip_id, address) = p.allocate_ip(region.trim(), ipv6).await?;
        self.record_resource(
            provider,
            ResourceKind::Ip,
            Some(&ip_id),
            Some(&address),
            Some(region.trim()),
            "active",
            serde_json::json!({ "address": address, "ipv6": ipv6 }),
            application_id,
            principal_id,
        )
        .await
    }

    /// Upsert a DNS record and persist it. `zone_id` may be a zone id or a domain — when a
    /// domain is supplied the provider's `dns_ensure_zone` resolves it first.
    #[allow(clippy::too_many_arguments)]
    pub async fn dns_upsert(
        &self,
        provider: &str,
        credential_id: Option<Uuid>,
        zone: &str,
        record_type: DnsRecordType,
        name: &str,
        value: &str,
        ttl: Option<u32>,
        application_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        validate_token("zone", zone, 253)?;
        validate_token("name", name, 253)?;
        validate_token("value", value, 1024)?;
        let p = self.factory.build(provider, credential_id).await?;

        // Accept either a raw zone id or a domain; ensure_zone is idempotent.
        let zone_id = if zone.contains('.') {
            p.dns_ensure_zone(zone.trim()).await?
        } else {
            zone.trim().to_string()
        };

        let record = DnsRecord {
            id: None,
            zone_id: zone_id.clone(),
            record_type,
            name: name.trim().to_string(),
            value: value.trim().to_string(),
            ttl,
        };
        let record_id = p.dns_upsert_record(&record).await?;
        self.record_resource(
            provider,
            ResourceKind::DnsRecord,
            Some(&record_id),
            Some(name.trim()),
            None,
            "active",
            serde_json::json!({ "zone_id": zone_id, "type": record_type, "value": value.trim() }),
            application_id,
            principal_id,
        )
        .await
    }

    /// Delete a tracked resource via the provider, then mark it deleted in the DB.
    /// Idempotent on the DB side: a `NotFound` from the provider still soft-deletes the row.
    pub async fn delete_resource(
        &self,
        provider: &str,
        id: Uuid,
        credential_id: Option<Uuid>,
    ) -> Result<ProvisionedResource, ProvisionError> {
        let resource = self.get_resource(provider, id).await?;
        if resource.deleted_at.is_some() {
            return Ok(resource);
        }
        let external_id = resource.external_id.clone().ok_or_else(|| {
            ProvisionError::InvalidInput("resource has no external id to delete".into())
        })?;
        let kind: ResourceKind =
            serde_json::from_value(serde_json::Value::String(resource.kind.clone()))
                .map_err(|_| ProvisionError::Internal(anyhow::anyhow!("unknown resource kind")))?;

        let p = self.factory.build(provider, credential_id).await?;

        // Treat "already gone" as success so deletes are idempotent.
        let outcome = match kind {
            ResourceKind::Server => p.delete_server(&ServerId::new(external_id.clone())).await,
            ResourceKind::Firewall => p.delete_firewall(&external_id).await,
            ResourceKind::Network => p.delete_network(&external_id).await,
            ResourceKind::Volume => p.delete_volume(&external_id).await,
            ResourceKind::LoadBalancer => p.delete_load_balancer(&external_id).await,
            ResourceKind::Ip => p.release_ip(&external_id).await,
            ResourceKind::DnsRecord => {
                let zone_id = resource
                    .metadata
                    .get("zone_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ProvisionError::InvalidInput("dns record missing zone_id".into())
                    })?;
                p.dns_delete_record(zone_id, &external_id).await
            }
        };

        match outcome {
            Ok(()) | Err(ProviderError::NotFound(_)) => {}
            Err(other) => return Err(ProvisionError::Provider(other)),
        }

        let row = sqlx::query!(
            r#"
            UPDATE provisioned_resources
            SET status = 'deleted', deleted_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND provider = $2
            RETURNING id, provider, kind, external_id, name, region, status, metadata,
                      application_id, created_by_principal_id, created_at, updated_at, deleted_at
            "#,
            id,
            provider
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ProvisionError::Internal(e.into()))?;

        Ok(row_to_resource(
            row.id,
            row.provider,
            row.kind,
            row.external_id,
            row.name,
            row.region,
            row.status,
            row.metadata,
            row.application_id,
            row.created_by_principal_id,
            row.created_at,
            row.updated_at,
            row.deleted_at,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn row_to_resource(
    id: Uuid,
    provider: String,
    kind: String,
    external_id: Option<String>,
    name: Option<String>,
    region: Option<String>,
    status: String,
    metadata: serde_json::Value,
    application_id: Option<Uuid>,
    created_by_principal_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
) -> ProvisionedResource {
    ProvisionedResource {
        id,
        provider,
        kind,
        external_id,
        name,
        region,
        status,
        metadata,
        application_id,
        created_by_principal_id,
        created_at,
        updated_at,
        deleted_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use forge_providers::{ImageInfo, NetworkInfo, RegionInfo, ServerInfo, ServerStatus, SizeInfo};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A mock provider used to exercise the persistence + partial-failure logic without a
    /// real cloud API. `partial` flips `provision_server` to a PartialFailure.
    struct MockProvider {
        partial: AtomicBool,
        deleted: AtomicBool,
    }

    impl MockProvider {
        fn new(partial: bool) -> Self {
            Self {
                partial: AtomicBool::new(partial),
                deleted: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl CloudProvider for MockProvider {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                servers: true,
                networks: true,
                firewalls: true,
                ..Capabilities::none()
            }
        }
        async fn list_regions(&self) -> forge_providers::Result<Vec<RegionInfo>> {
            Ok(vec![RegionInfo {
                id: "fsn1".into(),
                name: "Falkenstein".into(),
                country: Some("DE".into()),
                city: Some("Falkenstein".into()),
            }])
        }
        async fn list_sizes(&self) -> forge_providers::Result<Vec<SizeInfo>> {
            Ok(vec![SizeInfo {
                id: "cx22".into(),
                description: "2vCPU".into(),
                vcpus: 2,
                memory_gb: 4.0,
                disk_gb: 40.0,
                available_regions: vec!["fsn1".into()],
            }])
        }
        async fn list_images(&self) -> forge_providers::Result<Vec<ImageInfo>> {
            Ok(vec![ImageInfo {
                id: "ubuntu-24.04".into(),
                name: "Ubuntu 24.04".into(),
                description: None,
                os_flavor: Some("ubuntu".into()),
                os_version: Some("24.04".into()),
            }])
        }
        async fn provision_server(&self, spec: &ServerSpec) -> forge_providers::Result<ServerInfo> {
            if self.partial.load(Ordering::SeqCst) {
                return Err(ProviderError::PartialFailure {
                    message: "network attach failed".into(),
                    created_resource_ids: vec!["server-999".into(), "net-1".into()],
                    leftover_resource_ids: vec!["net-1".into()],
                });
            }
            Ok(ServerInfo {
                id: ServerId::new("server-1"),
                name: spec.name.clone(),
                status: ServerStatus::Initializing,
                public_ipv4: Some("203.0.113.7".into()),
                public_ipv6: None,
                private_ips: vec![],
                region: spec.region.clone(),
                size: spec.size.clone(),
                image: spec.image.clone(),
                labels: spec.labels.clone(),
            })
        }
        async fn get_server(&self, _id: &ServerId) -> forge_providers::Result<ServerInfo> {
            Err(ProviderError::NotImplemented)
        }
        async fn list_servers(&self) -> forge_providers::Result<Vec<ServerInfo>> {
            Ok(vec![])
        }
        async fn delete_server(&self, _id: &ServerId) -> forge_providers::Result<()> {
            self.deleted.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn resize_server(
            &self,
            _id: &ServerId,
            _new_size: &str,
            _upgrade_disk: bool,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn rebuild_server(
            &self,
            _id: &ServerId,
            _image: &str,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn ensure_ssh_key(
            &self,
            _name: &str,
            _public_key: &str,
        ) -> forge_providers::Result<String> {
            Err(ProviderError::NotImplemented)
        }
        async fn list_ssh_keys(&self) -> forge_providers::Result<Vec<(String, String)>> {
            Ok(vec![])
        }
        async fn delete_ssh_key(&self, _id: &str) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn create_network(
            &self,
            name: &str,
            ip_range: &str,
        ) -> forge_providers::Result<NetworkInfo> {
            Ok(NetworkInfo {
                id: "net-1".into(),
                name: name.into(),
                ip_range: ip_range.into(),
            })
        }
        async fn delete_network(&self, _id: &str) -> forge_providers::Result<()> {
            Ok(())
        }
        async fn list_networks(&self) -> forge_providers::Result<Vec<NetworkInfo>> {
            Ok(vec![])
        }
        async fn attach_server_to_network(
            &self,
            _server: &ServerId,
            _network_id: &str,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn create_firewall(
            &self,
            _name: &str,
            _rules: &[FirewallRule],
        ) -> forge_providers::Result<String> {
            Ok("fw-1".into())
        }
        async fn delete_firewall(&self, _id: &str) -> forge_providers::Result<()> {
            Ok(())
        }
        async fn attach_firewall(
            &self,
            _firewall_id: &str,
            _server: &ServerId,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn detach_firewall(
            &self,
            _firewall_id: &str,
            _server: &ServerId,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn allocate_ip(
            &self,
            _region: &str,
            _ipv6: bool,
        ) -> forge_providers::Result<(String, String)> {
            Err(ProviderError::NotImplemented)
        }
        async fn assign_ip(&self, _ip_id: &str, _server: &ServerId) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn release_ip(&self, _ip_id: &str) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn create_volume(
            &self,
            _name: &str,
            _size_gb: u64,
            _region: &str,
        ) -> forge_providers::Result<forge_providers::VolumeInfo> {
            Err(ProviderError::NotImplemented)
        }
        async fn attach_volume(
            &self,
            _volume_id: &str,
            _server: &ServerId,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn detach_volume(&self, _volume_id: &str) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn resize_volume(
            &self,
            _volume_id: &str,
            _new_size_gb: u64,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn delete_volume(&self, _volume_id: &str) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn create_load_balancer(
            &self,
            _name: &str,
            _region: &str,
            _services: &[LbService],
        ) -> forge_providers::Result<forge_providers::LoadBalancerInfo> {
            Err(ProviderError::NotImplemented)
        }
        async fn delete_load_balancer(&self, _id: &str) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn add_lb_target(
            &self,
            _lb_id: &str,
            _target: &forge_providers::LbTarget,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn remove_lb_target(
            &self,
            _lb_id: &str,
            _server: &ServerId,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn update_lb_service(
            &self,
            _lb_id: &str,
            _service: &LbService,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn dns_ensure_zone(&self, _domain: &str) -> forge_providers::Result<String> {
            Err(ProviderError::NotImplemented)
        }
        async fn dns_upsert_record(&self, _record: &DnsRecord) -> forge_providers::Result<String> {
            Err(ProviderError::NotImplemented)
        }
        async fn dns_delete_record(
            &self,
            _zone_id: &str,
            _record_id: &str,
        ) -> forge_providers::Result<()> {
            Err(ProviderError::NotImplemented)
        }
        async fn dns_list_records(
            &self,
            _zone_id: &str,
        ) -> forge_providers::Result<Vec<DnsRecord>> {
            Ok(vec![])
        }
    }

    /// A factory that always returns the same mock provider, ignoring credentials.
    struct MockFactory {
        provider: Arc<MockProvider>,
    }

    #[async_trait]
    impl ProviderFactory for MockFactory {
        fn capabilities(&self, provider: &str) -> Option<Capabilities> {
            if provider == "mock" {
                Some(self.provider.capabilities())
            } else {
                None
            }
        }
        async fn build(
            &self,
            provider: &str,
            _credential_id: Option<Uuid>,
        ) -> Result<Arc<dyn CloudProvider>, ProvisionError> {
            if provider == "mock" {
                Ok(self.provider.clone() as Arc<dyn CloudProvider>)
            } else {
                Err(ProvisionError::UnknownProvider)
            }
        }
    }

    fn service_with(pool: PgPool, partial: bool) -> (ProvisioningService, Arc<MockProvider>) {
        let provider = Arc::new(MockProvider::new(partial));
        let factory = Arc::new(MockFactory {
            provider: provider.clone(),
        });
        (ProvisioningService::new(pool, factory), provider)
    }

    fn server_input() -> ServerProvisionInput {
        ServerProvisionInput {
            name: "forge-node-1".into(),
            size: "cx22".into(),
            image: "ubuntu-24.04".into(),
            region: "fsn1".into(),
            user_data: Some("#cloud-config\n".into()),
            ssh_key_ids: vec![],
            network_ids: vec![],
            firewall_ids: vec![],
            labels: BTreeMap::new(),
            application_id: None,
        }
    }

    #[sqlx::test]
    async fn provision_persists_a_row_and_lists_it(pool: PgPool) {
        let (svc, _) = service_with(pool, false);

        let created = svc
            .provision_server("mock", None, server_input(), None)
            .await
            .expect("provision should succeed");

        assert_eq!(created.kind, "server");
        assert_eq!(created.external_id.as_deref(), Some("server-1"));
        assert_eq!(created.status, "active");
        assert_eq!(created.region.as_deref(), Some("fsn1"));

        let listed = svc.list_resources("mock").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);

        // get_resource round-trips by (provider, id).
        let got = svc.get_resource("mock", created.id).await.unwrap();
        assert_eq!(got.external_id.as_deref(), Some("server-1"));
    }

    #[sqlx::test]
    async fn partial_failure_records_created_resources_then_raises(pool: PgPool) {
        let (svc, _) = service_with(pool, true);

        let err = svc
            .provision_server("mock", None, server_input(), None)
            .await
            .expect_err("partial failure should surface");

        match err {
            ProvisionError::Provider(ProviderError::PartialFailure {
                ref leftover_resource_ids,
                ..
            }) => {
                assert_eq!(leftover_resource_ids, &vec!["net-1".to_string()]);
            }
            other => panic!("expected PartialFailure, got {other:?}"),
        }

        // A `partial` row was recorded carrying the created + leftover IDs for cleanup.
        let listed = svc.list_resources("mock").await.unwrap();
        assert_eq!(listed.len(), 1);
        let row = &listed[0];
        assert_eq!(row.status, "partial");
        assert!(row.external_id.is_none());
        let created_ids = row.metadata["created_resource_ids"].as_array().unwrap();
        assert_eq!(created_ids.len(), 2);
        assert_eq!(row.metadata["leftover_resource_ids"][0], "net-1");
    }

    #[sqlx::test]
    async fn delete_calls_provider_and_soft_deletes(pool: PgPool) {
        let (svc, provider) = service_with(pool, false);

        let created = svc
            .provision_server("mock", None, server_input(), None)
            .await
            .unwrap();

        let deleted = svc.delete_resource("mock", created.id, None).await.unwrap();
        assert_eq!(deleted.status, "deleted");
        assert!(deleted.deleted_at.is_some());
        assert!(
            provider.deleted.load(Ordering::SeqCst),
            "provider delete was called"
        );

        // Soft-deleted rows drop out of the live listing.
        assert!(svc.list_resources("mock").await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn unknown_provider_is_rejected(pool: PgPool) {
        let (svc, _) = service_with(pool, false);
        let err = svc
            .provision_server("nope", None, server_input(), None)
            .await
            .expect_err("unknown provider must fail");
        assert!(matches!(err, ProvisionError::UnknownProvider));
    }

    #[sqlx::test]
    async fn server_input_is_length_bounded(pool: PgPool) {
        let (svc, _) = service_with(pool, false);
        let mut input = server_input();
        input.name = "x".repeat(200);
        let err = svc
            .provision_server("mock", None, input, None)
            .await
            .expect_err("over-long name rejected");
        assert!(matches!(err, ProvisionError::InvalidInput(_)));
    }
}
