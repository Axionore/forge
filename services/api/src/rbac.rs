//! Full additive RBAC scaffolding (Tier 3-4).
//!
//! Principals (users or api_keys) + roles with JSONB permissions + admin_tokens (hashed).
//! Bootstrap FORGE_ADMIN_TOKEN (env var) is ALWAYS full admin via fast constant-time path
//! (never stored in DB, never subject to role changes). Issued tokens provide the path
//! beyond single-token bootstrap for real multi-operator use and future OIDC.
//!
//! Security (OWASP A01 #1, ASVS L2 V8, api-design-and-security):
//! - Default-deny on every permission check (action_allowed returns false unless explicit match).
//! - All checks server-side only; never trust client or URL.
//! - Token storage: sha256 hash only (BYTEA PK), raw value returned exactly once in create response.
//! - Constant-time compare ONLY for bootstrap (ring::constant_time); issued tokens use DB PK lookup.
//! - Structured logs with principal_id / role names only — never raw tokens or secrets (A09).
//! - Fail-closed: any DB error, serde failure, or missing data → deny.
//! - Input validation + length bounds on all create paths.
//!
//! Projects/teams tables exist for future scoping (principal_projects, team_members) but are not
//! enforced in v1 scaffolding. Enforcement + object-level checks come in follow-up slices.

use anyhow::Context;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// Error type for RBAC operations. Mirrors DeploymentError / EnrollmentError patterns.
#[derive(Debug, Error)]
pub enum RbacError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found")]
    NotFound,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

/// Lightweight principal row (for responses and in-memory checks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: Uuid,
    pub name: String,
    pub principal_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Summary of an issued admin token (NEVER contains the raw secret after creation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTokenSummary {
    pub token_hash_prefix: String,
    pub principal_id: Uuid,
    pub description: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Role with its JSONB permissions (the source of truth for checks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub permissions: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Project scaffolding (future scoping surface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Team scaffolding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Returned exactly once from create_admin_token (raw value + metadata).
#[derive(Debug)]
pub struct CreatedAdminToken {
    pub raw_token: String,
    pub principal_id: Uuid,
    pub description: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The RBAC service. All DB access for principals/roles/tokens goes through here.
/// Pattern-matched exactly on EnrollmentService for consistency (same token lifecycle UX).
pub struct RbacService {
    pool: PgPool,
}

impl RbacService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new principal (user or api_key type).
    pub async fn create_principal(
        &self,
        name: &str,
        principal_type: &str,
        created_by: Option<&str>,
    ) -> Result<Principal, RbacError> {
        if name.trim().is_empty() || name.len() > 128 {
            return Err(RbacError::InvalidInput(
                "name must be 1..=128 characters".into(),
            ));
        }
        if !matches!(principal_type, "user" | "api_key") {
            return Err(RbacError::InvalidInput(
                "principal_type must be 'user' or 'api_key'".into(),
            ));
        }

        let id = Uuid::now_v7();
        let now = chrono::Utc::now();

        let row = sqlx::query!(
            r#"
            INSERT INTO principals (id, name, principal_type, created_by, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            RETURNING id, name, principal_type, created_at
            "#,
            id,
            name,
            principal_type,
            created_by,
            now
        )
        .fetch_one(&self.pool)
        .await
        .context("failed to insert principal")?;

        Ok(Principal {
            id: row.id,
            name: row.name,
            principal_type: row.principal_type,
            created_at: row.created_at,
        })
    }

    /// List principals (non-deleted).
    pub async fn list_principals(&self) -> Result<Vec<Principal>, RbacError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, principal_type, created_at
            FROM principals
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 200
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to list principals")?;

        Ok(rows
            .into_iter()
            .map(|r| Principal {
                id: r.id,
                name: r.name,
                principal_type: r.principal_type,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Create role with permissions JSONB (validated shape: object).
    pub async fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
        permissions: serde_json::Value,
        created_by: Option<&str>,
    ) -> Result<Role, RbacError> {
        if name.trim().is_empty() || name.len() > 64 {
            return Err(RbacError::InvalidInput("name 1..=64 required".into()));
        }
        if !permissions.is_object() {
            return Err(RbacError::InvalidInput(
                "permissions must be a JSON object".into(),
            ));
        }

        let id = Uuid::now_v7();
        let now = chrono::Utc::now();

        let row = sqlx::query!(
            r#"
            INSERT INTO roles (id, name, description, permissions, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, description, permissions, created_at, revoked_at
            "#,
            id,
            name,
            description,
            permissions,
            created_by,
            now
        )
        .fetch_one(&self.pool)
        .await
        .context("failed to insert role")?;

        Ok(Role {
            id: row.id,
            name: row.name,
            description: row.description,
            permissions: row.permissions,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        })
    }

    /// List active (non-revoked) roles.
    pub async fn list_roles(&self) -> Result<Vec<Role>, RbacError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, description, permissions, created_at, revoked_at
            FROM roles
            WHERE revoked_at IS NULL
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("list roles")?;

        Ok(rows
            .into_iter()
            .map(|r| Role {
                id: r.id,
                name: r.name,
                description: r.description,
                permissions: r.permissions,
                created_at: r.created_at,
                revoked_at: r.revoked_at,
            })
            .collect())
    }

    /// Create a new admin token for a principal + (optional) role assignment.
    /// Raw token returned ONLY in this struct — caller must surface it once then forget it.
    /// Mirrors enrollment token creation exactly (same UX, same security properties).
    pub async fn create_admin_token(
        &self,
        principal_id: Uuid,
        description: Option<String>,
        expires_in_days: Option<i32>,
        created_by: Option<&str>,
    ) -> Result<CreatedAdminToken, RbacError> {
        // Basic validation (defense in depth)
        if description.as_ref().is_some_and(|d| d.len() > 256) {
            return Err(RbacError::InvalidInput(
                "description must be <= 256 chars".into(),
            ));
        }
        if let Some(d) = expires_in_days {
            if !(0..=365).contains(&d) {
                return Err(RbacError::InvalidInput("expires_in_days 0..=365".into()));
            }
        }

        // Verify principal exists and is not deleted
        let principal_exists = sqlx::query_scalar!(
            "SELECT 1 FROM principals WHERE id = $1 AND deleted_at IS NULL",
            principal_id
        )
        .fetch_optional(&self.pool)
        .await
        .context("principal lookup")?
        .is_some();

        if !principal_exists {
            return Err(RbacError::NotFound);
        }

        let raw_token = generate_secure_token(32);
        let token_hash = Sha256::digest(raw_token.as_bytes()).to_vec();

        let expires_at = expires_in_days
            .filter(|d| *d > 0)
            .map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));

        sqlx::query!(
            r#"
            INSERT INTO admin_tokens (token_hash, principal_id, description, expires_at, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
            token_hash,
            principal_id,
            description,
            expires_at,
            created_by
        )
        .execute(&self.pool)
        .await
        .context("insert admin_token")?;

        Ok(CreatedAdminToken {
            raw_token,
            principal_id,
            description,
            expires_at,
        })
    }

    /// List admin tokens (prefixes only — never raw values).
    pub async fn list_admin_tokens(&self) -> Result<Vec<AdminTokenSummary>, RbacError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                encode(token_hash, 'hex') as token_hash_hex,
                principal_id,
                description,
                expires_at,
                revoked_at,
                created_at
            FROM admin_tokens
            ORDER BY created_at DESC
            LIMIT 200
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("list admin_tokens")?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let prefix: String = r
                    .token_hash_hex
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(8)
                    .collect();
                AdminTokenSummary {
                    token_hash_prefix: prefix,
                    principal_id: r.principal_id,
                    description: r.description,
                    expires_at: r.expires_at,
                    revoked_at: r.revoked_at,
                    created_at: r.created_at,
                }
            })
            .collect())
    }

    /// Revoke an admin token by 4+ char hex prefix (operator UX, same as enrollment).
    pub async fn revoke_admin_token(&self, prefix: &str) -> Result<(), RbacError> {
        let p = prefix.trim().to_lowercase();
        if p.len() < 4 || p.len() > 64 {
            return Err(RbacError::InvalidInput("invalid prefix".into()));
        }

        sqlx::query!(
            r#"
            UPDATE admin_tokens
            SET revoked_at = NOW()
            WHERE encode(token_hash, 'hex') LIKE $1 || '%'
              AND revoked_at IS NULL
            "#,
            p
        )
        .execute(&self.pool)
        .await
        .context("revoke admin_token")?;

        Ok(())
    }

    /// Load all active (non-revoked) role permissions JSONB for a principal.
    /// Used by middleware / guards for issued-token checks.
    pub async fn get_principal_permissions(
        &self,
        principal_id: Uuid,
    ) -> Result<Vec<serde_json::Value>, RbacError> {
        let rows = sqlx::query!(
            r#"
            SELECT r.permissions
            FROM principal_roles pr
            JOIN roles r ON r.id = pr.role_id
            WHERE pr.principal_id = $1
              AND r.revoked_at IS NULL
            "#,
            principal_id
        )
        .fetch_all(&self.pool)
        .await
        .context("load principal permissions")?;

        Ok(rows.into_iter().map(|r| r.permissions).collect())
    }

    /// High-level convenience: does this principal (via any of its roles) allow the action?
    /// Bootstrap callers should short-circuit before calling this.
    pub async fn principal_can(&self, principal_id: Uuid, action: &str) -> Result<bool, RbacError> {
        let perms = self.get_principal_permissions(principal_id).await?;
        Ok(perms.iter().any(|p| action_allowed(p, action)))
    }
}

/// Core permission matcher (default-deny). Supports three grant shapes:
///
/// - exact: `"deployments:read"`
/// - wildcard namespace: `"deployments:*"` matches any `deployments:xxx`
/// - super-admin: `"*"` matches everything
///
/// All other cases (including malformed input) return `false`.
pub fn action_allowed(permissions: &serde_json::Value, action: &str) -> bool {
    let obj = match permissions.as_object() {
        Some(o) => o,
        None => return false,
    };

    // Super admin
    if obj.get("*").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }

    // Exact match
    if obj.get(action).and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }

    // Namespace wildcard: "foo:*" covers "foo:bar" and "foo:baz:quux"
    if let Some(colon) = action.find(':') {
        let ns = &action[..colon + 1]; // "foo:"
        let wildcard = format!("{ns}*");
        if obj.get(&wildcard).and_then(|v| v.as_bool()) == Some(true) {
            return true;
        }
    }

    false
}

/// Secure token generator (identical to enrollment.rs).
fn generate_secure_token(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// =============================================================================
// Unit tests for the permission engine (must be able to fail to be real tests)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn action_allowed_super_admin() {
        let p = json!({"*": true});
        assert!(action_allowed(&p, "anything"));
        assert!(action_allowed(&p, "secrets:write"));
    }

    #[test]
    fn action_allowed_exact_and_namespace() {
        let p = json!({
            "deployments:read": true,
            "secrets:*": true
        });
        assert!(action_allowed(&p, "deployments:read"));
        assert!(!action_allowed(&p, "deployments:write")); // no wildcard for deployments
        assert!(action_allowed(&p, "secrets:read"));
        assert!(action_allowed(&p, "secrets:rotate"));
    }

    #[test]
    fn action_allowed_default_deny() {
        let p = json!({"deployments:read": true});
        assert!(!action_allowed(&p, "secrets:read"));
        assert!(!action_allowed(&p, "roles:write"));
        assert!(!action_allowed(&json!({}), "anything"));
        assert!(!action_allowed(&json!({"foo": "bar"}), "foo")); // non-bool ignored
    }

    #[test]
    fn action_allowed_malformed_is_deny() {
        assert!(!action_allowed(&json!(null), "x"));
        assert!(!action_allowed(&json!(["a"]), "a"));
    }
}
