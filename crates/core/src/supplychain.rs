//! Supply-chain security types shared by the control plane and the agent (Phase C).
//!
//! This module carries the *data* model for Forge's supply-chain differentiator: the
//! enforcement [`SupplyChainPolicy`] and the SLSA-aligned [`SlsaProvenance`] in-toto
//! statement. The actual cosign sign/attest/verify *behavior* lives in the agent
//! (`crates/agent/src/supplychain.rs`); keeping these types in `forge-core` lets both
//! sides agree on the policy on the wire and on the exact provenance shape that gets
//! signed, persisted on the `builds` record, and written into `audit_logs`.
//!
//! Security notes (threat-model `specs/threat-model-source-to-deploy.md`):
//! - No secret material ever lives in these types. The provenance statement is a
//!   public attestation (subject digest + source commit + builder id) — by design it is
//!   safe to persist and log.
//! - The policy default is intentionally strict: when a signing key is configured the
//!   control plane resolves [`SupplyChainPolicy::SignAndRequireVerify`]; only the explicit
//!   absence of a key downgrades to [`SupplyChainPolicy::Disabled`] (with a loud warning,
//!   surfaced by the caller — not here).

use serde::{Deserialize, Serialize};

/// How strictly the supply-chain controls are enforced for a build + its deployment.
///
/// Resolution (see [`SupplyChainPolicy::resolve_default`]): with a cosign key configured the
/// default is [`Self::SignAndRequireVerify`]; with no key it is [`Self::Disabled`]. An operator
/// may pin a weaker/stronger value per application or globally — but a configured key never
/// silently means "off".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SupplyChainPolicy {
    /// Supply-chain enforcement is OFF. Builds are not signed and images are not verified
    /// before run. The control plane logs a loud warning when this is the *resolved* policy
    /// because a key was absent.
    Disabled,
    /// Sign + attest every built image, but do NOT block a run if verification fails or is
    /// impossible. Useful during rollout; the signature still establishes provenance.
    Sign,
    /// Sign + attest, AND verify the signature + provenance before the agent runs/deploys a
    /// Forge-built image. Verification failure → refuse to run (fail-closed, OWASP A10).
    /// This is the secure default whenever a signing key exists.
    #[default]
    SignAndRequireVerify,
}

impl SupplyChainPolicy {
    /// The policy Forge resolves to when no explicit override is configured.
    ///
    /// `has_signing_key` is whether a cosign signing key is available to the build agent
    /// (resolved from `FORGE_COSIGN_KEY` or the secret store). With a key → strict; without
    /// a key → disabled (the caller is expected to emit the "supply-chain enforcement is OFF"
    /// warning so the downgrade is never silent).
    #[must_use]
    pub fn resolve_default(has_signing_key: bool) -> Self {
        if has_signing_key {
            Self::SignAndRequireVerify
        } else {
            Self::Disabled
        }
    }

    /// Whether this policy requires the build agent to sign + attest the produced image.
    #[must_use]
    pub fn requires_signing(self) -> bool {
        matches!(self, Self::Sign | Self::SignAndRequireVerify)
    }

    /// Whether this policy requires the agent to verify signature + provenance before running
    /// a Forge-built image, refusing to run on failure (fail-closed).
    #[must_use]
    pub fn requires_verify(self) -> bool {
        matches!(self, Self::SignAndRequireVerify)
    }

    /// Stable wire/string discriminant (matches the serde `kebab-case` rename and the DB
    /// CHECK constraint values).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Sign => "sign",
            Self::SignAndRequireVerify => "sign-and-require-verify",
        }
    }

    /// Parse the wire/DB discriminant back into a policy. Unknown values fail closed to the
    /// strict default rather than silently disabling enforcement.
    #[must_use]
    pub fn from_str_or_strict(s: &str) -> Self {
        match s {
            "disabled" => Self::Disabled,
            "sign" => Self::Sign,
            _ => Self::SignAndRequireVerify,
        }
    }
}

/// The builder type that produced an image, recorded in provenance so a verifier can reason
/// about *how* the artifact was built. Mirrors the [`crate::spec::Builder`] discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderType {
    Dockerfile,
    Nixpacks,
    Compose,
    Buildpack,
}

impl BuilderType {
    /// Map the rich [`crate::spec::Builder`] to its provenance discriminant.
    #[must_use]
    pub fn from_builder(b: &crate::spec::Builder) -> Self {
        match b {
            crate::spec::Builder::Dockerfile { .. } => Self::Dockerfile,
            crate::spec::Builder::Nixpacks { .. } => Self::Nixpacks,
            crate::spec::Builder::Compose { .. } => Self::Compose,
            crate::spec::Builder::Buildpack { .. } => Self::Buildpack,
        }
    }
}

/// The in-toto/SLSA predicate type URI Forge emits. v1 is provenance-style but Forge-specific
/// (key-based cosign, not keyless/Fulcio), so we use a Forge predicate type rather than claiming
/// full SLSA Build L3.
pub const FORGE_PREDICATE_TYPE: &str = "https://forge.dev/attestations/provenance/v1";

/// The fixed builder identity Forge stamps into provenance. A verifier checks this matches the
/// expected builder before trusting the attestation.
pub const FORGE_BUILDER_ID: &str = "forge-agent";

/// in-toto statement type for the predicate envelope.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// One subject of an in-toto statement: the artifact being attested, keyed by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Human-facing image name (informational; the digest is the cryptographic binding).
    pub name: String,
    /// `{ "sha256": "<hex>" }` — the algorithm-keyed digest, WITHOUT the `sha256:` prefix
    /// (in-toto convention).
    pub digest: std::collections::BTreeMap<String, String>,
}

/// The Forge provenance predicate: who built what, from which source, how, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenancePredicate {
    /// Fixed builder identity (`forge-agent`).
    pub builder_id: String,
    /// Builder type (dockerfile / nixpacks / compose / buildpack).
    pub builder_type: BuilderType,
    /// Source repository URL the build was fetched from.
    pub source_repo: String,
    /// The exact pinned commit SHA the artifact was built from. This is the root of the
    /// commit → image-digest → deployment audit chain.
    pub source_commit: String,
    /// Human-facing branch/tag the commit was resolved from (informational).
    pub source_ref: Option<String>,
    /// RFC3339 build completion timestamp.
    pub built_at: String,
}

/// A complete in-toto statement Forge signs as a cosign attestation. `serde_json` of this is
/// the exact bytes handed to `cosign attest --predicate -`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaProvenance {
    #[serde(rename = "_type")]
    pub statement_type: String,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<Subject>,
    pub predicate: ProvenancePredicate,
}

impl SlsaProvenance {
    /// Build a provenance statement binding `image_digest` (a `sha256:<hex>` reference) to the
    /// source commit + builder. Returns `None` if the digest is not a well-formed
    /// `sha256:<64-hex>` reference — we refuse to attest an artifact we cannot pin by digest.
    #[must_use]
    pub fn new(
        image_name: &str,
        image_digest: &str,
        source_repo: &str,
        source_commit: &str,
        source_ref: Option<&str>,
        builder_type: BuilderType,
        built_at_rfc3339: &str,
    ) -> Option<Self> {
        let (algo, hex) = image_digest.split_once(':')?;
        if algo != "sha256" || hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut digest = std::collections::BTreeMap::new();
        digest.insert(algo.to_string(), hex.to_ascii_lowercase());

        Some(Self {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            predicate_type: FORGE_PREDICATE_TYPE.to_string(),
            subject: vec![Subject {
                name: image_name.to_string(),
                digest,
            }],
            predicate: ProvenancePredicate {
                builder_id: FORGE_BUILDER_ID.to_string(),
                builder_type,
                source_repo: source_repo.to_string(),
                source_commit: source_commit.to_string(),
                source_ref: source_ref.map(str::to_string),
                built_at: built_at_rfc3339.to_string(),
            },
        })
    }

    /// A compact, persistable summary (no secrets) for the `builds.provenance` JSONB column and
    /// the `audit_logs` row. This is what links principal → commit → image digest → deploy.
    #[must_use]
    pub fn summary_json(&self) -> serde_json::Value {
        let digest = self
            .subject
            .first()
            .and_then(|s| s.digest.iter().next())
            .map(|(a, h)| format!("{a}:{h}"));
        serde_json::json!({
            "predicate_type": self.predicate_type,
            "builder_id": self.predicate.builder_id,
            "builder_type": self.predicate.builder_type,
            "source_repo": self.predicate.source_repo,
            "source_commit": self.predicate.source_commit,
            "source_ref": self.predicate.source_ref,
            "image_digest": digest,
            "built_at": self.predicate.built_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_resolution_strict_with_key_disabled_without() {
        assert_eq!(
            SupplyChainPolicy::resolve_default(true),
            SupplyChainPolicy::SignAndRequireVerify
        );
        assert_eq!(
            SupplyChainPolicy::resolve_default(false),
            SupplyChainPolicy::Disabled
        );
    }

    #[test]
    fn policy_capability_flags() {
        assert!(!SupplyChainPolicy::Disabled.requires_signing());
        assert!(!SupplyChainPolicy::Disabled.requires_verify());
        assert!(SupplyChainPolicy::Sign.requires_signing());
        assert!(!SupplyChainPolicy::Sign.requires_verify());
        assert!(SupplyChainPolicy::SignAndRequireVerify.requires_signing());
        assert!(SupplyChainPolicy::SignAndRequireVerify.requires_verify());
    }

    #[test]
    fn policy_string_round_trip_and_unknown_fails_strict() {
        for p in [
            SupplyChainPolicy::Disabled,
            SupplyChainPolicy::Sign,
            SupplyChainPolicy::SignAndRequireVerify,
        ] {
            assert_eq!(SupplyChainPolicy::from_str_or_strict(p.as_str()), p);
        }
        // Unknown / tampered value must NOT silently disable enforcement.
        assert_eq!(
            SupplyChainPolicy::from_str_or_strict("garbage"),
            SupplyChainPolicy::SignAndRequireVerify
        );
        assert_eq!(
            SupplyChainPolicy::from_str_or_strict(""),
            SupplyChainPolicy::SignAndRequireVerify
        );
    }

    #[test]
    fn policy_default_is_strict() {
        assert_eq!(
            SupplyChainPolicy::default(),
            SupplyChainPolicy::SignAndRequireVerify
        );
    }

    #[test]
    fn provenance_shape_carries_digest_commit_and_builder() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let prov = SlsaProvenance::new(
            "registry.example.com/acme/app:abc123",
            &digest,
            "https://github.com/acme/app.git",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            Some("main"),
            BuilderType::Nixpacks,
            "2026-06-02T12:00:00Z",
        )
        .expect("valid digest");

        assert_eq!(prov.statement_type, IN_TOTO_STATEMENT_TYPE);
        assert_eq!(prov.predicate_type, FORGE_PREDICATE_TYPE);
        assert_eq!(prov.predicate.builder_id, FORGE_BUILDER_ID);
        assert_eq!(prov.predicate.builder_type, BuilderType::Nixpacks);
        assert_eq!(
            prov.predicate.source_commit,
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        );
        assert_eq!(
            prov.predicate.source_repo,
            "https://github.com/acme/app.git"
        );

        // Subject is keyed by the algorithm WITHOUT the `sha256:` prefix (in-toto convention).
        let subj = prov.subject.first().unwrap();
        assert_eq!(subj.digest.get("sha256"), Some(&"a".repeat(64)));

        // The on-wire statement serializes with in-toto field names.
        let json = serde_json::to_value(&prov).unwrap();
        assert_eq!(json["_type"], IN_TOTO_STATEMENT_TYPE);
        assert_eq!(json["predicateType"], FORGE_PREDICATE_TYPE);
        assert_eq!(json["subject"][0]["digest"]["sha256"], "a".repeat(64));

        // Summary re-attaches the `sha256:` prefix for storage/audit.
        let summary = prov.summary_json();
        assert_eq!(summary["image_digest"], digest);
        assert_eq!(summary["source_commit"], prov.predicate.source_commit);
    }

    #[test]
    fn provenance_rejects_malformed_digest() {
        // Missing algorithm.
        assert!(
            SlsaProvenance::new(
                "img",
                "deadbeef",
                "https://x/y.git",
                "abc",
                None,
                BuilderType::Dockerfile,
                "2026-06-02T12:00:00Z",
            )
            .is_none()
        );
        // Wrong algorithm.
        assert!(
            SlsaProvenance::new(
                "img",
                &format!("md5:{}", "a".repeat(32)),
                "https://x/y.git",
                "abc",
                None,
                BuilderType::Dockerfile,
                "2026-06-02T12:00:00Z",
            )
            .is_none()
        );
        // Short hex.
        assert!(
            SlsaProvenance::new(
                "img",
                "sha256:abcd",
                "https://x/y.git",
                "abc",
                None,
                BuilderType::Dockerfile,
                "2026-06-02T12:00:00Z",
            )
            .is_none()
        );
    }
}
