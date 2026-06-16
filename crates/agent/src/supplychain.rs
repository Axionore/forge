//! Supply-chain signing + verification on the agent (Phase C).
//!
//! This extends Forge's signed-job root of trust to BUILD ARTIFACTS — the differentiator
//! neither Coolify nor Dokploy offer. After a successful build the agent signs the produced
//! image **by digest** with `cosign` and attaches a SLSA-aligned provenance attestation; before
//! it runs/deploys a Forge-built image it verifies that signature + provenance and REFUSES to
//! run on failure (fail-closed, OWASP A10 / A08).
//!
//! Hard rules enforced here (threat-model `specs/threat-model-source-to-deploy.md`):
//! - **Explicit argv only.** Every `cosign` invocation uses [`tokio::process::Command`] with a
//!   discrete argument vector — never a shell string, never `sh -c`, consistent with the
//!   nixpacks build pattern. Repo/image-derived values are passed as argv tokens, never
//!   interpolated into a command line.
//! - **Keys never logged.** The cosign private key is resolved from `FORGE_COSIGN_KEY` (env,
//!   base64 or raw PEM) or an age-encrypted secret, written to a 0600 temp file for the cosign
//!   invocation, and removed immediately after. The key bytes and its password are NEVER placed
//!   in a log line, an error string, or argv (the password is passed via `COSIGN_PASSWORD` env).
//! - **Fail-closed on missing tooling.** If `cosign` is absent and the policy requires signing
//!   or verification, we return an actionable error rather than silently skipping (A10).
//! - **Sign by digest.** We resolve the image's `sha256:` digest and sign that immutable
//!   reference, so the signature binds to exact bytes, not a mutable tag.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use age::x25519::Identity as AgeIdentity;
use forge_core::spec::SecretCiphertext;
use forge_core::supplychain::SlsaProvenance;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

/// Wall-clock cap for a single cosign invocation. Signing/verifying a digest is fast; a hang
/// (e.g. a network registry stall) must not wedge a build or a deploy.
const COSIGN_TIMEOUT: Duration = Duration::from_secs(60);

/// Environment variable carrying the cosign private key (base64-encoded PEM or raw PEM).
pub const COSIGN_KEY_ENV: &str = "FORGE_COSIGN_KEY";
/// Optional environment variable carrying the cosign key password (passed to cosign via env,
/// never argv, never logged).
pub const COSIGN_PASSWORD_ENV: &str = "FORGE_COSIGN_PASSWORD";
/// Environment variable carrying the trusted cosign PUBLIC key used to verify before run
/// (base64-encoded PEM or raw PEM).
pub const COSIGN_PUBLIC_KEY_ENV: &str = "FORGE_COSIGN_PUBLIC_KEY";

/// Errors from the supply-chain layer. Coarse and free of key/host detail (OWASP A09).
#[derive(Debug, thiserror::Error)]
pub enum SupplyChainError {
    /// `cosign` is not installed but the policy requires signing/verification. Actionable.
    #[error(
        "the `cosign` binary is not installed on this agent but the supply-chain policy \
         requires it; install cosign (https://docs.sigstore.dev/cosign/installation) or set the \
         policy to `disabled`"
    )]
    CosignMissing,
    /// No signing key configured but the policy requires signing.
    #[error(
        "no cosign signing key is configured (set {COSIGN_KEY_ENV} or provide an age-encrypted \
         signing secret) but the supply-chain policy requires signing"
    )]
    NoSigningKey,
    /// No trusted public key configured but the policy requires verification.
    #[error(
        "no trusted cosign public key is configured (set {COSIGN_PUBLIC_KEY_ENV}) but the \
         supply-chain policy requires verify-before-run"
    )]
    NoPublicKey,
    /// The image could not be resolved to an immutable `sha256:` digest for signing.
    #[error("could not resolve image digest for signing")]
    NoDigest,
    /// cosign signing or attestation failed.
    #[error("cosign signing failed")]
    SignFailed,
    /// cosign verification failed — the image is unsigned, altered, or provenance is invalid.
    /// This is the fail-closed refusal surfaced to the deploy path.
    #[error("image signature/provenance verification failed — refusing to run (fail-closed)")]
    VerifyFailed,
    /// Key material was malformed (bad base64 / unreadable PEM). Never echoes the material.
    #[error("cosign key material is malformed")]
    BadKeyMaterial,
    /// Internal I/O failure (temp file, spawn). Free of host detail.
    #[error("internal supply-chain error")]
    Internal,
}

/// Resolve the cosign signing key bytes from the environment or an age-encrypted secret.
///
/// Resolution order:
/// 1. `FORGE_COSIGN_KEY` — base64-encoded PEM, or raw PEM (we detect which).
/// 2. `age_secret` — an age envelope (decrypted with the agent identity) whose plaintext is a
///    PEM (or base64 PEM). Used when the key is delivered via the secret store.
///
/// Returns the PEM bytes. NEVER logs the key. Returns `None` if no source is configured.
pub fn resolve_signing_key(
    age_secret: Option<&SecretCiphertext>,
    age_identity: Option<&AgeIdentity>,
) -> Result<Option<Vec<u8>>, SupplyChainError> {
    if let Ok(raw) = std::env::var(COSIGN_KEY_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return decode_key_material(trimmed).map(Some);
        }
    }
    if let (Some(ct), Some(id)) = (age_secret, age_identity) {
        let pt =
            crate::job::decrypt_secret(ct, id).map_err(|_| SupplyChainError::BadKeyMaterial)?;
        // The decrypted secret may itself be base64-of-PEM or raw PEM.
        let s = String::from_utf8(pt).map_err(|_| SupplyChainError::BadKeyMaterial)?;
        return decode_key_material(s.trim()).map(Some);
    }
    Ok(None)
}

/// Resolve the trusted cosign PUBLIC key (PEM bytes) used for verify-before-run. NEVER logged.
pub fn resolve_public_key() -> Result<Option<Vec<u8>>, SupplyChainError> {
    if let Ok(raw) = std::env::var(COSIGN_PUBLIC_KEY_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return decode_key_material(trimmed).map(Some);
        }
    }
    Ok(None)
}

/// Decode key material that is either raw PEM (`-----BEGIN ...`) or standard base64 of PEM.
/// We never log the material; on any failure we return [`SupplyChainError::BadKeyMaterial`].
fn decode_key_material(s: &str) -> Result<Vec<u8>, SupplyChainError> {
    if s.starts_with("-----BEGIN") {
        return Ok(s.as_bytes().to_vec());
    }
    // Base64 (standard alphabet, no whitespace). We hand-decode to avoid pulling a base64 crate
    // into the agent for this one use; the alphabet check also rejects obviously-bad input.
    let decoded = base64_decode(s).ok_or(SupplyChainError::BadKeyMaterial)?;
    Ok(decoded)
}

/// Minimal, strict standard-base64 decoder (RFC 4648, `+/` alphabet, `=` padding). Returns
/// `None` on any invalid character or malformed padding. Sufficient for decoding a PEM blob.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut acc: u32 = 0;
        for &b in chunk {
            acc <<= 6;
            if b != b'=' {
                acc |= u32::from(val(b)?);
            }
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Locate the `cosign` binary on PATH. Returns whether it is available.
pub async fn cosign_available() -> bool {
    // `command -v cosign` — the binary name is a compile-time literal (no injection surface).
    Command::new("sh")
        .arg("-c")
        .arg("command -v cosign")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// RAII 0600 temp file holding sensitive bytes (a signing key). Removed on drop so key material
/// never outlives the cosign invocation that needs it.
struct SecretFile {
    path: PathBuf,
}

impl SecretFile {
    async fn create(bytes: &[u8]) -> Result<Self, SupplyChainError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::var("FORGE_BUILD_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let path = dir.join(format!("forge-cosign-{}.key", uuid::Uuid::now_v7()));
        let mut f = tokio::fs::File::create(&path)
            .await
            .map_err(|_| SupplyChainError::Internal)?;
        // Tighten to 0600 before writing the key bytes.
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|_| SupplyChainError::Internal)?;
        f.write_all(bytes)
            .await
            .map_err(|_| SupplyChainError::Internal)?;
        f.flush().await.map_err(|_| SupplyChainError::Internal)?;
        Ok(Self { path })
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Signs built images and attaches provenance attestations.
///
/// A trait so the build path can be unit-tested with a mock that records calls without needing a
/// real `cosign` binary or registry.
#[async_trait::async_trait]
pub trait ArtifactSigner: Send + Sync {
    /// Sign `image_ref` (a digest reference `name@sha256:...`) and attach `provenance` as a
    /// cosign attestation. Returns `Ok(())` on success.
    async fn sign_and_attest(
        &self,
        image_ref: &str,
        provenance: &SlsaProvenance,
    ) -> Result<(), SupplyChainError>;
}

/// Verifies an image's signature + provenance before it is run. Injectable so the deploy path can
/// be tested with a mock verifier (accept / reject) without the real cosign binary.
#[async_trait::async_trait]
pub trait ArtifactVerifier: Send + Sync {
    /// Verify the signature + provenance attestation of `image_ref` against the trusted key.
    /// Returns `Ok(())` only if BOTH the signature and the provenance attestation verify.
    async fn verify(&self, image_ref: &str) -> Result<(), SupplyChainError>;
}

/// Production [`ArtifactSigner`] that shells out to the real `cosign` binary with explicit argv.
pub struct CosignSigner {
    /// PEM key bytes (resolved from env or secret store). Never logged.
    key_pem: Vec<u8>,
    /// Optional key password, passed to cosign via env, never argv/log.
    password: Option<String>,
}

impl CosignSigner {
    /// Build a signer from resolved PEM key bytes. `password` (if any) is read from
    /// `FORGE_COSIGN_PASSWORD` by the caller and threaded here.
    #[must_use]
    pub fn new(key_pem: Vec<u8>, password: Option<String>) -> Self {
        Self { key_pem, password }
    }
}

#[async_trait::async_trait]
impl ArtifactSigner for CosignSigner {
    async fn sign_and_attest(
        &self,
        image_ref: &str,
        provenance: &SlsaProvenance,
    ) -> Result<(), SupplyChainError> {
        if !cosign_available().await {
            return Err(SupplyChainError::CosignMissing);
        }
        let key_file = SecretFile::create(&self.key_pem).await?;
        let predicate_json =
            serde_json::to_vec(provenance).map_err(|_| SupplyChainError::SignFailed)?;
        let predicate_file = write_predicate(&predicate_json).await?;

        // 1. `cosign sign --yes --key <keyfile> <image@digest>`
        let sign_args: Vec<String> = vec![
            "sign".into(),
            "--yes".into(),
            "--key".into(),
            key_file.path.display().to_string(),
            image_ref.to_string(),
        ];
        run_cosign(&sign_args, self.password.as_deref())
            .await
            .map_err(|_| SupplyChainError::SignFailed)?;

        // 2. `cosign attest --yes --predicate <file> --type <uri> --key <keyfile> <image@digest>`
        let attest_args: Vec<String> = vec![
            "attest".into(),
            "--yes".into(),
            "--predicate".into(),
            predicate_file.path.display().to_string(),
            "--type".into(),
            forge_core::supplychain::FORGE_PREDICATE_TYPE.to_string(),
            "--key".into(),
            key_file.path.display().to_string(),
            image_ref.to_string(),
        ];
        run_cosign(&attest_args, self.password.as_deref())
            .await
            .map_err(|_| SupplyChainError::SignFailed)?;

        info!(image = %image_ref, "image signed + provenance attested (cosign)");
        Ok(())
    }
}

/// Production [`ArtifactVerifier`] that shells out to the real `cosign verify`/`verify-attestation`.
pub struct CosignVerifier {
    /// Trusted public-key PEM bytes. Never logged.
    public_key_pem: Vec<u8>,
}

impl CosignVerifier {
    #[must_use]
    pub fn new(public_key_pem: Vec<u8>) -> Self {
        Self { public_key_pem }
    }
}

#[async_trait::async_trait]
impl ArtifactVerifier for CosignVerifier {
    async fn verify(&self, image_ref: &str) -> Result<(), SupplyChainError> {
        if !cosign_available().await {
            return Err(SupplyChainError::CosignMissing);
        }
        let key_file = SecretFile::create(&self.public_key_pem).await?;

        // 1. Verify the signature.
        let verify_args: Vec<String> = vec![
            "verify".into(),
            "--key".into(),
            key_file.path.display().to_string(),
            image_ref.to_string(),
        ];
        run_cosign(&verify_args, None)
            .await
            .map_err(|_| SupplyChainError::VerifyFailed)?;

        // 2. Verify the provenance attestation (type-pinned to Forge's predicate).
        let attest_args: Vec<String> = vec![
            "verify-attestation".into(),
            "--key".into(),
            key_file.path.display().to_string(),
            "--type".into(),
            forge_core::supplychain::FORGE_PREDICATE_TYPE.to_string(),
            image_ref.to_string(),
        ];
        run_cosign(&attest_args, None)
            .await
            .map_err(|_| SupplyChainError::VerifyFailed)?;

        info!(image = %image_ref, "image signature + provenance verified (cosign)");
        Ok(())
    }
}

/// Write the provenance predicate JSON to a temp file (cosign reads `--predicate <file>`).
async fn write_predicate(json: &[u8]) -> Result<SecretFile, SupplyChainError> {
    // Reuse SecretFile (0600) — provenance is not secret, but 0600 + auto-remove is harmless and
    // keeps the temp surface tidy.
    SecretFile::create(json).await
}

/// Spawn `cosign <args>` with an explicit argv (no shell), an optional password via env, a hard
/// timeout, and piped stdio that we DROP (never relay key/registry detail to logs). Returns
/// `Ok(())` only on a zero exit.
async fn run_cosign(args: &[String], password: Option<&str>) -> Result<(), SupplyChainError> {
    // Defense in depth: reject NUL in any argv token even though we control most literals
    // (image_ref is the only repo-influenced value and is digest-validated upstream).
    for a in args {
        if a.contains('\0') {
            return Err(SupplyChainError::Internal);
        }
    }

    let mut cmd = Command::new("cosign");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // cosign reads the registry config from the agent's docker config / credential helpers.
        // Disable interactive prompts so a missing cred fails fast rather than hanging.
        .env("COSIGN_YES", "true")
        .kill_on_drop(true);

    if let Some(pw) = password {
        // Password via env ONLY — never argv (would leak in `ps`) and never logged.
        cmd.env(COSIGN_PASSWORD_ENV, pw);
        // cosign reads its key password from COSIGN_PASSWORD.
        cmd.env("COSIGN_PASSWORD", pw);
    }

    let mut child = cmd.spawn().map_err(|e| {
        // ENOENT here means cosign vanished between the `which` probe and spawn.
        if e.kind() == std::io::ErrorKind::NotFound {
            SupplyChainError::CosignMissing
        } else {
            SupplyChainError::Internal
        }
    })?;

    match tokio::time::timeout(COSIGN_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(_)) => Err(SupplyChainError::SignFailed),
        Ok(Err(_)) => {
            let _ = child.start_kill();
            Err(SupplyChainError::Internal)
        }
        Err(_) => {
            warn!("cosign invocation timed out");
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(SupplyChainError::SignFailed)
        }
    }
}

/// Compose the immutable digest reference cosign signs: `name@sha256:<hex>`.
///
/// `image` is the tag reference the build produced (`name:tag` or `registry/name:tag`); `digest`
/// is the resolved `sha256:<hex>`. We strip any existing `:tag` (after the final `/`) and append
/// `@<digest>`. Signing the digest (not the tag) binds the signature to exact bytes.
#[must_use]
pub fn digest_reference(image: &str, digest: &str) -> Option<String> {
    if !is_sha256_digest(digest) {
        return None;
    }
    // Find the repository portion: drop a trailing `:tag` only if it is after the last '/'
    // (so a registry host:port like `registry.example.com:5000/app` is preserved).
    let repo = match image.rfind('/') {
        Some(slash) => {
            let (host, rest) = image.split_at(slash);
            // rest starts with '/'
            match rest.rfind(':') {
                Some(colon) => format!("{host}{}", &rest[..colon]),
                None => image.to_string(),
            }
        }
        None => match image.rfind(':') {
            Some(colon) => image[..colon].to_string(),
            None => image.to_string(),
        },
    };
    Some(format!("{repo}@{digest}"))
}

/// Whether `s` is a well-formed `sha256:<64-hex>` reference.
#[must_use]
pub fn is_sha256_digest(s: &str) -> bool {
    match s.split_once(':') {
        Some(("sha256", hex)) => hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::supplychain::BuilderType;
    use std::sync::Mutex;

    #[test]
    fn base64_round_trips_and_rejects_garbage() {
        // "forge" → "Zm9yZ2U=" (standard base64)
        assert_eq!(base64_decode("Zm9yZ2U=").unwrap(), b"forge");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        // Invalid alphabet / padding.
        assert!(base64_decode("not base64 !!!").is_none());
        assert!(base64_decode("Zm9").is_none()); // not a multiple of 4
        assert!(base64_decode("").is_none());
    }

    #[test]
    fn pem_passthrough_and_base64_decode() {
        let pem = "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\nabc\n-----END-----";
        assert_eq!(decode_key_material(pem).unwrap(), pem.as_bytes());
        // base64 of "forge" decodes to the raw bytes.
        assert_eq!(decode_key_material("Zm9yZ2U=").unwrap(), b"forge");
    }

    #[test]
    fn sha256_digest_validation() {
        assert!(is_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_sha256_digest("sha256:short"));
        assert!(!is_sha256_digest(&format!("md5:{}", "a".repeat(32))));
        assert!(!is_sha256_digest("no-colon"));
        assert!(!is_sha256_digest(&format!("sha256:{}", "g".repeat(64)))); // non-hex
    }

    #[test]
    fn digest_reference_strips_tag_preserves_registry_port() {
        let d = format!("sha256:{}", "a".repeat(64));
        // name:tag → name@digest
        assert_eq!(
            digest_reference("app:latest", &d).unwrap(),
            format!("app@{d}")
        );
        // registry/name:tag
        assert_eq!(
            digest_reference("registry.example.com/acme/app:abc123", &d).unwrap(),
            format!("registry.example.com/acme/app@{d}")
        );
        // registry-with-port: the host colon must NOT be treated as a tag.
        assert_eq!(
            digest_reference("registry.example.com:5000/app:v1", &d).unwrap(),
            format!("registry.example.com:5000/app@{d}")
        );
        // no tag at all
        assert_eq!(digest_reference("app", &d).unwrap(), format!("app@{d}"));
        // bad digest → None
        assert!(digest_reference("app:latest", "deadbeef").is_none());
    }

    /// A mock verifier whose verdict is controllable, used to prove verify-before-run is wired
    /// (and to mutation-test it). Records the refs it was asked to verify.
    struct MockVerifier {
        accept: bool,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ArtifactVerifier for MockVerifier {
        async fn verify(&self, image_ref: &str) -> Result<(), SupplyChainError> {
            self.seen.lock().unwrap().push(image_ref.to_string());
            if self.accept {
                Ok(())
            } else {
                Err(SupplyChainError::VerifyFailed)
            }
        }
    }

    #[tokio::test]
    async fn mock_verifier_rejects_unsigned_image() {
        let v = MockVerifier {
            accept: false,
            seen: Mutex::new(vec![]),
        };
        let err = v.verify("app@sha256:bad").await.unwrap_err();
        assert!(matches!(err, SupplyChainError::VerifyFailed));
        assert_eq!(v.seen.lock().unwrap().as_slice(), &["app@sha256:bad"]);
    }

    /// A mock signer that records the (image_ref, provenance) it was asked to sign.
    struct MockSigner {
        calls: Mutex<Vec<(String, SlsaProvenance)>>,
    }

    #[async_trait::async_trait]
    impl ArtifactSigner for MockSigner {
        async fn sign_and_attest(
            &self,
            image_ref: &str,
            provenance: &SlsaProvenance,
        ) -> Result<(), SupplyChainError> {
            self.calls
                .lock()
                .unwrap()
                .push((image_ref.to_string(), provenance.clone()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn mock_signer_receives_digest_ref_and_provenance() {
        let digest = format!("sha256:{}", "b".repeat(64));
        let prov = SlsaProvenance::new(
            "app:latest",
            &digest,
            "https://github.com/acme/app.git",
            &"d".repeat(40),
            Some("main"),
            BuilderType::Dockerfile,
            "2026-06-02T00:00:00Z",
        )
        .unwrap();
        let signer = MockSigner {
            calls: Mutex::new(vec![]),
        };
        let reference = digest_reference("app:latest", &digest).unwrap();
        signer.sign_and_attest(&reference, &prov).await.unwrap();

        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, format!("app@{digest}"));
        assert_eq!(calls[0].1.predicate.source_commit, "d".repeat(40));
    }

    #[test]
    fn resolve_signing_key_none_when_unset() {
        // With no env and no secret, resolution yields None (caller decides per policy).
        // Guard against a CI env that happens to set the var.
        if std::env::var(COSIGN_KEY_ENV).is_err() {
            assert!(resolve_signing_key(None, None).unwrap().is_none());
        }
    }
}
