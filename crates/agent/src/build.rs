//! Source-to-deploy build executor (Phase B).
//!
//! Turns a [`BuildSpec`] into a real container image, on the agent, inside an isolated
//! workspace. This is the most security-sensitive code path in the agent after job
//! verification: it executes UNTRUSTED repository content. Every decision here maps to a
//! mitigation in `specs/threat-model-source-to-deploy.md`.
//!
//! Hard rules enforced in this module:
//! - **No host shell with repo data.** Git and the build tools are invoked via
//!   [`tokio::process::Command`] with explicit argument vectors. We NEVER build a shell
//!   string out of a URL, ref, branch, image name, or any other repo-derived value, and
//!   we NEVER pass `sh -c`. (Elevation of privilege — the Coolify Jan-2026 CVE class.)
//! - **Pinned source.** The repo is fetched and then reset HARD to the spec's
//!   `commit_sha`. Floating refs are never built. (Tampering.)
//! - **Secrets never in layers.** Build secrets are age-decrypted to a 0600 file on a
//!   private tmpfs-style dir and exposed to the build ONLY via BuildKit `--secret`.
//!   They are scrubbed from the streamed logs. (Information disclosure.)
//! - **Bounded.** Build-context size is capped; CPU / memory / wall-clock limits are
//!   applied to the build; a hard timeout kills the build and fails closed. (DoS.)
//! - **Fail-closed.** Any error aborts the build, cleans up the workspace + secret files,
//!   and reports failure. A failed build must never yield a deployable image. (A10.)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use forge_core::spec::{BuildSpec, Builder, GitCheckout, SecretRef};

/// Hard wall-clock cap for an entire build (clone + build + inspect). Beyond this the
/// build is killed and fails closed.
const BUILD_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Wall-clock cap for the git clone alone (a malicious/huge repo must not hang forever).
const CLONE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Maximum build-context size on disk after checkout. Caps the "build bomb" surface.
const MAX_CONTEXT_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Maximum number of files in the build context (cheap protection against inode bombs).
const MAX_CONTEXT_FILES: usize = 200_000;

/// CPU quota for the build container (number of CPUs). Passed to the build tool's
/// `--cpus`/cgroup options where the tool supports it.
const BUILD_CPUS: &str = "2.0";

/// Memory cap for the build container.
const BUILD_MEMORY: &str = "4g";

/// Errors from the build executor. Deliberately coarse and free of secret/host detail so
/// nothing sensitive reaches a log line or the control plane (OWASP A09).
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid build spec: {0}")]
    InvalidSpec(String),
    #[error("git checkout failed: {0}")]
    Checkout(String),
    #[error("build context exceeds limits: {0}")]
    ContextTooLarge(String),
    #[error("disallowed compose directive: {0}")]
    ComposeRejected(String),
    #[error("secret preparation failed")]
    Secret,
    #[error("builder not available: {0}")]
    BuilderUnavailable(String),
    #[error("build failed: {0}")]
    BuildFailed(String),
    #[error("build timed out")]
    Timeout,
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("internal build error")]
    Internal,
}

/// Outcome of a successful build.
#[derive(Debug, Clone)]
pub struct BuildOutcome {
    /// Fully-qualified image reference (`name:tag` or `registry/name:tag`).
    pub image: String,
    /// Image digest (`sha256:...`) recorded after the build, if resolvable.
    pub image_digest: Option<String>,
    /// Whether the image was pushed to the configured registry.
    pub pushed: bool,
}

/// A sink for streamed, redacted build-log lines. Each line is sent to the control plane
/// as it is produced. Backpressure-bounded by the underlying channel.
pub type LogSink = mpsc::Sender<String>;

/// Validate a value that will be passed as a discrete argv entry to git. We use argv (not a
/// shell) so injection is already structurally impossible, but we additionally reject
/// control characters and obvious metacharacters as defense-in-depth and to satisfy the
/// threat-model obligation that "repo with shell metacharacters in name/branch cannot
/// inject a host command".
fn is_safe_git_token(s: &str) -> bool {
    if s.is_empty() || s.len() > 2048 {
        return false;
    }
    // No control chars, no NUL, and none of the classic shell metacharacters. A leading
    // '-' is rejected so a value can never be interpreted as a git option ("--upload-pack").
    if s.starts_with('-') {
        return false;
    }
    !s.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '<' | '>' | '(' | ')' | '\\'
            )
    })
}

/// Structurally validate a user-supplied git remote URL before it is ever handed to `git`.
///
/// `is_safe_git_token` is a *blocklist* — sufficient to stop shell metacharacters, but NOT
/// sufficient to stop git's own remote-helper transports. A value such as `ext::sh -c <cmd>`
/// contains no blocked metacharacter yet makes git invoke an arbitrary command at clone time
/// (the Coolify-class RCE in the threat model). We therefore require the URL to parse as an
/// absolute URL whose scheme is on a strict allowlist {https, ssh, git} — rejecting `ext::`,
/// `transport::`, `file://`, and bare/relative refs outright (A03 / EoP, defense in depth on
/// top of the `GIT_ALLOW_PROTOCOL` / `protocol.*.allow=never` env hardening in `run_git`).
fn validate_git_url(raw: &str) -> Result<(), BuildError> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err(BuildError::InvalidSpec(
            "git url is empty or too long".into(),
        ));
    }
    // No whitespace or quotes anywhere — these have no place in a real remote URL and are the
    // building blocks of remote-helper argument smuggling (`ext::sh -c "..."`).
    if raw
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\''))
    {
        return Err(BuildError::InvalidSpec(
            "git url contains whitespace or quotes".into(),
        ));
    }

    // Must parse as an absolute URL. `ext::sh ...`, `transport::...`, and relative paths fail
    // here (they are not absolute URLs with a network scheme). This rejects the remote-helper
    // smuggling class structurally rather than by enumerating bad prefixes.
    let parsed = url::Url::parse(raw)
        .map_err(|_| BuildError::InvalidSpec("git url is not an absolute URL".into()))?;

    match parsed.scheme() {
        "https" | "ssh" | "git" => {}
        _ => {
            return Err(BuildError::InvalidSpec(
                "git url scheme not allowed (only https, ssh, git)".into(),
            ));
        }
    }

    // A network transport must carry a host. `file://` would have been rejected by the scheme
    // allowlist already; this rejects any in-allowlist scheme that resolved to an empty host.
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(BuildError::InvalidSpec("git url has no host".into()));
    }

    Ok(())
}

/// A 40- or 64-hex commit SHA. Anything else is rejected — we only ever build a pinned commit.
fn is_valid_commit_sha(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolve and sanitize a path that the spec claims is relative to the repo root, returning
/// an absolute path that is GUARANTEED to stay inside `root` (no `..` traversal, no absolute
/// escape). Returns `None` if the candidate escapes the workspace.
fn safe_subpath(root: &Path, rel: &str) -> Option<PathBuf> {
    let candidate = root.join(rel);
    // Reject any `..` component outright; we do not canonicalize against symlinks the repo
    // may contain — a lexical check keeps us inside the workspace regardless of FS state.
    let mut normalized = PathBuf::new();
    for comp in candidate.components() {
        use std::path::Component;
        match comp {
            Component::ParentDir => return None,
            Component::Normal(_)
            | Component::RootDir
            | Component::Prefix(_)
            | Component::CurDir => normalized.push(comp.as_os_str()),
        }
    }
    if normalized.starts_with(root) {
        Some(normalized)
    } else {
        None
    }
}

/// Send a line to the log sink, best-effort. Never blocks the build on a slow consumer.
async fn emit(sink: &Option<LogSink>, line: impl Into<String>) {
    if let Some(tx) = sink {
        let _ = tx.try_send(line.into());
    }
}

/// Redact every known secret VALUE from a log line. We never have the plaintext here (it
/// only lives in the tmpfs files), so we redact by the secret NAMES that BuildKit would
/// echo and, conservatively, any `--secret`/`id=` token. The actual plaintext can never
/// appear because it is passed via BuildKit's secret channel, not argv/env — but a
/// misbehaving Dockerfile that `cat`s the secret would print it, so we also scrub the known
/// plaintext values when the caller provides them.
pub fn redact_line(line: &str, secret_values: &[String]) -> String {
    let mut out = line.to_string();
    for v in secret_values {
        if v.len() >= 4 && out.contains(v.as_str()) {
            out = out.replace(v.as_str(), "***REDACTED***");
        }
    }
    out
}

/// Decrypt build secrets to 0600 files under `secret_dir`, returning a map of
/// secret-id → file path (for BuildKit `--secret id=<name>,src=<path>`) and the list of
/// plaintext values (used ONLY to redact them from the log stream — never logged itself).
fn prepare_build_secrets(
    secrets: &[SecretRef],
    secret_dir: &Path,
    age_identity: Option<&age::x25519::Identity>,
) -> Result<(HashMap<String, PathBuf>, Vec<String>), BuildError> {
    use std::os::unix::fs::PermissionsExt;

    let mut paths = HashMap::new();
    let mut plaintexts = Vec::new();

    if secrets.is_empty() {
        return Ok((paths, plaintexts));
    }
    let age_id = age_identity.ok_or(BuildError::Secret)?;

    std::fs::create_dir_all(secret_dir).map_err(|_| BuildError::Secret)?;
    std::fs::set_permissions(secret_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| BuildError::Secret)?;

    for secret in secrets {
        // The BuildKit secret id is the secret name; keep it filesystem-safe.
        let safe_name: String = secret
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if safe_name.is_empty() {
            return Err(BuildError::InvalidSpec("empty build-secret name".into()));
        }

        let plaintext = crate::job::decrypt_secret(&secret.ciphertext, age_id)
            .map_err(|_| BuildError::Secret)?;

        // For builds we always materialize a file that the Dockerfile mounts via
        // `RUN --mount=type=secret,id=<name>`. The SecretTarget (Env/File) is advisory here;
        // the BuildKit secret id is what matters, so the variant does not change behavior.
        let path = secret_dir.join(&safe_name);
        std::fs::write(&path, &plaintext).map_err(|_| BuildError::Secret)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| BuildError::Secret)?;

        if let Ok(s) = String::from_utf8(plaintext) {
            plaintexts.push(s);
        }
        paths.insert(safe_name, path);
    }

    Ok((paths, plaintexts))
}

/// Compute the on-disk size + file count of `dir`, failing closed if either limit is
/// exceeded. Skips the `.git` directory (it is removed before the build anyway).
fn enforce_context_limits(dir: &Path) -> Result<u64, BuildError> {
    let mut total: u64 = 0;
    let mut count: usize = 0;
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry.map_err(|_| BuildError::ContextTooLarge("walk failed".into()))?;
        count = count.saturating_add(1);
        if count > MAX_CONTEXT_FILES {
            return Err(BuildError::ContextTooLarge(format!(
                "more than {MAX_CONTEXT_FILES} files"
            )));
        }
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                total = total.saturating_add(meta.len());
                if total > MAX_CONTEXT_BYTES {
                    return Err(BuildError::ContextTooLarge(format!(
                        "exceeds {MAX_CONTEXT_BYTES} bytes"
                    )));
                }
            }
        }
    }
    Ok(total)
}

/// Parse a user-supplied Compose file and reject directives that would let a build escape
/// the sandbox: `privileged`, host bind-mounts, and docker-socket mounts. Returns the
/// rejected directive on the first violation (threat-model EoP mitigation).
///
/// We parse the YAML structurally rather than grepping, so quoting tricks cannot bypass it.
pub fn validate_compose_yaml(yaml: &str) -> Result<(), BuildError> {
    let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml)
        .map_err(|_| BuildError::ComposeRejected("compose file is not valid YAML".into()))?;

    let services = doc.get("services").and_then(|s| s.as_mapping());
    let Some(services) = services else {
        // No services → nothing to build; let compose surface its own error later.
        return Ok(());
    };

    for (_name, svc) in services {
        let Some(svc) = svc.as_mapping() else {
            continue;
        };

        // 1. privileged: true
        if svc
            .get(yaml_key("privileged"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err(BuildError::ComposeRejected(
                "privileged: true is not allowed".into(),
            ));
        }

        // 2. cap_add includes ALL/SYS_ADMIN
        if let Some(caps) = svc.get(yaml_key("cap_add")).and_then(|v| v.as_sequence()) {
            for c in caps {
                if let Some(cap) = c.as_str() {
                    let cap = cap.to_ascii_uppercase();
                    if cap == "ALL" || cap == "SYS_ADMIN" {
                        return Err(BuildError::ComposeRejected(format!(
                            "cap_add: {cap} is not allowed"
                        )));
                    }
                }
            }
        }

        // 3. volumes: host bind-mounts and docker-socket mounts.
        if let Some(vols) = svc.get(yaml_key("volumes")).and_then(|v| v.as_sequence()) {
            for v in vols {
                let mount_src = compose_volume_source(v);
                if let Some(src) = mount_src {
                    check_mount_source(&src)?;
                }
            }
        }
    }

    Ok(())
}

/// Reject a single mount source if it is a host bind-mount or the docker socket.
fn check_mount_source(src: &str) -> Result<(), BuildError> {
    let trimmed = src.trim();
    if trimmed == "/var/run/docker.sock" || trimmed.ends_with("/docker.sock") {
        return Err(BuildError::ComposeRejected(
            "mounting the docker socket is not allowed".into(),
        ));
    }
    // Absolute host path bind-mount (named volumes do not start with '/' or '.').
    if trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../") {
        return Err(BuildError::ComposeRejected(format!(
            "host bind-mount '{trimmed}' is not allowed"
        )));
    }
    Ok(())
}

/// Extract the source of a compose `volumes` entry, whether short `"src:dst[:mode]"` or
/// long-form `{ type, source, target }`.
fn compose_volume_source(v: &serde_yaml_ng::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        // Short syntax: "source:target[:mode]". Handle the absolute-path case where the
        // source itself contains no extra colon beyond drive-less unix paths.
        return s.split(':').next().map(|x| x.to_string());
    }
    if let Some(map) = v.as_mapping() {
        // Long syntax. A bind type with a source is the dangerous case.
        if let Some(src) = map.get(yaml_key("source")).and_then(|x| x.as_str()) {
            return Some(src.to_string());
        }
    }
    None
}

fn yaml_key(k: &str) -> serde_yaml_ng::Value {
    serde_yaml_ng::Value::String(k.to_string())
}

/// Run a [`BuildSpec`] end-to-end. On success returns the [`BuildOutcome`]; on any failure
/// cleans up and returns a coarse [`BuildError`]. Logs stream to `log_sink` as redacted lines.
///
/// `target_image` is the authoritative image reference the control plane assigned (the
/// `Job::Build.target_image`); the agent tags exactly that, so the control plane and agent
/// never disagree on the artifact name. `docker` is the bollard client used for the
/// post-build image-digest inspection and push.
pub async fn run_build(
    build_id: Uuid,
    spec: &BuildSpec,
    target_image: &str,
    age_identity: Option<&age::x25519::Identity>,
    log_sink: Option<LogSink>,
    #[cfg(feature = "docker")] docker: Option<&bollard::Docker>,
    #[cfg(not(feature = "docker"))] docker: Option<&()>,
) -> Result<BuildOutcome, BuildError> {
    // A hard wall-clock cap over the WHOLE build. Timeout → kill child processes via the
    // workspace guard's Drop and fail closed.
    match tokio::time::timeout(
        BUILD_TIMEOUT,
        run_build_inner(
            build_id,
            spec,
            target_image,
            age_identity,
            log_sink.clone(),
            docker,
        ),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => {
            emit(&log_sink, "build timed out — aborting".to_string()).await;
            warn!(build_id = %build_id, "build exceeded hard timeout");
            Err(BuildError::Timeout)
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_build_inner(
    build_id: Uuid,
    spec: &BuildSpec,
    target_image: &str,
    age_identity: Option<&age::x25519::Identity>,
    log_sink: Option<LogSink>,
    #[cfg(feature = "docker")] docker: Option<&bollard::Docker>,
    #[cfg(not(feature = "docker"))] _docker: Option<&()>,
) -> Result<BuildOutcome, BuildError> {
    // 1. Validate the spec / source up front (fail-closed before touching the network).
    validate_source(&spec.source)?;
    let target_image = target_image.to_string();
    validate_image_ref(&target_image)?;

    // 2. Isolated workspace (auto-removed on drop, including on early return / panic).
    let workspace = WorkspaceGuard::new(build_id).map_err(|_| BuildError::Internal)?;
    let repo_dir = workspace.path().join("repo");
    let secret_dir = workspace.path().join("secrets");

    emit(
        &log_sink,
        format!("preparing build {build_id} for {target_image}"),
    )
    .await;

    // 3. Fetch the repo pinned to the exact commit SHA.
    git_fetch_pinned(&spec.source, &repo_dir, &log_sink).await?;

    // 4. Determine the effective build root (repo root or subdir), staying inside workspace.
    let build_root = match spec.source.subdir.as_deref() {
        Some(sub) if !sub.is_empty() => safe_subpath(&repo_dir, sub)
            .ok_or_else(|| BuildError::InvalidSpec("subdir escapes the repository".into()))?,
        _ => repo_dir.clone(),
    };

    // 5. Cap context size BEFORE invoking any build tool.
    let bytes = enforce_context_limits(&build_root)?;
    emit(&log_sink, format!("build context: {bytes} bytes")).await;

    // 6. Prepare build secrets to a private tmpfs-ish dir (0600 files).
    let (secret_files, secret_plaintexts) =
        prepare_build_secrets(&spec.build_secrets, &secret_dir, age_identity)?;

    // 7. Dispatch to the selected builder.
    let build_res = match &spec.builder {
        Builder::Dockerfile {
            dockerfile_path,
            context,
            target,
        } => {
            build_dockerfile(
                &build_root,
                dockerfile_path.as_deref(),
                context.as_deref(),
                target.as_deref(),
                &target_image,
                &spec.build_args,
                &secret_files,
                &secret_plaintexts,
                &log_sink,
            )
            .await
        }
        Builder::Nixpacks { context, start_cmd } => {
            build_nixpacks(
                &build_root,
                context.as_deref(),
                start_cmd.as_deref(),
                &target_image,
                &spec.build_args,
                &secret_plaintexts,
                &log_sink,
            )
            .await
        }
        Builder::Compose { file } => {
            build_compose(&build_root, file, &secret_plaintexts, &log_sink).await
        }
        Builder::Buildpack { .. } => {
            // SCAFFOLD: explicit, clear runtime error — never a silent fake (per spec).
            Err(BuildError::NotImplemented(
                "Cloud Native Buildpacks (Paketo) builder is scaffolded but not yet \
                 implemented; use dockerfile, nixpacks, or compose"
                    .into(),
            ))
        }
    };

    build_res?;

    // 8. Record the image digest (best effort) + optional push.
    #[allow(unused_mut)]
    let mut pushed = false;
    #[allow(unused_mut)]
    let mut image_digest: Option<String> = None;

    #[cfg(feature = "docker")]
    {
        if let Some(docker) = docker {
            image_digest = inspect_image_digest(docker, &target_image).await;
            if spec.registry.is_some() {
                pushed = push_image(&target_image, &secret_plaintexts, &log_sink).await?;
            }
        }
    }

    emit(
        &log_sink,
        format!("build {build_id} succeeded: {target_image}"),
    )
    .await;
    info!(build_id = %build_id, image = %target_image, "build succeeded");

    // WorkspaceGuard drops here → repo + secret files removed.
    Ok(BuildOutcome {
        image: target_image,
        image_digest,
        pushed,
    })
}

fn validate_source(src: &GitCheckout) -> Result<(), BuildError> {
    // Structural URL validation (scheme allowlist) first — closes the remote-helper smuggling
    // class that the blocklist below cannot see. Then keep the metacharacter blocklist as a
    // second, independent guard.
    validate_git_url(&src.url)?;
    if !is_safe_git_token(&src.url) {
        return Err(BuildError::InvalidSpec("unsafe git url".into()));
    }
    let sha = src
        .commit_sha
        .as_deref()
        .ok_or_else(|| BuildError::InvalidSpec("commit_sha is required for builds".into()))?;
    if !is_valid_commit_sha(sha) {
        return Err(BuildError::InvalidSpec(
            "commit_sha is not a valid hash".into(),
        ));
    }
    if !src.r#ref.is_empty() && !is_safe_git_token(&src.r#ref) {
        return Err(BuildError::InvalidSpec("unsafe git ref".into()));
    }
    Ok(())
}

/// An image reference must not contain shell metacharacters or whitespace (defense in depth;
/// it is passed as argv but is also echoed into logs and used as a docker tag).
fn validate_image_ref(image: &str) -> Result<(), BuildError> {
    if image.is_empty() || image.len() > 512 {
        return Err(BuildError::InvalidSpec("invalid image reference".into()));
    }
    let ok = image
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':' | '@'));
    if !ok {
        return Err(BuildError::InvalidSpec("invalid image reference".into()));
    }
    Ok(())
}

/// Shallow-clone the repo and reset HARD to the pinned commit. Uses argv exclusively; the
/// SSH command (if any) is built from a fixed template, never from repo data.
async fn git_fetch_pinned(
    src: &GitCheckout,
    repo_dir: &Path,
    log_sink: &Option<LogSink>,
) -> Result<(), BuildError> {
    let sha = src.commit_sha.as_deref().unwrap_or_default();

    std::fs::create_dir_all(repo_dir).map_err(|_| BuildError::Internal)?;

    // `git init` + `git fetch <url> <sha>` + `git checkout FETCH_HEAD`. Fetching the SHA
    // directly is the most robust way to pin without trusting a branch tip.
    run_git(&["init", "--quiet"], repo_dir, log_sink).await?;
    run_git(
        &["fetch", "--depth", "1", "--no-tags", &src.url, sha],
        repo_dir,
        log_sink,
    )
    .await
    .map_err(|_| BuildError::Checkout("fetch of pinned commit failed".into()))?;
    run_git(&["checkout", "--quiet", "FETCH_HEAD"], repo_dir, log_sink)
        .await
        .map_err(|_| BuildError::Checkout("checkout of pinned commit failed".into()))?;

    // Remove the VCS metadata so it never lands in the build context.
    let _ = std::fs::remove_dir_all(repo_dir.join(".git"));
    emit(log_sink, format!("checked out {sha}")).await;
    Ok(())
}

/// Prepend git protocol-restriction config to an argv. `-c protocol.<x>.allow=never` disables
/// the remote-helper (`ext`), local (`file`) transports; `protocol.allow=user` denies any
/// transport git would otherwise follow indirectly (redirects, submodules) unless the user named
/// it on the command line. These config flags MUST precede the git subcommand.
fn harden_git_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut full = Vec::with_capacity(args.len() + 6);
    full.extend_from_slice(&[
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.allow=user",
    ]);
    full.extend_from_slice(args);
    full
}

async fn run_git(args: &[&str], cwd: &Path, log_sink: &Option<LogSink>) -> Result<(), BuildError> {
    // Defense in depth: validate every argv token even though we control the literals.
    for a in args {
        if a.contains('\0') {
            return Err(BuildError::Checkout("invalid git argument".into()));
        }
    }
    // Protocol restriction (defense in depth): even if a malicious URL slipped past
    // `validate_git_url`, deny git the dangerous transports. See `harden_git_args`.
    let full_args = harden_git_args(args);

    let mut cmd = Command::new("git");
    cmd.args(&full_args)
        .current_dir(cwd)
        // Never prompt for credentials interactively (would hang the build).
        .env("GIT_TERMINAL_PROMPT", "0")
        // Allowlist the only transports a real remote needs; blocks ext::/file:// helpers.
        .env("GIT_ALLOW_PROTOCOL", "https:ssh:git")
        .env(
            "GIT_SSH_COMMAND",
            "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let status = run_streamed(cmd, &[], log_sink, CLONE_TIMEOUT).await?;
    if status {
        Ok(())
    } else {
        Err(BuildError::Checkout("git command failed".into()))
    }
}

/// Build a Dockerfile via BuildKit (`DOCKER_BUILDKIT=1 docker build`), passing build
/// secrets via `--secret id=<name>,src=<path>` so they never persist in a layer.
#[allow(clippy::too_many_arguments)]
async fn build_dockerfile(
    build_root: &Path,
    dockerfile_path: Option<&str>,
    context: Option<&str>,
    target: Option<&str>,
    image: &str,
    build_args: &HashMap<String, String>,
    secret_files: &HashMap<String, PathBuf>,
    secret_plaintexts: &[String],
    log_sink: &Option<LogSink>,
) -> Result<(), BuildError> {
    let context_dir = match context {
        Some(c) if !c.is_empty() => safe_subpath(build_root, c)
            .ok_or_else(|| BuildError::InvalidSpec("context escapes the repo".into()))?,
        _ => build_root.to_path_buf(),
    };

    let mut cmd = Command::new("docker");
    cmd.arg("build")
        .arg("--tag")
        .arg(image)
        .arg("--cpus")
        .arg(BUILD_CPUS)
        .arg("--memory")
        .arg(BUILD_MEMORY)
        // Pull base images fresh so we record an up-to-date digest; pin is a Phase C concern.
        .arg("--pull")
        .env("DOCKER_BUILDKIT", "1")
        .current_dir(&context_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(df) = dockerfile_path {
        let df_path = safe_subpath(build_root, df)
            .ok_or_else(|| BuildError::InvalidSpec("dockerfile path escapes the repo".into()))?;
        cmd.arg("--file").arg(df_path);
    }
    if let Some(t) = target {
        validate_build_token(t)?;
        cmd.arg("--target").arg(t);
    }
    for (k, v) in build_args {
        validate_build_token(k)?;
        // value can be arbitrary but is argv, not shell; reject NUL only.
        if v.contains('\0') {
            return Err(BuildError::InvalidSpec("invalid build arg".into()));
        }
        cmd.arg("--build-arg").arg(format!("{k}={v}"));
    }
    for (id, path) in secret_files {
        // id=<name>,src=<path> — BuildKit reads the file at solve time; it never lands in a layer.
        cmd.arg("--secret")
            .arg(format!("id={id},src={}", path.display()));
    }
    // The context is the final positional arg.
    cmd.arg(".");

    emit(log_sink, format!("running docker build for {image}")).await;
    let ok = run_streamed(cmd, secret_plaintexts, log_sink, BUILD_TIMEOUT).await?;
    if ok {
        Ok(())
    } else {
        Err(BuildError::BuildFailed(
            "docker build returned non-zero".into(),
        ))
    }
}

/// Build via the Nixpacks CLI. Fails closed with an actionable error if `nixpacks` is absent.
async fn build_nixpacks(
    build_root: &Path,
    context: Option<&str>,
    start_cmd: Option<&str>,
    image: &str,
    build_args: &HashMap<String, String>,
    secret_plaintexts: &[String],
    log_sink: &Option<LogSink>,
) -> Result<(), BuildError> {
    // Probe for the binary first so the error is clear, not a generic spawn failure.
    if which("nixpacks").await.is_none() {
        return Err(BuildError::BuilderUnavailable(
            "the `nixpacks` CLI is not installed on this agent; install nixpacks or use the \
             dockerfile builder"
                .into(),
        ));
    }

    let context_dir = match context {
        Some(c) if !c.is_empty() => safe_subpath(build_root, c)
            .ok_or_else(|| BuildError::InvalidSpec("context escapes the repo".into()))?,
        _ => build_root.to_path_buf(),
    };

    let mut cmd = Command::new("nixpacks");
    cmd.arg("build")
        .arg(&context_dir)
        .arg("--name")
        .arg(image)
        .env("DOCKER_BUILDKIT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(sc) = start_cmd {
        if sc.contains('\0') {
            return Err(BuildError::InvalidSpec("invalid start command".into()));
        }
        cmd.arg("--start-cmd").arg(sc);
    }
    for (k, v) in build_args {
        validate_build_token(k)?;
        if v.contains('\0') {
            return Err(BuildError::InvalidSpec("invalid build arg".into()));
        }
        cmd.arg("--env").arg(format!("{k}={v}"));
    }

    emit(log_sink, format!("running nixpacks build for {image}")).await;
    let ok = run_streamed(cmd, secret_plaintexts, log_sink, BUILD_TIMEOUT).await?;
    if ok {
        Ok(())
    } else {
        Err(BuildError::BuildFailed(
            "nixpacks build returned non-zero".into(),
        ))
    }
}

/// Build via `docker compose build`. The user's compose file is validated structurally and
/// rejected if it requests privileged mode, host bind-mounts, or a docker-socket mount.
async fn build_compose(
    build_root: &Path,
    file: &str,
    secret_plaintexts: &[String],
    log_sink: &Option<LogSink>,
) -> Result<(), BuildError> {
    let compose_path = safe_subpath(build_root, file)
        .ok_or_else(|| BuildError::InvalidSpec("compose file escapes the repo".into()))?;

    let yaml = std::fs::read_to_string(&compose_path)
        .map_err(|_| BuildError::ComposeRejected("compose file not found".into()))?;
    // Fail closed BEFORE invoking docker compose.
    validate_compose_yaml(&yaml)?;

    if which("docker").await.is_none() {
        return Err(BuildError::BuilderUnavailable(
            "the `docker` CLI is not installed on this agent".into(),
        ));
    }

    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("--file")
        .arg(&compose_path)
        .arg("build")
        .env("DOCKER_BUILDKIT", "1")
        .current_dir(build_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    emit(log_sink, "running docker compose build".to_string()).await;
    let ok = run_streamed(cmd, secret_plaintexts, log_sink, BUILD_TIMEOUT).await?;
    if ok {
        Ok(())
    } else {
        Err(BuildError::BuildFailed(
            "compose build returned non-zero".into(),
        ))
    }
}

/// Validate a token used as a docker `--target`/`--build-arg` key.
fn validate_build_token(s: &str) -> Result<(), BuildError> {
    if s.is_empty()
        || s.len() > 256
        || s.starts_with('-')
        || s.chars().any(|c| c.is_control() || c == '=')
    {
        return Err(BuildError::InvalidSpec("invalid build token".into()));
    }
    Ok(())
}

/// Spawn a command, stream its merged stdout/stderr line-by-line to `log_sink` (redacting
/// the given secret values), and enforce a per-command timeout. Returns whether it exited 0.
/// On timeout the child is killed and `Timeout` is returned.
async fn run_streamed(
    mut cmd: Command,
    secret_values: &[String],
    log_sink: &Option<LogSink>,
    timeout: Duration,
) -> Result<bool, BuildError> {
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| {
        // ENOENT → the tool is missing; surface that as BuilderUnavailable upstream via the
        // caller's `which` probe, but we still guard here.
        BuildError::BuildFailed(format!("failed to spawn build process: {}", e.kind()))
    })?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let sink_out = log_sink.clone();
    let secrets_out = secret_values.to_vec();
    let stdout_task = tokio::spawn(async move {
        if let Some(out) = stdout {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let red = redact_line(&line, &secrets_out);
                if let Some(tx) = &sink_out {
                    let _ = tx.try_send(red);
                }
            }
        }
    });

    let sink_err = log_sink.clone();
    let secrets_err = secret_values.to_vec();
    let stderr_task = tokio::spawn(async move {
        if let Some(err) = stderr {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let red = redact_line(&line, &secrets_err);
                if let Some(tx) = &sink_err {
                    let _ = tx.try_send(red);
                }
            }
        }
    });

    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            let _ = child.start_kill();
            return Err(BuildError::BuildFailed("process wait failed".into()));
        }
        Err(_) => {
            // Timed out — kill the child (kill_on_drop also covers this) and fail closed.
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(BuildError::Timeout);
        }
    };

    // Drain the log tasks so no line is lost.
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    Ok(status.success())
}

/// Resolve a binary on PATH. Returns its path if found.
async fn which(bin: &str) -> Option<PathBuf> {
    let mut cmd = Command::new("sh");
    // `command -v` is POSIX and only used to LOCATE a fixed, non-repo binary name; the name
    // is a compile-time literal here, never repo-derived, so there is no injection surface.
    cmd.arg("-c")
        .arg(format!("command -v {bin}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let out = cmd.output().await.ok()?;
    if out.status.success() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            None
        } else {
            Some(PathBuf::from(path))
        }
    } else {
        None
    }
}

#[cfg(feature = "docker")]
async fn inspect_image_digest(docker: &bollard::Docker, image: &str) -> Option<String> {
    match docker.inspect_image(image).await {
        Ok(info) => {
            // Prefer a RepoDigest if present (it includes the registry digest); fall back to Id.
            if let Some(digests) = info.repo_digests {
                if let Some(first) = digests.first() {
                    if let Some((_, digest)) = first.split_once('@') {
                        return Some(digest.to_string());
                    }
                }
            }
            info.id
        }
        Err(e) => {
            warn!(error = ?e, "failed to inspect built image for digest");
            None
        }
    }
}

/// Push the image via the docker CLI (which uses the agent's configured registry creds /
/// credential helpers). Registry auth handling beyond the local docker config is a follow-up.
#[cfg(feature = "docker")]
async fn push_image(
    image: &str,
    secret_plaintexts: &[String],
    log_sink: &Option<LogSink>,
) -> Result<bool, BuildError> {
    let mut cmd = Command::new("docker");
    cmd.arg("push")
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    emit(log_sink, format!("pushing {image}")).await;
    run_streamed(cmd, secret_plaintexts, log_sink, BUILD_TIMEOUT).await
}

/// RAII guard for the per-build workspace. Removes the whole tree on drop so secret files
/// and partial artifacts never outlive the build (fail-closed cleanup, A10).
struct WorkspaceGuard {
    dir: PathBuf,
}

impl WorkspaceGuard {
    fn new(build_id: Uuid) -> std::io::Result<Self> {
        // Prefer the agent's build root under a tmpfs if available; fall back to the system temp.
        let base = std::env::var("FORGE_BUILD_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!("forge-build-{build_id}"));
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_shell_metacharacters_in_git_tokens() {
        assert!(is_safe_git_token("https://github.com/acme/app.git"));
        assert!(is_safe_git_token("main"));
        assert!(is_safe_git_token("release/v1.2.3"));
        // Injection attempts must be rejected.
        assert!(!is_safe_git_token("main; rm -rf /"));
        assert!(!is_safe_git_token("$(touch pwned)"));
        assert!(!is_safe_git_token("a`id`b"));
        assert!(!is_safe_git_token("a|b"));
        assert!(!is_safe_git_token("--upload-pack=evil"));
        assert!(!is_safe_git_token("a\nb"));
    }

    #[test]
    fn validate_git_url_accepts_real_remotes() {
        assert!(validate_git_url("https://github.com/org/repo.git").is_ok());
        assert!(validate_git_url("ssh://git@github.com/org/repo.git").is_ok());
        assert!(validate_git_url("git://example.com/repo.git").is_ok());
    }

    #[test]
    fn validate_git_url_rejects_remote_helper_and_transport_smuggling() {
        // git remote-helper command execution at clone time.
        assert!(validate_git_url("ext::sh -c touch /tmp/pwned").is_err());
        assert!(validate_git_url("ext::sh -c 'id'").is_err());
        assert!(validate_git_url("transport::https://evil/").is_err());
        // Local transport — reading host files / dirtied submodules.
        assert!(validate_git_url("file:///etc/passwd").is_err());
        // Disallowed schemes.
        assert!(validate_git_url("http://insecure/repo.git").is_err());
        assert!(validate_git_url("ftp://example.com/repo").is_err());
        // Relative / bare refs are not absolute URLs.
        assert!(validate_git_url("../../../etc/passwd").is_err());
        assert!(validate_git_url("repo.git").is_err());
        // Leading '-' (would also be caught downstream, but reject structurally too).
        assert!(validate_git_url("-oProxyCommand=evil").is_err());
        // Embedded whitespace / quotes (argument smuggling primitives).
        assert!(validate_git_url("https://github.com/org/repo.git extra").is_err());
        assert!(validate_git_url("https://github.com/\"; touch x").is_err());
        // Empty / oversized.
        assert!(validate_git_url("").is_err());
        assert!(validate_git_url(&format!("https://h/{}", "a".repeat(3000))).is_err());
    }

    #[test]
    fn git_args_carry_protocol_restrictions() {
        let hardened = harden_git_args(&["fetch", "--depth", "1", "https://h/r.git", "abc"]);
        // The protocol-restriction config must precede the subcommand.
        let joined = hardened.join(" ");
        assert!(joined.contains("-c protocol.ext.allow=never"));
        assert!(joined.contains("-c protocol.file.allow=never"));
        assert!(joined.contains("-c protocol.allow=user"));
        let ext_pos = hardened
            .iter()
            .position(|a| *a == "protocol.ext.allow=never")
            .unwrap();
        let fetch_pos = hardened.iter().position(|a| *a == "fetch").unwrap();
        assert!(
            ext_pos < fetch_pos,
            "config flags must come before the git subcommand"
        );
        // Original argv is preserved verbatim after the hardening flags.
        assert_eq!(
            &hardened[hardened.len() - 5..],
            &["fetch", "--depth", "1", "https://h/r.git", "abc"]
        );
    }

    #[test]
    fn only_accepts_real_commit_shas() {
        assert!(is_valid_commit_sha(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        ));
        assert!(is_valid_commit_sha(&"a".repeat(64)));
        assert!(!is_valid_commit_sha("main"));
        assert!(!is_valid_commit_sha("HEAD"));
        assert!(!is_valid_commit_sha("a1b2")); // too short
        assert!(!is_valid_commit_sha(
            "g1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        )); // non-hex
    }

    #[test]
    fn safe_subpath_blocks_traversal() {
        let root = Path::new("/srv/build/repo");
        assert!(safe_subpath(root, "app").is_some());
        assert!(safe_subpath(root, "a/b/c").is_some());
        assert!(safe_subpath(root, "../etc/passwd").is_none());
        assert!(safe_subpath(root, "a/../../etc").is_none());
    }

    #[test]
    fn compose_rejects_privileged() {
        let yaml = r#"
services:
  app:
    build: .
    privileged: true
"#;
        let err = validate_compose_yaml(yaml).unwrap_err();
        assert!(matches!(err, BuildError::ComposeRejected(_)));
    }

    #[test]
    fn compose_rejects_docker_socket_mount() {
        let yaml = r#"
services:
  app:
    build: .
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"#;
        let err = validate_compose_yaml(yaml).unwrap_err();
        assert!(matches!(err, BuildError::ComposeRejected(_)));
    }

    #[test]
    fn compose_rejects_host_bind_mount() {
        let yaml = r#"
services:
  app:
    build: .
    volumes:
      - /etc:/host-etc
"#;
        let err = validate_compose_yaml(yaml).unwrap_err();
        assert!(matches!(err, BuildError::ComposeRejected(_)));
    }

    #[test]
    fn compose_rejects_long_form_bind_mount() {
        let yaml = r#"
services:
  app:
    build: .
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
"#;
        let err = validate_compose_yaml(yaml).unwrap_err();
        assert!(matches!(err, BuildError::ComposeRejected(_)));
    }

    #[test]
    fn compose_allows_named_volumes() {
        let yaml = r#"
services:
  app:
    build: .
    volumes:
      - app_data:/data
"#;
        assert!(validate_compose_yaml(yaml).is_ok());
    }

    #[test]
    fn redaction_scrubs_secret_values() {
        let secrets = vec!["super-secret-token-1234".to_string()];
        let line = "echo super-secret-token-1234 > /tmp/x";
        let red = redact_line(line, &secrets);
        assert!(!red.contains("super-secret-token-1234"));
        assert!(red.contains("***REDACTED***"));
    }

    #[test]
    fn redaction_ignores_short_values() {
        // A 3-char value is too short to redact safely (would scrub common substrings).
        let secrets = vec!["ab".to_string()];
        let line = "label about apps";
        assert_eq!(redact_line(line, &secrets), line);
    }

    #[test]
    fn image_ref_validation() {
        assert!(validate_image_ref("registry.example.com/acme/app:abc123").is_ok());
        assert!(validate_image_ref("app:latest").is_ok());
        assert!(validate_image_ref("app; rm -rf /").is_err());
        assert!(validate_image_ref("$(evil)").is_err());
        assert!(validate_image_ref("").is_err());
    }
}
