#!/usr/bin/env bash
#
# Forge Agent One-Command Installer (Tier 2 bootstrap UX)
#
# Usage (recommended from the Forge admin UI after creating a token):
#   curl -fsSL https://your-forge.example.com/install-agent.sh | \
#     bash -s -- --enrollment-token="forge_..." --control-plane="https://your-forge.example.com"
#
# Or manually:
#   ./install-agent.sh --enrollment-token=... --control-plane=...
#
# This script:
#   - Detects OS/arch
#   - Installs the forge-agent binary (prefers prebuilt if available, falls back to cargo)
#   - Creates a secure config with the enrollment token
#   - Sets up a systemd service (Linux) or prints run instructions
#   - Runs with 0600 permissions on all sensitive files
#
# Security: Never hard-code secrets. Token is only used during first enrollment.

set -euo pipefail

CONTROL_PLANE=""
ENROLLMENT_TOKEN=""
BINARY_URL=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/forge"
IDENTITY_PATH="$CONFIG_DIR/agent-identity.toml"
SERVICE_NAME="forge-agent"

log() { echo "[forge-agent-install] $*"; }
err() { echo "[forge-agent-install] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --control-plane) CONTROL_PLANE="$2"; shift 2 ;;
    --enrollment-token) ENROLLMENT_TOKEN="$2"; shift 2 ;;
    --binary-url) BINARY_URL="$2"; shift 2 ;;
    *) err "Unknown argument: $1" ;;
  esac
done

if [[ -z "$CONTROL_PLANE" || -z "$ENROLLMENT_TOKEN" ]]; then
  err "Both --control-plane and --enrollment-token are required.\n\nExample:\n  curl -fsSL https://forge.example.com/install-agent.sh | bash -s -- --control-plane=https://forge.example.com --enrollment-token=forge_xxx"
fi

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
  x86_64)  ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) err "Unsupported architecture: $ARCH" ;;
esac

case $OS in
  linux)  TARGET="linux-${ARCH}" ;;
  darwin) TARGET="macos-${ARCH}" ;;
  *) err "Unsupported OS: $OS (Linux/macOS supported)" ;;
esac

log "Detected $OS on $ARCH → target $TARGET"

# Install binary
mkdir -p "$INSTALL_DIR"

if [[ -n "$BINARY_URL" ]]; then
  log "Downloading prebuilt binary from $BINARY_URL"
  curl -fsSL "$BINARY_URL" -o /tmp/forge-agent
  chmod +x /tmp/forge-agent
  sudo mv /tmp/forge-agent "$INSTALL_DIR/forge-agent"
else
  # Fallback: try to use cargo if Rust is present (good for self-hosters building from source)
  if command -v cargo >/dev/null 2>&1; then
    log "Rust detected. Building forge-agent from source (this may take a few minutes)..."
    cargo install --git https://github.com/your-org/forge --bin forge-agent --root /tmp/forge-install 2>/dev/null || \
      cargo install --path crates/agent --bin forge-agent --root /tmp/forge-install
    sudo mv /tmp/forge-install/bin/forge-agent "$INSTALL_DIR/forge-agent"
  else
    err "No prebuilt binary URL provided and Rust/cargo not found.\n\nPlease either:\n  - Pass --binary-url to this script, or\n  - Install Rust and re-run, or\n  - Download the binary manually from your Forge releases."
  fi
fi

log "Binary installed to $INSTALL_DIR/forge-agent"

# Supply-chain prerequisite check (Phase C). When a supply-chain policy of `sign` or
# `sign-and-require-verify` is in effect, the agent shells out to the `cosign` binary to sign
# built images by digest and to verify image signatures + SLSA provenance BEFORE running a
# Forge-built image (fail-closed). cosign is therefore a prerequisite on any agent that builds
# or runs signed images. We warn (not fail) here so docker-only nodes that never build/verify
# still install cleanly; the agent itself fails closed at runtime if the policy requires cosign
# and it is absent.
if ! command -v cosign >/dev/null 2>&1; then
  log "NOTE: 'cosign' not found on PATH. It is REQUIRED when the supply-chain policy is 'sign' or"
  log "      'sign-and-require-verify' (signing built images + verify-before-run). Install it:"
  log "        https://docs.sigstore.dev/cosign/installation"
  log "      Also set FORGE_COSIGN_KEY (signing) and FORGE_COSIGN_PUBLIC_KEY (verify) in the agent env."
else
  log "cosign detected ($(command -v cosign)) — supply-chain signing/verification available."
fi
# Note: 'nixpacks' and 'docker'/'docker compose' remain prerequisites for those build strategies.

# Create config directory with secure perms
sudo mkdir -p "$CONFIG_DIR"
sudo chmod 700 "$CONFIG_DIR"

# Write minimal config
CONFIG_FILE="$CONFIG_DIR/agent.toml"
sudo tee "$CONFIG_FILE" > /dev/null <<EOF
[agent]
control_plane_url = "$CONTROL_PLANE"
enrollment_token = "$ENROLLMENT_TOKEN"
identity_path = "$IDENTITY_PATH"

# Optional: enable WireGuard mesh (advanced)
# wireguard_enabled = true
EOF
sudo chmod 600 "$CONFIG_FILE"

log "Config written to $CONFIG_FILE (0600)"

# Create identity dir (will be populated on first run)
sudo mkdir -p "$(dirname "$IDENTITY_PATH")"
sudo chmod 700 "$(dirname "$IDENTITY_PATH")"

# Systemd service (Linux only for now)
if [[ "$OS" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Forge Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/forge-agent
Restart=always
RestartSec=5
User=root
Environment="RUST_LOG=info"
# Uncomment for handover during self-updates
# Environment="FORGE_AGENT_HANDOVER_SOCKET=/run/forge-agent/handover.sock"

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable "$SERVICE_NAME"
  log "systemd service installed and enabled: $SERVICE_NAME"

  log "Starting service..."
  sudo systemctl start "$SERVICE_NAME" || true
  sleep 2
  sudo systemctl status "$SERVICE_NAME" --no-pager || true
else
  log "systemd not detected or not Linux. Run manually with:"
  log "  sudo $INSTALL_DIR/forge-agent"
fi

log ""
log "=== SUCCESS ==="
log "Agent installed. It will enroll on first run using the provided token."
log "Check status: sudo journalctl -u $SERVICE_NAME -f"
log "The agent will appear in your Forge admin UI under Agents once enrollment succeeds."
log ""
log "Security note: The enrollment token is one-time use and has been written to $CONFIG_FILE (0600)."
log "After successful enrollment it is no longer needed and can be revoked in the UI."

# Optional: clean the token from config after successful enrollment would be even better,
# but that is an agent-side improvement for a future micro-slice.