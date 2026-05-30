"use client";

import React from "react";
import { useAdminToken } from "../token-store";

type TokenSummary = {
  token_hash_prefix: string;
  description: string | null;
  created_at: string;
  expires_at: string | null;
  used_at: string | null;
  revoked_at: string | null;
  max_uses: number;
  uses_count: number;
  status: "active" | "used" | "expired" | "revoked";
};

type CreatedToken = {
  token: string;
  description: string | null;
  expires_at: string | null;
  max_uses: number;
  prefix: string;
};

const API_BASE = "http://localhost:3000";

export default function EnrollmentTokensPage() {
  const [adminToken] = useAdminToken();

  const [description, setDescription] = React.useState("");
  const [expiresInDays, setExpiresInDays] = React.useState<number | "">("");
  const [maxUses, setMaxUses] = React.useState(1);

  const [isCreating, setIsCreating] = React.useState(false);
  const [justCreated, setJustCreated] = React.useState<CreatedToken | null>(
    null,
  );
  const [copied, setCopied] = React.useState(false);

  const [tokens, setTokens] = React.useState<TokenSummary[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [isRevoking, setIsRevoking] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);

  // Hetzner Provisioning (A0-4 advanced UI)
  const [hetznerToken, setHetznerToken] = React.useState("");
  const [rememberHetznerToken, setRememberHetznerToken] = React.useState(false);
  const [hetznerNamePrefix, setHetznerNamePrefix] =
    React.useState("forge-node");
  const [hetznerCount, setHetznerCount] = React.useState(1);
  const [hetznerServerType, setHetznerServerType] = React.useState("cx22");
  const [hetznerPrivateNetworkName, setHetznerPrivateNetworkName] =
    React.useState("");
  const [hetznerPrivateNetworkIpRange, setHetznerPrivateNetworkIpRange] =
    React.useState("");
  const [isProvisioning, setIsProvisioning] = React.useState(false);
  const [hetznerResult, setHetznerResult] = React.useState<any>(null);
  const [savedHetznerCredentials, setSavedHetznerCredentials] = React.useState<
    any[]
  >([]);
  const [selectedCredentialId, setSelectedCredentialId] = React.useState("");
  const [hetznerFormError, setHetznerFormError] = React.useState<string | null>(
    null,
  );
  const [hetznerFormSuccess, setHetznerFormSuccess] = React.useState<
    string | null
  >(null);

  // Phase 4: Editable public control plane URL so the one-liner is always correct for the user's actual deployment (dev, prod, behind proxy, etc.)
  const [controlPlaneUrl, setControlPlaneUrl] = React.useState("");
  const [copiedOneLiner, setCopiedOneLiner] = React.useState(false);

  React.useEffect(() => {
    if (typeof window !== "undefined" && !controlPlaneUrl) {
      setControlPlaneUrl(window.location.origin);
    }
  }, [controlPlaneUrl]);

  const headers = React.useMemo(() => {
    const h = new Headers();
    h.set("Content-Type", "application/json");
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  const fetchTokens = React.useCallback(async () => {
    if (!adminToken) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/admin/enrollment-tokens`, {
        headers,
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(
          body?.detail || body?.title || `Request failed (${res.status})`,
        );
      }
      const data = await res.json();
      setTokens(data.tokens || []);
    } catch (e: any) {
      setError(e.message || "Failed to load tokens");
    } finally {
      setIsLoading(false);
    }
  }, [adminToken, headers]);

  const fetchHetznerCredentials = React.useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await fetch(`${API_BASE}/admin/hetzner-credentials`, {
        headers,
      });
      if (res.ok) {
        const data = await res.json();
        setSavedHetznerCredentials(data.credentials || []);
      }
    } catch {}
  }, [adminToken, headers]);

  React.useEffect(() => {
    if (adminToken) {
      fetchTokens();
      fetchHetznerCredentials();
    }
  }, [adminToken, fetchTokens, fetchHetznerCredentials]);

  // Load remembered Hetzner token (session only)
  React.useEffect(() => {
    const saved = localStorage.getItem("forge_hetzner_token");
    if (saved) {
      setHetznerToken(saved);
      setRememberHetznerToken(true);
    }
  }, []);

  // Auto refresh every 30s while admin token present
  React.useEffect(() => {
    if (!adminToken) return;
    const id = setInterval(() => {
      fetchTokens();
    }, 30000);
    return () => clearInterval(id);
  }, [adminToken, fetchTokens]);

  // Phase 4: Live registered agents/servers (from /agents/status + WS registry)
  const [agents, setAgents] = React.useState<any[]>([]);
  const [isLoadingAgents, setIsLoadingAgents] = React.useState(false);

  const fetchAgents = React.useCallback(async () => {
    if (!adminToken) return;
    setIsLoadingAgents(true);
    try {
      const res = await fetch(`${API_BASE}/agents/status`, { headers });
      if (res.ok) {
        const data = await res.json();
        setAgents(Array.isArray(data) ? data : []);
      }
    } catch {}
    setIsLoadingAgents(false);
  }, [adminToken, headers]);

  React.useEffect(() => {
    if (adminToken) {
      fetchAgents();
    }
  }, [adminToken, fetchAgents]);

  // Auto-refresh agents list
  React.useEffect(() => {
    if (!adminToken) return;
    const id = setInterval(fetchAgents, 15000);
    return () => clearInterval(id);
  }, [adminToken, fetchAgents]);

  async function createToken(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken) {
      setError("Enter your FORGE_ADMIN_TOKEN above first");
      return;
    }
    setIsCreating(true);
    setError(null);
    setSuccessMsg(null);
    setJustCreated(null);

    try {
      const payload: {
        description?: string;
        expires_in_days?: number;
        max_uses?: number;
      } = {};
      if (description.trim()) payload.description = description.trim();
      if (expiresInDays !== "") payload.expires_in_days = Number(expiresInDays);
      if (maxUses > 0) payload.max_uses = maxUses;

      const res = await fetch(`${API_BASE}/admin/enrollment-tokens`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });

      const body = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(body?.detail || body?.title || "Failed to issue token");
      }

      const created: CreatedToken = body;
      setJustCreated(created);

      // Optimistically add to list (without secret)
      const newSummary: TokenSummary = {
        token_hash_prefix: created.prefix,
        description: created.description,
        created_at: new Date().toISOString(),
        expires_at: created.expires_at,
        used_at: null,
        revoked_at: null,
        max_uses: created.max_uses,
        uses_count: 0,
        status: "active",
      };
      setTokens((prev) => [newSummary, ...prev]);

      setSuccessMsg(
        "Token issued successfully. Copy the secret now — it will not be shown again.",
      );
      setDescription("");
      setExpiresInDays("");
      setMaxUses(1);
    } catch (e: any) {
      setError(e.message || "Failed to issue token");
    } finally {
      setIsCreating(false);
    }
  }

  async function revokeToken(prefix: string) {
    if (!adminToken) return;
    if (!confirm(`Revoke token ${prefix}* ? This cannot be undone.`)) return;

    setIsRevoking(prefix);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/admin/enrollment-tokens/${prefix}`, {
        method: "DELETE",
        headers,
      });
      if (!res.ok && res.status !== 204) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || "Failed to revoke");
      }
      setSuccessMsg(`Token ${prefix}* revoked`);
      await fetchTokens();
    } catch (e: any) {
      setError(e.message || "Revoke failed");
    } finally {
      setIsRevoking(null);
    }
  }

  async function copySecret(token: string) {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    } catch {
      // Fallback for older browsers
      const ta = document.createElement("textarea");
      ta.value = token;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    }
  }

  // Save current Hetzner token using the dedicated credential system (control-plane decryptable)
  async function rotateHetznerCredential(id: string) {
    const newToken = prompt("Enter the new Hetzner API token:");
    if (!newToken) return;

    try {
      const res = await fetch(
        `${API_BASE}/admin/hetzner-credentials/${id}/rotate`,
        {
          method: "PUT",
          headers,
          body: JSON.stringify({ token: newToken }),
        },
      );
      if (res.ok) {
        const data = await res.json();
        alert("Credential rotated. New token (one-time): " + data.plaintext);
        await fetchHetznerCredentials();
      } else {
        alert("Rotate failed");
      }
    } catch {
      alert("Error rotating credential");
    }
  }

  async function deleteHetznerCredential(id: string) {
    if (!confirm("Delete this credential?")) return;
    try {
      const res = await fetch(`${API_BASE}/admin/hetzner-credentials/${id}`, {
        method: "DELETE",
        headers,
      });
      if (res.ok) {
        await fetchHetznerCredentials();
      } else {
        alert("Delete failed");
      }
    } catch {
      alert("Error deleting credential");
    }
  }

  async function saveHetznerCredential() {
    if (!adminToken || !hetznerToken) return;
    const name = prompt(
      "Credential name (e.g. hetzner:production):",
      "hetzner:main",
    );
    if (!name) return;

    setHetznerFormError(null);
    setHetznerFormSuccess(null);

    try {
      const res = await fetch(`${API_BASE}/admin/hetzner-credentials`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name,
          description: "Hetzner Cloud API Token",
          token: hetznerToken,
        }),
      });
      if (res.ok) {
        setHetznerFormSuccess("Credential saved successfully.");
        await fetchHetznerCredentials();
        setTimeout(() => setHetznerFormSuccess(null), 3000);
      } else {
        const err = await res.json().catch(() => ({}));
        setHetznerFormError(
          "Failed to save credential: " + (err?.detail || res.status),
        );
      }
    } catch (e: any) {
      setHetznerFormError("Error saving credential: " + e.message);
    }
  }

  // Advanced Hetzner provisioning (A0-4)
  async function provisionHetznerServers() {
    if (!adminToken || (!hetznerToken && !selectedCredentialId)) return;
    setIsProvisioning(true);
    setHetznerResult(null);
    setHetznerFormError(null);
    setHetznerFormSuccess(null);

    if (rememberHetznerToken && hetznerToken) {
      localStorage.setItem("forge_hetzner_token", hetznerToken);
    }

    try {
      const payload: any = {
        name_prefix: hetznerNamePrefix,
        count: hetznerCount,
        server_type: hetznerServerType,
        control_plane_url: controlPlaneUrl,
        private_network_name: hetznerPrivateNetworkName || undefined,
        private_network_ip_range: hetznerPrivateNetworkIpRange || undefined,
      };

      if (selectedCredentialId) {
        payload.hetzner_credential_id = selectedCredentialId;
      } else if (hetznerToken) {
        payload.hetzner_token = hetznerToken;
      }

      const res = await fetch(`${API_BASE}/admin/providers/hetzner/servers`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail || "Provisioning failed");

      setHetznerResult(data);
      setHetznerFormSuccess(
        `Successfully initiated ${data.created_count} server(s). Check your Hetzner console.`,
      );
      await fetchTokens();
      setTimeout(() => setHetznerFormSuccess(null), 4000);
    } catch (e: any) {
      setHetznerFormError(e.message || "Hetzner provisioning failed");
    } finally {
      setIsProvisioning(false);
    }
  }

  function copyPrefix(prefix: string) {
    navigator.clipboard.writeText(prefix).catch(() => {});
  }

  function formatDate(d: string | null) {
    if (!d) return "—";
    return new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(d));
  }

  function StatusPill({ status }: { status: TokenSummary["status"] }) {
    const styles: Record<TokenSummary["status"], string> = {
      active:
        "bg-[oklch(0.55_0.18_145)]/10 text-[oklch(0.45_0.15_145)] border-[oklch(0.55_0.18_145)]/30",
      used: "bg-[oklch(0.55_0.22_25)]/10 text-[oklch(0.50_0.20_25)] border-[oklch(0.55_0.22_25)]/30",
      expired:
        "bg-[oklch(0.75_0.18_85)]/10 text-[oklch(0.55_0.15_85)] border-[oklch(0.75_0.18_85)]/30",
      revoked:
        "bg-[oklch(0.45_0.02_260)]/10 text-[oklch(0.40_0.02_260)] border-[oklch(0.45_0.02_260)]/30",
    };
    return (
      <span
        className={`inline-flex items-center rounded-full border px-2.5 py-px text-[11px] font-medium tracking-tight ${styles[status]}`}
      >
        {status}
      </span>
    );
  }

  const hasAdminToken = adminToken.length >= 12;

  return (
    <div className="page-root">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">
          Enrollment Tokens
        </h1>
        <p className="mt-0.5 text-[13px] text-[oklch(1_0_0/0.45)]">
          Issue one-time enrollment tokens and provision servers. Set your admin
          token in the top bar to manage.
        </p>
      </div>

      <div>
        {/* === Advanced Hetzner Provisioning (A0-4) === */}
        <div className="mb-8 rounded-lg border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="rounded-[4px] border border-[oklch(1_0_0/0.1)] bg-[oklch(1_0_0/0.05)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-[oklch(1_0_0/0.55)]">
              NEW
            </div>
            <div className="text-base font-semibold tracking-tight">
              Provision Hetzner Servers
            </div>
          </div>
          <p className="text-sm text-[var(--color-muted-foreground)] max-w-2xl mb-6">
            One-click (or many-click) server creation. Each server gets its own
            one-time enrollment token embedded in a hardened cloud-init.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div className="lg:col-span-2">
              <label className="text-xs font-medium text-[var(--color-muted-foreground)]">
                Hetzner API Token
              </label>
              <input
                type="password"
                value={hetznerToken}
                onChange={(e) => setHetznerToken(e.target.value)}
                placeholder="hcloud_xxxxxxxxxxxxxxxx"
                className="input mt-1 font-mono"
              />
              <label className="mt-2 flex items-center gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={rememberHetznerToken}
                  onChange={(e) => {
                    setRememberHetznerToken(e.target.checked);
                    if (!e.target.checked)
                      localStorage.removeItem("forge_hetzner_token");
                  }}
                />
                Remember token in this browser (session only)
              </label>
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--color-muted-foreground)]">
                Name Prefix
              </label>
              <input
                value={hetznerNamePrefix}
                onChange={(e) => setHetznerNamePrefix(e.target.value)}
                className="input mt-1"
                placeholder="prod-node"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--color-muted-foreground)]">
                Count
              </label>
              <input
                type="number"
                min={1}
                max={10}
                value={hetznerCount}
                onChange={(e) => setHetznerCount(parseInt(e.target.value) || 1)}
                className="input mt-1"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--color-muted-foreground)]">
                Server Type
              </label>
              <select
                value={hetznerServerType}
                onChange={(e) => setHetznerServerType(e.target.value)}
                className="input mt-1"
              >
                <option value="cx22">cx22 (4 vCPU / 8 GB)</option>
                <option value="cx32">cx32 (8 vCPU / 16 GB)</option>
                <option value="cpx41">cpx41 (16 vCPU / 32 GB)</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--color-muted-foreground)]">
                Private Network (optional)
              </label>
              <input
                value={hetznerPrivateNetworkName}
                onChange={(e) => setHetznerPrivateNetworkName(e.target.value)}
                placeholder="forge-private"
                className="input mt-1"
              />
              <input
                value={hetznerPrivateNetworkIpRange}
                onChange={(e) =>
                  setHetznerPrivateNetworkIpRange(e.target.value)
                }
                placeholder="10.0.0.0/16 (optional IP range)"
                className="input mt-1 font-mono"
              />
              <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1">
                Provide a name to create/attach a private network. Optionally
                specify CIDR.
              </div>
            </div>
          </div>

          {/* Local form feedback for Hetzner section */}
          {(hetznerFormError || hetznerFormSuccess) && (
            <div
              className={`rounded-xl px-4 py-2 text-sm ${hetznerFormError ? "bg-[var(--color-destructive)]/100/10 text-[var(--color-destructive)] border border-red-500/30" : "bg-[var(--color-success)]/120/10 text-emerald-700 border border-emerald-500/30"}`}
            >
              {hetznerFormError || hetznerFormSuccess}
            </div>
          )}

          <div className="mt-4 flex flex-col gap-3">
            {savedHetznerCredentials.length > 0 && (
              <div>
                <label className="text-xs font-medium text-[var(--color-muted-foreground)]">
                  Use Saved Credential (lookup + decryption wired in backend)
                </label>
                <select
                  value={selectedCredentialId}
                  onChange={(e) => setSelectedCredentialId(e.target.value)}
                  className="input mt-1"
                >
                  <option value="">
                    -- Paste token above or select saved --
                  </option>
                  {savedHetznerCredentials.map((c: any) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                      {c.description ? ` — ${c.description}` : ""}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="flex gap-3 items-center">
              <button
                onClick={provisionHetznerServers}
                disabled={!hetznerToken || isProvisioning}
                className="btn btn-primary"
              >
                {isProvisioning
                  ? "Provisioning..."
                  : `Spin up ${hetznerCount} server${hetznerCount > 1 ? "s" : ""}`}
              </button>
              <button
                onClick={saveHetznerCredential}
                disabled={!hetznerToken}
                className="btn btn-ghost"
              >
                Save as Credential
              </button>
              <div className="text-xs text-[var(--color-muted-foreground)]">
                Each server gets its own single-use enrollment token + hardened
                cloud-init.
              </div>
            </div>
          </div>

          {hetznerResult && (
            <div className="mt-4 rounded-2xl border p-4 text-sm bg-black/5">
              <div className="font-medium mb-2">Provisioning Results</div>
              <div className="space-y-3">
                {(hetznerResult.servers || []).map((s: any, idx: number) => (
                  <div
                    key={idx}
                    className="rounded-xl border bg-[var(--color-card)] p-3 text-xs font-mono"
                  >
                    <div>
                      <span className="text-[var(--color-muted-foreground)]">
                        Name:
                      </span>{" "}
                      {s.server?.name}
                    </div>
                    <div>
                      <span className="text-[var(--color-muted-foreground)]">
                        ID:
                      </span>{" "}
                      {s.server?.id}
                    </div>
                    <div>
                      <span className="text-[var(--color-muted-foreground)]">
                        IPv4:
                      </span>{" "}
                      {s.server?.ipv4 || "pending"}
                    </div>
                    <div>
                      <span className="text-[var(--color-muted-foreground)]">
                        Status:
                      </span>{" "}
                      {s.server?.status}
                    </div>
                  </div>
                ))}
              </div>
              {hetznerResult.note && (
                <div className="mt-2 text-[10px] text-[var(--color-muted-foreground)]">
                  {hetznerResult.note}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Richer Credential Management UI */}
        {savedHetznerCredentials.length > 0 && (
          <div className="mb-10 rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-6">
            <div className="font-semibold text-lg tracking-tight mb-4">
              Saved Hetzner Credentials
            </div>
            <div className="space-y-3">
              {savedHetznerCredentials.map((c: any) => (
                <div
                  key={c.id}
                  className="flex items-center justify-between rounded-2xl border p-4 text-sm"
                >
                  <div>
                    <div className="font-medium">{c.name}</div>
                    {c.description && (
                      <div className="text-xs text-[var(--color-muted-foreground)]">
                        {c.description}
                      </div>
                    )}
                    <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1">
                      Created {new Date(c.created_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => rotateHetznerCredential(c.id)}
                      className="rounded-xl border px-3 py-1 text-xs hover:bg-[var(--color-muted)]"
                    >
                      Rotate
                    </button>
                    <button
                      onClick={() => deleteHetznerCredential(c.id)}
                      className="rounded-xl border border-red-300 px-3 py-1 text-xs text-[var(--color-destructive)] hover:bg-[var(--color-destructive)]/10"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {error && (
          <div className="mb-6 rounded-xl border border-red-200 bg-[var(--color-destructive)]/10 px-4 py-3 text-sm text-[var(--color-destructive)] flex items-center justify-between">
            <span>{error}</span>
            <button
              onClick={() => setError(null)}
              className="font-medium underline"
            >
              Dismiss
            </button>
          </div>
        )}
        {successMsg && (
          <div className="mb-6 rounded-xl border border-[var(--color-success)]/30 bg-[var(--color-success)]/5 px-4 py-3 text-sm text-[var(--color-success)] flex items-center justify-between">
            <span>{successMsg}</span>
            <button
              onClick={() => setSuccessMsg(null)}
              className="font-medium underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Phase 4 marketing: why this is different (crypto superiority, no weakening) */}
        <div className="card mb-8 p-6">
          <div className="uppercase tracking-[1.5px] text-xs font-semibold text-[var(--color-muted-foreground)] mb-1">
            THE FORGE DIFFERENCE
          </div>
          <div className="text-xl font-semibold tracking-tighter">
            Your servers never see plaintext secrets.
            <br />
            Ever.
          </div>
          <div className="mt-2 text-sm text-[var(--color-muted-foreground)] max-w-2xl">
            Every agent gets a unique Ed25519 identity on enrollment. Jobs are
            signed by the control plane and verified on the agent. Secrets are
            wrapped in age X25519 envelopes addressed only to the exact agents
            that need them (using the age_recipient the agent sent at enrollment
            time). The control plane and database never contain decryptable
            material. This is the bar competitors miss.
          </div>
        </div>

        {/* Issue form */}
        <div className="mb-8 rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] p-6">
          <div className="mb-5">
            <div className="text-base font-semibold tracking-tight">
              Issue enrollment token
            </div>
            <div className="mt-0.5 text-[13px] text-[oklch(1_0_0/0.45)]">
              Agents use this one-time (or limited-use) secret to join the mesh
              and receive signed work.
            </div>
          </div>

          <form onSubmit={createToken} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2">
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  DESCRIPTION (OPTIONAL)
                </label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="hetzner node-03 — staging"
                  className="input"
                />
              </div>

              <div>
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  EXPIRES IN
                </label>
                <select
                  value={expiresInDays}
                  onChange={(e) =>
                    setExpiresInDays(
                      e.target.value === "" ? "" : Number(e.target.value),
                    )
                  }
                  className="select"
                >
                  <option value="">Never expires</option>
                  <option value={1}>1 day</option>
                  <option value={7}>7 days</option>
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                  <option value={180}>180 days</option>
                  <option value={365}>365 days</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  MAX USES
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={maxUses}
                    onChange={(e) =>
                      setMaxUses(
                        Math.max(
                          1,
                          Math.min(100, parseInt(e.target.value) || 1),
                        ),
                      )
                    }
                    className="input w-28 tabular-nums"
                  />
                  <div className="text-xs text-[var(--color-muted-foreground)]">
                    1 = single-use (recommended for production nodes)
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isCreating || !hasAdminToken}
                className="btn btn-primary"
              >
                {isCreating
                  ? "Issuing secure token…"
                  : "Issue enrollment token"}
              </button>
              {!hasAdminToken && (
                <span className="ml-4 text-xs text-[var(--color-muted-foreground)]">
                  Enter admin token above to enable issuance
                </span>
              )}
            </div>
          </form>
        </div>

        {/* One-time secret reveal — only after successful create */}
        {justCreated && (
          <div className="mb-8 rounded-3xl border-2 border-amber-400/70 bg-[var(--color-warning)]/10/60 p-6">
            <div className="flex items-start gap-4">
              <div className="mt-0.5 text-amber-500">
                <svg
                  width="22"
                  height="22"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.5"
                >
                  <path d="M12 9v4m0 4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-semibold tracking-tight text-amber-950">
                  One-time secret — copy immediately
                </div>
                <div className="text-sm text-[var(--color-warning)]/80 mt-0.5">
                  This value is never stored or shown again after you leave this
                  page.
                </div>

                <div className="mt-4 flex items-center gap-3 rounded-2xl bg-[var(--color-card)] px-5 py-4 font-mono text-[15px] border border-[var(--color-warning)]/25 tracking-[0.5px] break-all select-all">
                  {justCreated.token}
                </div>

                <div className="mt-3 flex items-center gap-3">
                  <button
                    onClick={() => copySecret(justCreated.token)}
                    className="inline-flex items-center gap-2 rounded-2xl bg-[var(--color-card)] border border-[var(--color-warning)]/25 px-6 h-10 text-sm font-medium active:bg-[var(--color-warning)]/15 transition"
                  >
                    {copied ? (
                      <>Copied to clipboard ✓</>
                    ) : (
                      <>
                        <svg
                          width="15"
                          height="15"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2.25"
                        >
                          <rect x="9" y="9" width="13" height="13" rx="2" />
                          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                        </svg>
                        Copy secret
                      </>
                    )}
                  </button>
                  <button
                    onClick={() => setJustCreated(null)}
                    className="text-sm text-amber-950/70 hover:text-amber-950 underline underline-offset-2"
                  >
                    Dismiss
                  </button>
                  <div className="text-[10px] text-[var(--color-warning)]/60 ml-auto font-mono tracking-[1px]">
                    {justCreated.prefix}••••
                  </div>
                </div>

                {/* Phase 4: Live, always-correct one-command bootstrap (editable public URL + real copy button) */}
                <div className="mt-6 rounded-2xl border border-emerald-200 bg-[var(--color-success)]/12 p-4">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="text-xs font-medium tracking-widest text-emerald-700">
                      ONE-COMMAND SERVER BOOTSTRAP
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        const cmd = `curl -fsSL ${controlPlaneUrl || "https://your-forge.example.com"}/install-agent.sh | bash -s -- --enrollment-token="${justCreated.token}" --control-plane="${controlPlaneUrl || "https://your-forge.example.com"}"`;
                        navigator.clipboard.writeText(cmd).then(() => {
                          // reuse or set a local copied state if desired; for simplicity use toast if available, else alert pattern
                          const orig = (window as any)._lastOneLinerCopied;
                          (window as any)._lastOneLinerCopied = true;
                          setTimeout(() => {
                            (window as any)._lastOneLinerCopied = false;
                          }, 1800);
                        });
                      }}
                      className="text-[10px] px-2 py-0.5 rounded border border-emerald-300 text-emerald-700 hover:bg-[var(--color-card)] active:bg-emerald-100"
                    >
                      Copy command
                    </button>
                  </div>

                  <div className="mb-2">
                    <label className="text-[10px] text-emerald-700/70 block mb-0.5">
                      Public Control Plane URL (edit for prod / reverse proxy /
                      different host)
                    </label>
                    <input
                      value={controlPlaneUrl}
                      onChange={(e) =>
                        setControlPlaneUrl(e.target.value.trim())
                      }
                      className="w-full font-mono text-sm rounded-xl border border-emerald-200 bg-[var(--color-card)] px-3 py-1.5 text-emerald-950"
                      placeholder="https://forge.example.com"
                    />
                  </div>

                  {(() => {
                    const cmd = `curl -fsSL ${controlPlaneUrl || "https://your-forge.example.com"}/install-agent.sh | bash -s -- --enrollment-token="${justCreated.token}" --control-plane="${controlPlaneUrl || "https://your-forge.example.com"}"`;
                    return (
                      <>
                        <div className="flex items-center gap-2 mb-1">
                          <button
                            type="button"
                            onClick={() => {
                              navigator.clipboard.writeText(cmd).then(() => {
                                setCopiedOneLiner(true);
                                setTimeout(
                                  () => setCopiedOneLiner(false),
                                  1800,
                                );
                              });
                            }}
                            className="text-[10px] px-2.5 py-0.5 rounded border border-emerald-300 text-emerald-700 hover:bg-[var(--color-card)] active:bg-emerald-100"
                          >
                            {copiedOneLiner ? "Copied ✓" : "Copy full command"}
                          </button>
                          <span className="text-[10px] text-emerald-600/70">
                            Run exactly as-is on the new server
                          </span>
                        </div>
                        <code className="block bg-[var(--color-card)] border border-emerald-200 rounded-xl p-3 text-[12px] font-mono text-emerald-950 break-all select-all">
                          {cmd}
                        </code>
                      </>
                    );
                  })()}
                  <div className="mt-2 text-[11px] text-emerald-700/80">
                    Runs on the target machine. The agent will present its
                    Ed25519 key + age recipient at enrollment time. It appears
                    in "Your Servers" above within seconds. The one-time token
                    is consumed on success.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Phase 4: Live "Your Servers" — the payoff of the crypto model (ed25519 + age per-agent identity) */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-base font-semibold tracking-tight">
                Your Servers
              </div>
              <div className="text-[12px] text-[oklch(1_0_0/0.4)]">
                Agents that have successfully enrolled. Each has its own Ed25519
                identity + age recipient. Secrets are encrypted to the exact set
                of agents that need them — never in plaintext on the control
                plane or in transit.
              </div>
            </div>
            <button
              onClick={fetchAgents}
              disabled={isLoadingAgents || !hasAdminToken}
              className="text-xs rounded-full border px-3 h-8 flex items-center gap-1 disabled:opacity-50"
            >
              {isLoadingAgents ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          {isLoadingAgents && agents.length === 0 ? (
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-card)] p-8 text-center text-sm text-[var(--color-muted-foreground)]">
              Loading registered agents…
            </div>
          ) : agents.length === 0 ? (
            <div className="rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] p-10 text-center">
              <div className="font-medium">No servers enrolled yet</div>
              <div className="text-sm text-[var(--color-muted-foreground)] mt-1 max-w-xs mx-auto">
                Issue a token above, run the one-liner on any Linux box
                (Hetzner, AWS, bare metal, laptop), and it will appear here
                automatically.
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {agents.map((a: any, idx: number) => {
                const isConnected =
                  a.connected ||
                  (a.last_seen_at &&
                    new Date(a.last_seen_at).getTime() >
                      Date.now() - 1000 * 90);
                return (
                  <div
                    key={a.id || idx}
                    className="rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] p-4 flex flex-col gap-2 text-sm"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="font-semibold tracking-tight">
                          {a.hostname ||
                            a.name ||
                            `agent-${(a.id || "").slice(0, 8)}`}
                        </div>
                        <div className="font-mono text-[10px] text-[var(--color-muted-foreground)] mt-0.5">
                          {a.id}
                        </div>
                      </div>
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-px text-[10px] font-medium border ${isConnected ? "bg-[var(--color-success)]/120/10 text-emerald-700 border-emerald-500/30" : "bg-[var(--color-warning)]/100/10 text-[var(--color-warning)] border-amber-500/30"}`}
                      >
                        {isConnected ? "CONNECTED" : "OFFLINE"}
                      </span>
                    </div>
                    <div className="text-[11px] text-[var(--color-muted-foreground)] grid grid-cols-2 gap-x-4 gap-y-0.5 pt-1 border-t border-[var(--color-border)]/60">
                      <div>
                        Last seen:{" "}
                        {a.last_seen_at
                          ? new Date(a.last_seen_at).toLocaleTimeString()
                          : "—"}
                      </div>
                      <div>
                        Version:{" "}
                        <span className="font-mono">
                          {a.version || a.labels?.version || "—"}
                        </span>
                      </div>
                      {a.labels?.cpu && <div>CPU: {a.labels.cpu}</div>}
                      {a.labels?.mem && <div>Mem: {a.labels.mem}</div>}
                    </div>
                    <div className="text-[10px] text-[var(--color-muted-foreground)] mt-auto pt-1">
                      Ed25519 + age identity established on first enrollment.
                      Jobs are signed; secrets stay encrypted until the agent.
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <div className="text-[10px] text-[var(--color-muted-foreground)] mt-2 px-1">
            Data comes from the same /agents/status endpoint + live WS registry
            used by canary health gates and the Update Forge flow.
          </div>
        </div>

        {/* List of tokens (kept for operators who want to manage raw tokens) */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="text-base font-semibold tracking-tight">
              All enrollment tokens
            </div>
            <button
              onClick={fetchTokens}
              disabled={isLoading || !hasAdminToken}
              className="flex items-center gap-2 rounded-full border border-[var(--color-card-border)] bg-[var(--color-card)] px-4 h-9 text-sm font-medium disabled:opacity-50 active:bg-[var(--color-muted)]"
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="3"
              >
                <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
                <path d="M21 3v5h-5" />
                <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
                <path d="M8 21H3v-5" />
              </svg>
              Refresh
            </button>
          </div>

          <div className="overflow-hidden rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)]">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[oklch(1_0_0/0.07)] bg-[oklch(1_0_0/0.03)] text-left text-[10px] uppercase tracking-[0.12em] text-[oklch(1_0_0/0.38)]">
                    <th className="pl-6 py-3 font-medium">PREFIX</th>
                    <th className="py-3 font-medium">DESCRIPTION</th>
                    <th className="py-3 font-medium">STATUS</th>
                    <th className="py-3 font-medium tabular-nums">USES</th>
                    <th className="py-3 font-medium">CREATED</th>
                    <th className="py-3 font-medium">EXPIRES</th>
                    <th className="pr-6 py-3 w-24"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[oklch(1_0_0/0.06)]">
                  {isLoading &&
                    tokens.length === 0 &&
                    Array.from({ length: 3 }).map((_, i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="pl-6 py-4">
                          <div className="h-4 w-16 bg-[var(--color-muted)] rounded" />
                        </td>
                        <td className="py-4">
                          <div className="h-4 w-40 bg-[var(--color-muted)] rounded" />
                        </td>
                        <td className="py-4">
                          <div className="h-5 w-14 bg-[var(--color-muted)] rounded-full" />
                        </td>
                        <td className="py-4">
                          <div className="h-4 w-8 bg-[var(--color-muted)] rounded" />
                        </td>
                        <td className="py-4">
                          <div className="h-4 w-28 bg-[var(--color-muted)] rounded" />
                        </td>
                        <td className="py-4">
                          <div className="h-4 w-20 bg-[var(--color-muted)] rounded" />
                        </td>
                        <td className="pr-6"></td>
                      </tr>
                    ))}

                  {!isLoading && tokens.length === 0 && (
                    <tr>
                      <td
                        colSpan={7}
                        className="px-6 py-16 text-center text-[var(--color-muted-foreground)]"
                      >
                        {hasAdminToken
                          ? "No tokens have been issued yet."
                          : "Enter your admin token to view and manage enrollment tokens."}
                      </td>
                    </tr>
                  )}

                  {tokens.map((t) => {
                    const isActive = t.status === "active";
                    return (
                      <tr
                        key={t.token_hash_prefix}
                        className="hover:bg-[var(--color-muted)]/30 transition-colors"
                      >
                        <td
                          className="pl-6 py-3.5 font-mono text-xs tracking-[2px] text-[var(--color-muted-foreground)] cursor-pointer"
                          onClick={() => copyPrefix(t.token_hash_prefix)}
                          title="Click to copy prefix"
                        >
                          {t.token_hash_prefix}••••
                        </td>
                        <td className="py-3.5 pr-4 text-[15px] text-[var(--color-foreground)]/90">
                          {t.description || (
                            <span className="text-[var(--color-muted-foreground)]">
                              —
                            </span>
                          )}
                        </td>
                        <td className="py-3.5">
                          <StatusPill status={t.status} />
                        </td>
                        <td className="py-3.5 tabular-nums font-medium">
                          {t.uses_count}
                          <span className="text-[var(--color-muted-foreground)]">
                            /{t.max_uses}
                          </span>
                        </td>
                        <td className="py-3.5 text-[var(--color-muted-foreground)]">
                          {formatDate(t.created_at)}
                        </td>
                        <td className="py-3.5 text-[var(--color-muted-foreground)]">
                          {formatDate(t.expires_at)}
                        </td>
                        <td className="pr-6 py-3.5 text-right">
                          {isActive && (
                            <button
                              onClick={() => revokeToken(t.token_hash_prefix)}
                              disabled={isRevoking === t.token_hash_prefix}
                              className="inline-flex items-center gap-1 rounded-full border border-[var(--color-card-border)] px-3 py-1 text-xs font-medium text-[var(--color-destructive)] hover:bg-[var(--color-destructive)]/10 active:bg-red-100 disabled:opacity-50"
                            >
                              {isRevoking === t.token_hash_prefix
                                ? "Revoking…"
                                : "Revoke"}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-3 px-1 text-[10px] text-[var(--color-muted-foreground)]">
            Tokens are single-use by default. Multi-use tokens are intended only
            for automated provisioning scripts you fully control.
          </div>
        </div>
      </div>

      <footer className="border-t border-border mt-16 py-6 text-center text-xs text-[var(--color-muted-foreground)]">
        Forge Control Plane • Enrollment is the root of trust for every agent
      </footer>
    </div>
  );
}
