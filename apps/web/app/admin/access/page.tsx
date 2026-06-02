"use client";

import React from "react";
import { useAdminToken } from "../token-store";

const API_BASE = "http://localhost:3000";

type Principal = {
  id: string;
  name: string;
  principal_type: string;
  created_at: string;
};

type Role = {
  id: string;
  name: string;
  description: string | null;
  permissions: Record<string, unknown>;
  created_at: string;
  revoked_at: string | null;
};

type AdminTokenSummary = {
  token_hash_prefix: string;
  principal_id: string;
  description: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
};

type CreatedAdminToken = {
  token: string;
  principal_id: string;
  description: string | null;
  expires_at: string | null;
  prefix: string;
};

export default function AccessPage() {
  const [adminToken] = useAdminToken();

  const [principals, setPrincipals] = React.useState<Principal[]>([]);
  const [roles, setRoles] = React.useState<Role[]>([]);
  const [adminTokens, setAdminTokens] = React.useState<AdminTokenSummary[]>([]);

  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);

  // Create principal
  const [newPrincipalName, setNewPrincipalName] = React.useState("");
  const [newPrincipalType, setNewPrincipalType] = React.useState<
    "user" | "api_key"
  >("user");
  const [isCreatingPrincipal, setIsCreatingPrincipal] = React.useState(false);

  // Create role
  const [newRoleName, setNewRoleName] = React.useState("");
  const [newRoleDesc, setNewRoleDesc] = React.useState("");
  const [newRolePerms, setNewRolePerms] = React.useState(
    '{\n  "deployments:read": true\n}',
  );
  const [isCreatingRole, setIsCreatingRole] = React.useState(false);

  // Create admin token
  const [selectedPrincipalId, setSelectedPrincipalId] = React.useState("");
  const [tokenDesc, setTokenDesc] = React.useState("");
  const [tokenExpires, setTokenExpires] = React.useState<number | "">("");
  const [isCreatingToken, setIsCreatingToken] = React.useState(false);
  const [justCreatedToken, setJustCreatedToken] =
    React.useState<CreatedAdminToken | null>(null);
  const [copied, setCopied] = React.useState(false);

  const [isRevoking, setIsRevoking] = React.useState<string | null>(null);

  const headers = React.useMemo(() => {
    const h = new Headers();
    h.set("Content-Type", "application/json");
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  const hasAdminToken = adminToken.length >= 12;

  const fetchAll = React.useCallback(async () => {
    if (!adminToken) return;
    setIsLoading(true);
    setError(null);
    try {
      const [pRes, rRes, tRes] = await Promise.all([
        fetch(`${API_BASE}/admin/principals`, { headers }),
        fetch(`${API_BASE}/admin/roles`, { headers }),
        fetch(`${API_BASE}/admin/admin-tokens`, { headers }),
      ]);

      if (pRes.ok) {
        const data = await pRes.json();
        setPrincipals(data || []);
      }
      if (rRes.ok) {
        const data = await rRes.json();
        setRoles(data || []);
      }
      if (tRes.ok) {
        const data = await tRes.json();
        setAdminTokens(data || []);
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load RBAC data";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [adminToken, headers]);

  React.useEffect(() => {
    if (adminToken) {
      fetchAll();
    }
  }, [adminToken, fetchAll]);

  // Auto-refresh
  React.useEffect(() => {
    if (!adminToken) return;
    const id = setInterval(fetchAll, 30000);
    return () => clearInterval(id);
  }, [adminToken, fetchAll]);

  async function createPrincipal(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken) {
      setError("Enter your FORGE_ADMIN_TOKEN first");
      return;
    }
    setIsCreatingPrincipal(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/admin/principals`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: newPrincipalName.trim(),
          principal_type: newPrincipalType,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok)
        throw new Error(
          body?.detail || body?.title || "Failed to create principal",
        );

      setSuccessMsg("Principal created");
      setNewPrincipalName("");
      await fetchAll();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create principal";
      setError(msg);
    } finally {
      setIsCreatingPrincipal(false);
    }
  }

  async function createRole(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken) {
      setError("Enter your FORGE_ADMIN_TOKEN first");
      return;
    }
    setIsCreatingRole(true);
    setError(null);
    setSuccessMsg(null);

    let permissions: any;
    try {
      permissions = JSON.parse(newRolePerms);
      if (
        typeof permissions !== "object" ||
        permissions === null ||
        Array.isArray(permissions)
      ) {
        throw new Error("Permissions must be a JSON object");
      }
    } catch (err: any) {
      setError("Invalid JSON permissions: " + (err.message || ""));
      setIsCreatingRole(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/admin/roles`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: newRoleName.trim(),
          description: newRoleDesc.trim() || null,
          permissions,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok)
        throw new Error(body?.detail || body?.title || "Failed to create role");

      setSuccessMsg("Role created");
      setNewRoleName("");
      setNewRoleDesc("");
      setNewRolePerms('{\n  "deployments:read": true\n}');
      await fetchAll();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create role";
      setError(msg);
    } finally {
      setIsCreatingRole(false);
    }
  }

  async function createAdminToken(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken || !selectedPrincipalId) {
      setError("Select a principal and enter admin token");
      return;
    }
    setIsCreatingToken(true);
    setError(null);
    setSuccessMsg(null);
    setJustCreatedToken(null);

    try {
      const payload: any = { principal_id: selectedPrincipalId };
      if (tokenDesc.trim()) payload.description = tokenDesc.trim();
      if (tokenExpires !== "") payload.expires_in_days = Number(tokenExpires);

      const res = await fetch(`${API_BASE}/admin/admin-tokens`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok)
        throw new Error(
          body?.detail || body?.title || "Failed to issue admin token",
        );

      const created: CreatedAdminToken = body;
      setJustCreatedToken(created);

      // Optimistic list update
      const newSummary: AdminTokenSummary = {
        token_hash_prefix: created.prefix,
        principal_id: created.principal_id,
        description: created.description,
        expires_at: created.expires_at,
        revoked_at: null,
        created_at: new Date().toISOString(),
      };
      setAdminTokens((prev) => [newSummary, ...prev]);

      setSuccessMsg(
        "Admin token issued — copy it now. It will never be shown again.",
      );
      setTokenDesc("");
      setTokenExpires("");
      setSelectedPrincipalId("");
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to issue admin token";
      setError(msg);
    } finally {
      setIsCreatingToken(false);
    }
  }

  async function revokeAdminToken(prefix: string) {
    if (!adminToken) return;
    if (!confirm(`Revoke admin token ${prefix}*? This cannot be undone.`))
      return;

    setIsRevoking(prefix);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/admin/admin-tokens/${prefix}`, {
        method: "DELETE",
        headers,
      });
      if (!res.ok && res.status !== 204) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || "Failed to revoke");
      }
      setSuccessMsg(`Token ${prefix}* revoked`);
      await fetchAll();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Revoke failed";
      setError(msg);
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

  return (
    <div className="page-root">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">
          Access &amp; RBAC
        </h1>
        <p className="mt-0.5 text-[13px] text-[oklch(1_0_0/0.45)]">
          Principals, roles, and issued admin tokens. Set your admin token in
          the top bar to manage.
        </p>
      </div>

      <div className="space-y-8">
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

        {/* One-time admin token reveal (strong amber warning, copy once) */}
        {justCreatedToken && (
          <div className="mb-8 rounded-xl border-2 border-[var(--color-warning)]/70 bg-[var(--color-warning)]/10 p-6">
            <div className="flex items-start gap-4">
              <div className="mt-0.5 text-[var(--color-warning)]">
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
                <div className="font-semibold tracking-tight text-[var(--color-foreground)]">
                  One-time admin token — copy immediately
                </div>
                <div className="text-sm text-[var(--color-warning)]/80 mt-0.5">
                  This value is never stored or shown again. Use it in{" "}
                  <code>X-Admin-Token</code> for any /admin route.
                </div>

                <div className="mt-4 flex items-center gap-3 rounded-lg bg-[var(--color-card)] px-5 py-4 font-mono text-[15px] border border-[var(--color-warning)]/25 tracking-[0.5px] break-all select-all">
                  {justCreatedToken.token}
                </div>

                <div className="mt-3 flex items-center gap-3">
                  <button
                    onClick={() => copySecret(justCreatedToken.token)}
                    className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-warning)]/25 px-6 h-10 text-sm font-medium active:bg-[var(--color-warning)]/15 transition"
                  >
                    {copied ? "Copied to clipboard ✓" : "Copy secret"}
                  </button>
                  <button
                    onClick={() => setJustCreatedToken(null)}
                    className="text-sm text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)] underline underline-offset-2"
                  >
                    Dismiss
                  </button>
                  <div className="text-[10px] text-[var(--color-warning)]/60 ml-auto font-mono tracking-[1px]">
                    {justCreatedToken.prefix}••••
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Principals */}
          <div className="rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <div className="text-base font-semibold tracking-tight">
                  Principals
                </div>
                <div className="text-sm text-[var(--color-muted-foreground)] mt-1">
                  Human operators or API keys that can hold roles.
                </div>
              </div>
            </div>

            <form onSubmit={createPrincipal} className="space-y-4 mb-6">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <input
                  value={newPrincipalName}
                  onChange={(e) => setNewPrincipalName(e.target.value)}
                  placeholder="alice or ci-deployer"
                  className="input sm:col-span-2"
                  required
                />
                <select
                  value={newPrincipalType}
                  onChange={(e) => setNewPrincipalType(e.target.value as any)}
                  className="select"
                >
                  <option value="user">user</option>
                  <option value="api_key">api_key</option>
                </select>
              </div>
              <button
                type="submit"
                disabled={isCreatingPrincipal || !hasAdminToken}
                className="btn btn-primary w-full justify-center"
              >
                {isCreatingPrincipal ? "Creating..." : "Create Principal"}
              </button>
            </form>

            <div className="space-y-2 text-sm">
              {principals.length === 0 && !isLoading && (
                <div className="text-[var(--color-muted-foreground)]">
                  No principals yet.
                </div>
              )}
              {principals.map((p) => (
                <div
                  key={p.id}
                  className="flex items-center justify-between rounded-md border border-[oklch(1_0_0/0.07)] px-4 py-2.5"
                >
                  <div>
                    <span className="font-medium">{p.name}</span>
                    <span className="ml-2 text-[10px] rounded-full border px-2 py-px text-[var(--color-muted-foreground)]">
                      {p.principal_type}
                    </span>
                  </div>
                  <div className="font-mono text-[10px] text-[var(--color-muted-foreground)]">
                    {p.id.slice(0, 8)}…
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Roles */}
          <div className="rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <div className="text-base font-semibold tracking-tight">
                  Roles
                </div>
                <div className="text-sm text-[var(--color-muted-foreground)] mt-1">
                  JSONB permissions. * and ns:* wildcards supported.
                </div>
              </div>
            </div>

            <form onSubmit={createRole} className="space-y-4 mb-6">
              <input
                value={newRoleName}
                onChange={(e) => setNewRoleName(e.target.value)}
                placeholder="Role name (e.g. deployer)"
                className="input"
                required
              />
              <input
                value={newRoleDesc}
                onChange={(e) => setNewRoleDesc(e.target.value)}
                placeholder="Optional description"
                className="input"
              />
              <div>
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  PERMISSIONS (JSON object)
                </label>
                <textarea
                  value={newRolePerms}
                  onChange={(e) => setNewRolePerms(e.target.value)}
                  rows={4}
                  className="textarea font-mono text-sm"
                />
              </div>
              <button
                type="submit"
                disabled={isCreatingRole || !hasAdminToken}
                className="btn btn-primary w-full justify-center"
              >
                {isCreatingRole ? "Creating..." : "Create Role"}
              </button>
            </form>

            <div className="space-y-2 text-sm">
              {roles.length === 0 && !isLoading && (
                <div className="text-[var(--color-muted-foreground)]">
                  No roles loaded.
                </div>
              )}
              {roles.map((r) => (
                <div
                  key={r.id}
                  className="rounded-md border border-[oklch(1_0_0/0.07)] px-4 py-2.5"
                >
                  <div className="flex items-baseline gap-2">
                    <span className="font-semibold">{r.name}</span>
                    {r.description && (
                      <span className="text-[var(--color-muted-foreground)] text-xs">
                        — {r.description}
                      </span>
                    )}
                  </div>
                  <pre className="mt-2 text-[10px] bg-[var(--color-muted)]/20 p-2 rounded-xl overflow-auto">
                    {JSON.stringify(r.permissions, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Issued Admin Tokens */}
        <div className="mt-6 rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="text-base font-semibold tracking-tight">
                Issued Admin Tokens
              </div>
              <div className="text-sm text-[var(--color-muted-foreground)] mt-1">
                These tokens can be used in X-Admin-Token for any admin
                operation (subject to their roles).
              </div>
            </div>
          </div>

          <form onSubmit={createAdminToken} className="space-y-4 mb-8">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-1">
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  PRINCIPAL
                </label>
                <select
                  value={selectedPrincipalId}
                  onChange={(e) => setSelectedPrincipalId(e.target.value)}
                  className="w-full rounded-lg border border-[var(--color-input)] bg-[var(--color-card)] px-5 py-3 text-[15px] focus:outline-none focus:ring-2 focus:ring-[var(--color-ring)]"
                  required
                >
                  <option value="">Select principal…</option>
                  {principals.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.principal_type})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  DESCRIPTION
                </label>
                <input
                  value={tokenDesc}
                  onChange={(e) => setTokenDesc(e.target.value)}
                  placeholder="ops team — staging"
                  className="input"
                />
              </div>
              <div>
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                  EXPIRES
                </label>
                <select
                  value={tokenExpires}
                  onChange={(e) =>
                    setTokenExpires(
                      e.target.value === "" ? "" : Number(e.target.value),
                    )
                  }
                  className="w-full rounded-lg border border-[var(--color-input)] bg-[var(--color-card)] px-5 py-3 text-[15px] focus:outline-none focus:ring-2 focus:ring-[var(--color-ring)]"
                >
                  <option value="">Never</option>
                  <option value={7}>7 days</option>
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                  <option value={365}>1 year</option>
                </select>
              </div>
            </div>
            <button
              type="submit"
              disabled={
                isCreatingToken || !hasAdminToken || !selectedPrincipalId
              }
              className="btn btn-primary w-full justify-center"
            >
              {isCreatingToken
                ? "Issuing token..."
                : "Issue Admin Token (one-time secret)"}
            </button>
            <p className="text-[10px] text-[var(--color-muted-foreground)]">
              The raw token is returned only in the response above. It is stored
              hashed in the database.
            </p>
          </form>

          {/* Tokens table */}
          <div>
            <div className="flex items-center justify-between mb-3 px-1">
              <div className="text-sm font-semibold">
                Active &amp; revoked tokens
              </div>
              <button
                onClick={fetchAll}
                disabled={isLoading || !hasAdminToken}
                className="text-sm underline underline-offset-2 disabled:opacity-50"
              >
                Refresh
              </button>
            </div>

            {adminTokens.length === 0 && !isLoading && (
              <div className="text-sm text-[var(--color-muted-foreground)] px-1">
                No admin tokens issued yet.
              </div>
            )}

            <div className="space-y-2">
              {adminTokens.map((t) => (
                <div
                  key={t.token_hash_prefix}
                  className="flex items-center justify-between rounded-md border border-[oklch(1_0_0/0.07)] px-4 py-2.5 text-sm"
                >
                  <div className="flex items-center gap-4 font-mono">
                    <button
                      onClick={() =>
                        navigator.clipboard.writeText(t.token_hash_prefix)
                      }
                      className="hover:underline"
                    >
                      {t.token_hash_prefix}••••
                    </button>
                    <span className="text-[var(--color-muted-foreground)]">
                      → {t.principal_id.slice(0, 8)}
                    </span>
                    {t.description && (
                      <span className="text-[var(--color-muted-foreground)]">
                        · {t.description}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-4 text-xs text-[var(--color-muted-foreground)]">
                    {t.expires_at && (
                      <span>expires {formatDate(t.expires_at)}</span>
                    )}
                    {t.revoked_at ? (
                      <span className="text-[var(--color-destructive)]">
                        revoked
                      </span>
                    ) : (
                      <button
                        onClick={() => revokeAdminToken(t.token_hash_prefix)}
                        disabled={isRevoking === t.token_hash_prefix}
                        className="text-[var(--color-destructive)] hover:text-[var(--color-destructive)] underline disabled:opacity-50"
                      >
                        {isRevoking === t.token_hash_prefix
                          ? "Revoking..."
                          : "Revoke"}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-10 text-[10px] text-[var(--color-muted-foreground)] px-1">
          All actions use the same X-Admin-Token bootstrap as the rest of the
          admin surface. Issued tokens are additive and subject to the roles
          assigned to their principal.
        </div>
      </div>
    </div>
  );
}
