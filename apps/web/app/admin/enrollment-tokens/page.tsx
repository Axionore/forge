"use client";

import React from "react";

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
  const [adminToken, setAdminToken] = React.useState("");
  const [showAdminToken, setShowAdminToken] = React.useState(false);

  const [description, setDescription] = React.useState("");
  const [expiresInDays, setExpiresInDays] = React.useState<number | "">("");
  const [maxUses, setMaxUses] = React.useState(1);

  const [isCreating, setIsCreating] = React.useState(false);
  const [justCreated, setJustCreated] = React.useState<CreatedToken | null>(null);
  const [copied, setCopied] = React.useState(false);

  const [tokens, setTokens] = React.useState<TokenSummary[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [isRevoking, setIsRevoking] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);

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
      const res = await fetch(`${API_BASE}/admin/enrollment-tokens`, { headers });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || body?.title || `Request failed (${res.status})`);
      }
      const data = await res.json();
      setTokens(data.tokens || []);
    } catch (e: any) {
      setError(e.message || "Failed to load tokens");
    } finally {
      setIsLoading(false);
    }
  }, [adminToken, headers]);

  React.useEffect(() => {
    if (adminToken) {
      fetchTokens();
    }
  }, [adminToken, fetchTokens]);

  // Auto refresh every 30s while admin token present
  React.useEffect(() => {
    if (!adminToken) return;
    const id = setInterval(() => {
      fetchTokens();
    }, 30000);
    return () => clearInterval(id);
  }, [adminToken, fetchTokens]);

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
      const payload: { description?: string; expires_in_days?: number; max_uses?: number } = {};
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

      setSuccessMsg("Token issued successfully. Copy the secret now — it will not be shown again.");
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

  function copyPrefix(prefix: string) {
    navigator.clipboard.writeText(prefix).catch(() => {});
  }

  function formatDate(d: string | null) {
    if (!d) return "—";
    return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(d));
  }

  function StatusPill({ status }: { status: TokenSummary["status"] }) {
    const styles: Record<TokenSummary["status"], string> = {
      active: "bg-[oklch(0.55_0.18_145)]/10 text-[oklch(0.45_0.15_145)] border-[oklch(0.55_0.18_145)]/30",
      used: "bg-[oklch(0.55_0.22_25)]/10 text-[oklch(0.50_0.20_25)] border-[oklch(0.55_0.22_25)]/30",
      expired: "bg-[oklch(0.75_0.18_85)]/10 text-[oklch(0.55_0.15_85)] border-[oklch(0.75_0.18_85)]/30",
      revoked: "bg-[oklch(0.45_0.02_260)]/10 text-[oklch(0.40_0.02_260)] border-[oklch(0.45_0.02_260)]/30",
    };
    return (
      <span className={`inline-flex items-center rounded-full border px-2.5 py-px text-[11px] font-medium tracking-tight ${styles[status]}`}>
        {status}
      </span>
    );
  }

  const hasAdminToken = adminToken.length >= 12;

  return (
    <div className="min-h-screen bg-[var(--color-background)] text-[var(--color-foreground)]">
      <header className="border-b bg-[var(--color-card)]/80 backdrop-blur supports-[backdrop-filter]:bg-[var(--color-card)]/60 sticky top-0 z-50">
        <div className="mx-auto max-w-6xl px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded bg-[var(--color-primary)]" />
            <div>
              <div className="font-semibold tracking-tighter text-lg">Forge</div>
              <div className="text-[10px] text-[var(--color-muted-foreground)] -mt-1">CONTROL PLANE</div>
            </div>
            <div className="ml-4 text-sm font-medium text-[var(--color-muted-foreground)]">Enrollment Tokens</div>
          </div>

          <div className="flex items-center gap-3 text-sm">
            <a href="/" className="text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)] transition">← Back to home</a>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10">
        {/* Admin token bootstrap */}
        <div className="mb-8 rounded-2xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-5">
          <div className="flex items-start justify-between gap-6">
            <div className="flex-1">
              <div className="text-xs uppercase tracking-[0.5px] font-medium text-[var(--color-muted-foreground)] mb-1">OPERATOR AUTH</div>
              <div className="font-semibold tracking-tight">Admin Token</div>
              <p className="mt-1 text-sm text-[var(--color-muted-foreground)] max-w-md">
                Paste your <code className="font-mono text-xs bg-muted px-1 py-px rounded">FORGE_ADMIN_TOKEN</code> from the control plane environment. It is stored only in memory for this session.
              </p>
            </div>
            <div className="w-80">
              <div className="relative">
                <input
                  type={showAdminToken ? "text" : "password"}
                  value={adminToken}
                  onChange={(e) => setAdminToken(e.target.value.trim())}
                  placeholder="forge_admin_xxxxxxxxxxxxxxxx"
                  className="w-full rounded-xl border border-[var(--color-input)] bg-white px-4 py-2.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-ring)] placeholder:text-[var(--color-muted-foreground)]/60"
                />
                <button
                  type="button"
                  onClick={() => setShowAdminToken(!showAdminToken)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-medium text-[var(--color-muted-foreground)] hover:text-foreground"
                >
                  {showAdminToken ? "HIDE" : "SHOW"}
                </button>
              </div>
              <div className="mt-1.5 text-[10px] text-[var(--color-muted-foreground)]">Required for all issuance and revocation actions.</div>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="font-medium underline">Dismiss</button>
          </div>
        )}
        {successMsg && (
          <div className="mb-6 rounded-xl border border-[var(--color-success)]/30 bg-[var(--color-success)]/5 px-4 py-3 text-sm text-[var(--color-success)] flex items-center justify-between">
            <span>{successMsg}</span>
            <button onClick={() => setSuccessMsg(null)} className="font-medium underline">Dismiss</button>
          </div>
        )}

        {/* Issue form */}
        <div className="rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-8 mb-8 shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="font-semibold tracking-tighter text-2xl">Issue new enrollment token</div>
              <div className="text-sm text-[var(--color-muted-foreground)] mt-1">Agents use this one-time (or limited-use) secret to join the mesh and receive signed work.</div>
            </div>
          </div>

          <form onSubmit={createToken} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2">
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">DESCRIPTION (OPTIONAL)</label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="hetzner node-03 — staging"
                  className="w-full rounded-2xl border border-[var(--color-input)] px-5 py-3 text-[15px] focus:outline-none focus:ring-2 focus:ring-[var(--color-ring)] bg-white placeholder:text-[var(--color-muted-foreground)]/50"
                />
              </div>

              <div>
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">EXPIRES IN</label>
                <select
                  value={expiresInDays}
                  onChange={(e) => setExpiresInDays(e.target.value === "" ? "" : Number(e.target.value))}
                  className="w-full rounded-2xl border border-[var(--color-input)] bg-white px-5 py-3 text-[15px] focus:outline-none focus:ring-2 focus:ring-[var(--color-ring)]"
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
                <label className="block text-xs font-medium tracking-widest text-[var(--color-muted-foreground)] mb-1.5">MAX USES</label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={maxUses}
                    onChange={(e) => setMaxUses(Math.max(1, Math.min(100, parseInt(e.target.value) || 1)))}
                    className="w-28 rounded-2xl border border-[var(--color-input)] bg-white px-5 py-3 text-[15px] tabular-nums focus:outline-none focus:ring-2 focus:ring-[var(--color-ring)]"
                  />
                  <div className="text-xs text-[var(--color-muted-foreground)]">1 = single-use (recommended for production nodes)</div>
                </div>
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isCreating || !hasAdminToken}
                className="inline-flex h-12 items-center justify-center rounded-2xl bg-[var(--color-primary)] px-10 text-base font-semibold text-white transition active:scale-[0.985] disabled:cursor-not-allowed disabled:opacity-60 hover:bg-[var(--color-primary)]/90"
              >
                {isCreating ? "Issuing secure token…" : "Issue enrollment token"}
              </button>
              {!hasAdminToken && <span className="ml-4 text-xs text-[var(--color-muted-foreground)]">Enter admin token above to enable issuance</span>}
            </div>
          </form>
        </div>

        {/* One-time secret reveal — only after successful create */}
        {justCreated && (
          <div className="mb-8 rounded-3xl border-2 border-amber-400/70 bg-amber-50/60 p-6">
            <div className="flex items-start gap-4">
              <div className="mt-0.5 text-amber-500">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 9v4m0 4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/></svg>
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-semibold tracking-tight text-amber-950">One-time secret — copy immediately</div>
                <div className="text-sm text-amber-900/80 mt-0.5">This value is never stored or shown again after you leave this page.</div>

                <div className="mt-4 flex items-center gap-3 rounded-2xl bg-white px-5 py-4 font-mono text-[15px] border border-amber-200 tracking-[0.5px] break-all select-all">
                  {justCreated.token}
                </div>

                <div className="mt-3 flex items-center gap-3">
                  <button
                    onClick={() => copySecret(justCreated.token)}
                    className="inline-flex items-center gap-2 rounded-2xl bg-white border border-amber-200 px-6 h-10 text-sm font-medium active:bg-amber-100 transition"
                  >
                    {copied ? (
                      <>Copied to clipboard ✓</>
                    ) : (
                      <>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.25"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        Copy secret
                      </>
                    )}
                  </button>
                  <button onClick={() => setJustCreated(null)} className="text-sm text-amber-950/70 hover:text-amber-950 underline underline-offset-2">Dismiss</button>
                  <div className="text-[10px] text-amber-900/60 ml-auto font-mono tracking-[1px]">{justCreated.prefix}••••</div>
                </div>

                {/* Tier 2 Bootstrap UX: One-liner install command */}
                <div className="mt-6 rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
                  <div className="text-xs font-medium tracking-widest text-emerald-700 mb-1.5">ONE-COMMAND SERVER BOOTSTRAP (copy &amp; paste on the target machine)</div>
                  <code className="block bg-white border border-emerald-200 rounded-xl p-3 text-[13px] font-mono text-emerald-950 break-all">
                    curl -fsSL {typeof window !== 'undefined' ? window.location.origin : 'https://your-forge.example.com'}/install-agent.sh | bash -s -- --enrollment-token="{justCreated.token}" --control-plane="{typeof window !== 'undefined' ? window.location.origin : 'https://your-forge.example.com'}"
                  </code>
                  <div className="mt-2 text-[11px] text-emerald-700/80">The script installs the agent, sets up systemd (on Linux), and enrolls using this token. The token is one-time and will be revoked after use in a future improvement.</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* List */}
        <div>
          <div className="flex items-center justify-between mb-3 px-1">
            <div className="font-semibold tracking-tighter text-xl">All enrollment tokens</div>
            <button
              onClick={fetchTokens}
              disabled={isLoading || !hasAdminToken}
              className="flex items-center gap-2 rounded-full border border-[var(--color-card-border)] bg-white px-4 h-9 text-sm font-medium disabled:opacity-50 active:bg-[var(--color-muted)]"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 21H3v-5"/></svg>
              Refresh
            </button>
          </div>

          <div className="rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--color-card-border)] bg-[var(--color-muted)]/40 text-left text-[11px] uppercase tracking-[1px] text-[var(--color-muted-foreground)]">
                    <th className="pl-6 py-3 font-medium">PREFIX</th>
                    <th className="py-3 font-medium">DESCRIPTION</th>
                    <th className="py-3 font-medium">STATUS</th>
                    <th className="py-3 font-medium tabular-nums">USES</th>
                    <th className="py-3 font-medium">CREATED</th>
                    <th className="py-3 font-medium">EXPIRES</th>
                    <th className="pr-6 py-3 w-24"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-card-border)]">
                  {isLoading && tokens.length === 0 && (
                    Array.from({ length: 3 }).map((_, i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="pl-6 py-4"><div className="h-4 w-16 bg-[var(--color-muted)] rounded" /></td>
                        <td className="py-4"><div className="h-4 w-40 bg-[var(--color-muted)] rounded" /></td>
                        <td className="py-4"><div className="h-5 w-14 bg-[var(--color-muted)] rounded-full" /></td>
                        <td className="py-4"><div className="h-4 w-8 bg-[var(--color-muted)] rounded" /></td>
                        <td className="py-4"><div className="h-4 w-28 bg-[var(--color-muted)] rounded" /></td>
                        <td className="py-4"><div className="h-4 w-20 bg-[var(--color-muted)] rounded" /></td>
                        <td className="pr-6"></td>
                      </tr>
                    ))
                  )}

                  {!isLoading && tokens.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-6 py-16 text-center text-[var(--color-muted-foreground)]">
                        {hasAdminToken ? "No tokens have been issued yet." : "Enter your admin token to view and manage enrollment tokens."}
                      </td>
                    </tr>
                  )}

                  {tokens.map((t) => {
                    const isActive = t.status === "active";
                    return (
                      <tr key={t.token_hash_prefix} className="hover:bg-[var(--color-muted)]/30 transition-colors">
                        <td className="pl-6 py-3.5 font-mono text-xs tracking-[2px] text-[var(--color-muted-foreground)] cursor-pointer" onClick={() => copyPrefix(t.token_hash_prefix)} title="Click to copy prefix">
                          {t.token_hash_prefix}••••
                        </td>
                        <td className="py-3.5 pr-4 text-[15px] text-[var(--color-foreground)]/90">{t.description || <span className="text-[var(--color-muted-foreground)]">—</span>}</td>
                        <td className="py-3.5"><StatusPill status={t.status} /></td>
                        <td className="py-3.5 tabular-nums font-medium">{t.uses_count}<span className="text-[var(--color-muted-foreground)]">/{t.max_uses}</span></td>
                        <td className="py-3.5 text-[var(--color-muted-foreground)]">{formatDate(t.created_at)}</td>
                        <td className="py-3.5 text-[var(--color-muted-foreground)]">{formatDate(t.expires_at)}</td>
                        <td className="pr-6 py-3.5 text-right">
                          {isActive && (
                            <button
                              onClick={() => revokeToken(t.token_hash_prefix)}
                              disabled={isRevoking === t.token_hash_prefix}
                              className="inline-flex items-center gap-1 rounded-full border border-[var(--color-card-border)] px-3 py-1 text-xs font-medium text-[var(--color-destructive)] hover:bg-red-50 active:bg-red-100 disabled:opacity-50"
                            >
                              {isRevoking === t.token_hash_prefix ? "Revoking…" : "Revoke"}
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
            Tokens are single-use by default. Multi-use tokens are intended only for automated provisioning scripts you fully control.
          </div>
        </div>
      </main>

      <footer className="border-t mt-16 py-6 text-center text-xs text-[var(--color-muted-foreground)]">
        Forge Control Plane • Enrollment is the root of trust for every agent
      </footer>
    </div>
  );
}
