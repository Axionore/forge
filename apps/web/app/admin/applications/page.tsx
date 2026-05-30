"use client";

import React from "react";
import Link from "next/link";
import * as Dialog from "@radix-ui/react-dialog";
import { toast } from "sonner";

const API_BASE = "http://localhost:3000";

type AppKind = "git" | "dockerfile" | "compose" | "template";

interface Application {
  id: string;
  name: string;
  description: string | null;
  kind: string | null;
  status: string | null;
  created_at: string;
  updated_at: string;
  created_by_principal_id: string | null;
}

const KINDS: { kind: AppKind; label: string; desc: string }[] = [
  {
    kind: "git",
    label: "Git Repository",
    desc: "Connect a Git repo. Age-encrypted secrets supported.",
  },
  {
    kind: "dockerfile",
    label: "Dockerfile",
    desc: "Build from a Dockerfile in a repo.",
  },
  {
    kind: "compose",
    label: "Docker Compose",
    desc: "Multi-service from a Compose file.",
  },
  {
    kind: "template",
    label: "Template",
    desc: "Pre-built Forge template (coming soon).",
  },
];

function copyToClipboard(text: string) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      toast.success("Copied to clipboard");
    })
    .catch(() => {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      toast.success("Copied to clipboard");
    });
}

export default function ApplicationsPage() {
  const [adminToken, setAdminToken] = React.useState("");
  const [showAdminToken, setShowAdminToken] = React.useState(false);
  const [applications, setApplications] = React.useState<Application[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [oneTimeSecret, setOneTimeSecret] = React.useState<string | null>(null); // preserved for future real one-time secrets (e.g. age enrollment)

  const [isWizardOpen, setIsWizardOpen] = React.useState(false);
  const [wizardStep, setWizardStep] = React.useState<"select" | "details">(
    "select",
  );
  const [selectedKind, setSelectedKind] = React.useState<AppKind | null>(null);
  const [formData, setFormData] = React.useState<{
    name?: string;
    repoUrl?: string;
    branch?: string;
    ageKeyPath?: string;
  }>({});

  // Phase 1 Quick Deploy (real signed job dispatch)
  const [quickDeployApp, setQuickDeployApp] =
    React.useState<Application | null>(null);
  const [quickDeployImage, setQuickDeployImage] =
    React.useState("nginx:alpine");
  const [quickDeployAgent, setQuickDeployAgent] = React.useState("");
  const [isDeploying, setIsDeploying] = React.useState(false);

  // Quick deploy registry support (Slice C polish - consistent with detail page)
  const [quickDeployRegistryServer, setQuickDeployRegistryServer] =
    React.useState("");
  const [quickDeployRegistryUser, setQuickDeployRegistryUser] =
    React.useState("");
  const [quickDeployRegistryPass, setQuickDeployRegistryPass] =
    React.useState("");

  const headers = React.useMemo(() => {
    const h = new Headers();
    h.set("Content-Type", "application/json");
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  const loadApplications = React.useCallback(async () => {
    if (!adminToken) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/admin/applications`, { headers });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Failed to load applications (${res.status}) ${text}`);
      }
      const data: Application[] = await res.json();
      setApplications(data);
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to load applications";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [adminToken, headers]);

  React.useEffect(() => {
    if (adminToken) {
      void loadApplications();
    } else {
      setApplications([]);
    }
  }, [adminToken, loadApplications]);

  const createApplication = async (payload: {
    name: string;
    kind: AppKind;
    config: Record<string, unknown>;
  }) => {
    if (!adminToken) {
      setError("Enter your FORGE_ADMIN_TOKEN first (from Access page)");
      return;
    }
    setIsLoading(true);
    setError(null);

    const body = {
      name: payload.name,
      description: null,
      // kind and spec are set server-side in Phase 0 foundation; real wizard will send richer payload in Phase 1
    };

    try {
      const res = await fetch(`${API_BASE}/admin/applications`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        if (res.status === 403) {
          throw new Error(
            "Forbidden — your principal does not have applications:create permission",
          );
        }
        throw new Error(`Create failed (${res.status}) ${text}`);
      }

      const created: Application = await res.json();
      setApplications((prev) => [created, ...prev]);
      setIsWizardOpen(false);
      setWizardStep("select");
      setSelectedKind(null);
      setFormData({});

      toast.success(
        `Application "${created.name}" created (real backend + RBAC + audit)`,
      );
      // In a future slice the response can carry a one-time secret (age enrollment etc.) → setOneTimeSecret here
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to create application";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // Real Phase 1 deploy — reuses the exact same endpoint + dispatch path the deployments page uses
  async function quickDeploy(app: Application) {
    if (!adminToken) {
      setError("Enter your FORGE_ADMIN_TOKEN first");
      return;
    }
    setIsDeploying(true);
    setError(null);

    const container: any = {
      name: "app",
      image: quickDeployImage,
      env: [],
      ports: ["80"],
      expose: [],
      volumes: [],
      tmpfs: [],
      restart_policy: "unless-stopped",
      resources: null,
    };

    // Support private registry in quick deploy (consistent with detail page - Phase 1 complete)
    if (
      quickDeployRegistryServer &&
      (quickDeployRegistryUser || quickDeployRegistryPass)
    ) {
      container.registry_auth = {
        serveraddress: quickDeployRegistryServer,
        username: quickDeployRegistryUser || undefined,
        password: quickDeployRegistryPass || undefined,
      };
    }

    const spec: any = {
      containers: [container],
      networks: [],
      network_specs: [],
      volumes: [],
    };

    if (
      quickDeployRegistryServer &&
      (quickDeployRegistryUser || quickDeployRegistryPass)
    ) {
      spec.registry_credentials = [
        [
          quickDeployRegistryServer,
          {
            username: quickDeployRegistryUser || undefined,
            password: quickDeployRegistryPass || undefined,
          },
        ],
      ];
    }

    const strategy = {
      type: "rolling",
      max_unavailable: 1,
      max_surge: 1,
      health_check_grace_period_secs: 30,
      rollback_on_failure: true,
      failure_threshold: 3,
    };

    const targets = quickDeployAgent
      ? [{ agent_id: quickDeployAgent, replicas: 1 }]
      : [];

    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${app.id}/deployments`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({ spec, strategy, targets }),
        },
      );

      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`Deploy failed (${res.status}) ${body}`);
      }

      toast.success(
        `Deploy dispatched for ${app.name} — check Deployments page for logs & status`,
      );
      setQuickDeployApp(null);
      setQuickDeployImage("nginx:alpine");
      setQuickDeployAgent("");
      // Refresh the list so status can update later
      await loadApplications();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Deploy failed";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsDeploying(false);
    }
  }

  const submitWizard = () => {
    if (!selectedKind || !formData.name?.trim()) return;
    void createApplication({
      name: formData.name.trim(),
      kind: selectedKind,
      config: { repoUrl: formData.repoUrl, branch: formData.branch || "main" },
    });
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)] text-[var(--color-foreground)]">
      {/* Header - exact pattern from access + deployments */}
      <header className="sticky top-0 z-50 border-b border-[var(--color-border)] bg-[var(--color-card)]/95 backdrop-blur">
        <div className="mx-auto max-w-7xl px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded bg-[var(--color-primary)]" />
            <div>
              <div className="font-semibold tracking-tighter text-lg">
                Forge
              </div>
              <div className="text-[10px] text-[var(--color-muted-foreground)] -mt-1">
                CONTROL PLANE
              </div>
            </div>
            <div className="ml-4 text-sm font-medium text-[var(--color-muted-foreground)]">
              Applications
            </div>
          </div>
          <nav className="flex items-center gap-1 text-sm">
            <Link
              href="/admin/access"
              className="px-3 py-1.5 rounded-md hover:bg-[var(--color-muted)]"
            >
              Access
            </Link>
            <Link
              href="/admin/enrollment-tokens"
              className="px-3 py-1.5 rounded-md hover:bg-[var(--color-muted)]"
            >
              Add Server
            </Link>
            <Link
              href="/admin/deployments"
              className="px-3 py-1.5 rounded-md hover:bg-[var(--color-muted)]"
            >
              Deployments
            </Link>
            <Link
              href="/admin/applications"
              className="px-3 py-1.5 rounded-md bg-[var(--color-muted)] font-medium"
            >
              Applications
            </Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8 space-y-8">
        <div>
          <div className="flex items-baseline gap-3">
            <h1 className="text-3xl font-semibold tracking-tight">
              Applications
            </h1>
            <Link
              href="/admin/enrollment-tokens"
              className="text-xs px-2.5 py-0.5 rounded-full border border-emerald-500/30 bg-[var(--color-success)]/120/5 text-emerald-700 hover:bg-[var(--color-success)]/120/10"
            >
              Servers online → Add more
            </Link>
          </div>
          <p className="text-[var(--color-muted-foreground)] mt-1">
            Catalog of deployable units from Git, Dockerfiles, Compose, and
            templates. Deployments target real enrolled agents with signed jobs
            and per-agent age envelopes.
          </p>
          <Link
            href="/admin/enrollment-tokens"
            className="inline-flex mt-3 items-center gap-2 text-sm font-medium rounded-2xl border border-violet-500/30 bg-violet-500/5 px-4 h-9 hover:bg-violet-500/10"
          >
            🖥️ Add Server / Scale capacity →{" "}
            <span className="text-xs text-violet-600">
              (Ed25519 identity + age secrets per server — never plaintext in
              control plane)
            </span>
          </Link>
        </div>

        {/* Admin Token bootstrap card - exact pattern from access + deployments (real X-Admin-Token) */}
        <div className="rounded-3xl border border-[var(--color-border)] bg-[var(--color-card)] p-6">
          <div className="flex items-center justify-between mb-3">
            <div className="font-medium">Admin Token (FORGE_ADMIN_TOKEN)</div>
          </div>
          <div className="flex gap-3">
            <input
              type={showAdminToken ? "text" : "password"}
              value={adminToken}
              onChange={(e) => setAdminToken(e.target.value)}
              placeholder="Paste your strong bootstrap token"
              className="flex-1 rounded-2xl border border-[var(--color-input)] bg-[var(--color-background)] px-4 py-2.5 text-sm font-mono"
            />
            <button
              type="button"
              onClick={() => setShowAdminToken(!showAdminToken)}
              className="px-4 rounded-2xl border border-[var(--color-border)] text-sm"
            >
              {showAdminToken ? "Hide" : "Show"}
            </button>
            <Link
              href="/admin/access"
              className="px-4 py-2.5 rounded-2xl border border-[var(--color-border)] text-sm hover:bg-[var(--color-muted)]"
            >
              Manage
            </Link>
          </div>
          <div className="mt-2 text-xs text-[var(--color-muted-foreground)]">
            This page now calls the real /admin/applications endpoints (RBAC +
            audit enforced on create).
          </div>
        </div>

        {/* Error banner (real) */}
        {error && (
          <div className="rounded-3xl border border-red-500/30 bg-[var(--color-destructive)]/100/5 p-4 text-sm text-[var(--color-destructive)]">
            {error}
            <button onClick={() => setError(null)} className="ml-4 underline">
              dismiss
            </button>
          </div>
        )}

        {/* Exact amber one-time secret banner (copy-once, dismiss, redacted) */}
        {oneTimeSecret && (
          <div className="rounded-3xl border border-amber-500/30 bg-[var(--color-warning)]/100/5 p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="font-semibold text-amber-600">
                  One-time secret — copy now
                </div>
                <p className="text-sm text-amber-600/90 mt-0.5">
                  It will never be shown again.
                </p>
              </div>
              <button
                onClick={() => setOneTimeSecret(null)}
                className="text-amber-600/70 hover:text-amber-600 text-2xl leading-none -mt-1"
              >
                ×
              </button>
            </div>
            <pre className="mt-4 font-mono text-sm bg-black/60 p-4 rounded-2xl overflow-x-auto whitespace-pre-wrap break-all select-all border border-amber-500/20">
              {oneTimeSecret}
            </pre>
            <div className="mt-4 flex gap-3">
              <button
                onClick={() => copyToClipboard(oneTimeSecret)}
                className="px-4 py-2 rounded-2xl bg-[var(--color-warning)]/100 text-black text-sm font-medium hover:bg-amber-400"
              >
                Copy secret
              </button>
              <button
                onClick={() => setOneTimeSecret(null)}
                className="px-4 py-2 rounded-2xl border border-amber-500/30 text-amber-600 text-sm hover:bg-[var(--color-warning)]/100/10"
              >
                Dismiss (never shown again)
              </button>
            </div>
          </div>
        )}

        {/* Main catalog card */}
        <div className="rounded-3xl border border-[var(--color-border)] bg-[var(--color-card)] p-8">
          <div className="flex items-center justify-between mb-6">
            <div className="font-semibold text-lg tracking-tight">Catalog</div>
            <button
              onClick={() => {
                setIsWizardOpen(true);
                setWizardStep("select");
                setSelectedKind(null);
                setFormData({});
              }}
              className="px-5 py-2.5 rounded-2xl bg-[var(--color-primary)] text-[var(--color-primary-foreground)] text-sm font-medium hover:opacity-90"
            >
              Create Application
            </button>
          </div>

          {/* 4 async states - exact empty p-12, loading skeletons, error banner above, success grid (real API now) */}
          {isLoading ? (
            <div className="space-y-3">
              {[1, 2].map((i) => (
                <div
                  key={i}
                  className="rounded-2xl border border-[var(--color-border)] p-6 animate-pulse"
                >
                  <div className="flex justify-between">
                    <div className="space-y-2 flex-1">
                      <div className="h-5 bg-[var(--color-muted)] rounded w-2/5" />
                      <div className="h-3 bg-[var(--color-muted)] rounded w-1/4" />
                    </div>
                    <div className="h-6 w-20 bg-[var(--color-muted)] rounded-full" />
                  </div>
                </div>
              ))}
            </div>
          ) : applications.length === 0 ? (
            <div className="p-12 text-center">
              <p className="text-lg text-[var(--color-muted-foreground)]">
                No applications yet. Create your first from Git, Dockerfile,
                Compose or Template.
              </p>
              <button
                onClick={() => {
                  setIsWizardOpen(true);
                  setWizardStep("select");
                }}
                className="mt-6 px-6 py-3 rounded-2xl bg-[var(--color-primary)] text-[var(--color-primary-foreground)] font-medium text-sm"
              >
                Create Application
              </button>
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {applications.map((app) => (
                <div
                  key={app.id}
                  className="rounded-2xl border border-[var(--color-border)] p-6"
                >
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="font-semibold text-lg tracking-tight">
                        {app.name}
                      </div>
                      <div className="mt-1 text-xs uppercase tracking-widest text-[var(--color-muted-foreground)]">
                        {app.kind ?? "git"}
                      </div>
                    </div>
                    <div className="text-xs text-[var(--color-muted-foreground)]">
                      {new Date(app.created_at).toLocaleString()}
                    </div>
                  </div>
                  {app.status && (
                    <div className="mt-2 text-xs text-[var(--color-muted-foreground)]">
                      Status: {app.status}
                    </div>
                  )}

                  <div className="mt-4 flex gap-2">
                    {/* Primary: go to clean detail page with rich Deploy + live status/logs */}
                    <Link
                      href={`/admin/applications/${app.id}`}
                      className="flex-1 text-center rounded-2xl border border-[var(--color-border)] py-2 text-sm font-medium hover:bg-[var(--color-muted)]"
                    >
                      View details
                    </Link>
                    {/* Secondary fast path (list-level quick deploy) */}
                    <button
                      onClick={() => {
                        setQuickDeployApp(app);
                        setQuickDeployImage("nginx:alpine");
                      }}
                      className="flex-1 rounded-2xl bg-[var(--color-primary)] text-[var(--color-primary-foreground)] py-2 text-sm font-medium hover:opacity-90"
                    >
                      Quick Deploy
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      {/* Wizard Dialog - Radix + Service Catalog grid reuse */}
      <Dialog.Root open={isWizardOpen} onOpenChange={setIsWizardOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/70 z-50" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-3xl -translate-x-1/2 -translate-y-1/2 rounded-3xl border border-[var(--color-border)] bg-[var(--color-card)] p-8 shadow-2xl">
            <div className="flex justify-between mb-6">
              <Dialog.Title className="text-2xl font-semibold tracking-tight">
                Create Application
              </Dialog.Title>
              <Dialog.Close className="text-2xl leading-none">×</Dialog.Close>
            </div>

            {wizardStep === "select" && (
              <div>
                <div className="text-sm font-medium mb-4">Choose source</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {KINDS.map((k) => (
                    <button
                      key={k.kind}
                      onClick={() => {
                        setSelectedKind(k.kind);
                        setWizardStep("details");
                        setFormData({});
                      }}
                      className="rounded-2xl border border-[var(--color-border)] p-6 text-left hover:border-[var(--color-primary)]"
                    >
                      <div className="font-semibold text-lg tracking-tight">
                        {k.label}
                      </div>
                      <div className="text-sm text-[var(--color-muted-foreground)] mt-2">
                        {k.desc}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {wizardStep === "details" && selectedKind && (
              <div className="space-y-6">
                <button
                  onClick={() => setWizardStep("select")}
                  className="text-sm text-[var(--color-muted-foreground)]"
                >
                  ← Back
                </button>

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Application name
                  </label>
                  <input
                    value={formData.name || ""}
                    onChange={(e) =>
                      setFormData({ ...formData, name: e.target.value })
                    }
                    className="w-full rounded-2xl border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-3 text-sm"
                    placeholder="my-service"
                  />
                </div>

                {selectedKind === "git" && (
                  <>
                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Repository URL
                      </label>
                      <input
                        value={formData.repoUrl || ""}
                        onChange={(e) =>
                          setFormData({ ...formData, repoUrl: e.target.value })
                        }
                        className="w-full rounded-2xl border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-3 text-sm"
                        placeholder="https://github.com/org/repo.git"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium mb-2">
                          Branch
                        </label>
                        <input
                          value={formData.branch || "main"}
                          onChange={(e) =>
                            setFormData({ ...formData, branch: e.target.value })
                          }
                          className="w-full rounded-2xl border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-3 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium mb-2">
                          Age key path (optional)
                        </label>
                        <input
                          value={formData.ageKeyPath || ""}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              ageKeyPath: e.target.value,
                            })
                          }
                          className="w-full rounded-2xl border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-3 text-sm"
                          placeholder="~/.config/forge/age.key"
                        />
                      </div>
                    </div>
                  </>
                )}

                <div className="pt-4 flex justify-end gap-3">
                  <Dialog.Close className="px-5 py-2.5 rounded-2xl border border-[var(--color-border)]">
                    Cancel
                  </Dialog.Close>
                  <button
                    onClick={submitWizard}
                    disabled={!formData.name?.trim()}
                    className="px-6 py-2.5 rounded-2xl bg-[var(--color-primary)] text-[var(--color-primary-foreground)] disabled:opacity-60"
                  >
                    Create Application
                  </button>
                </div>
              </div>
            )}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Phase 1 Quick Deploy Modal — real signed Job::Deploy dispatch */}
      <Dialog.Root
        open={!!quickDeployApp}
        onOpenChange={(o) => !o && setQuickDeployApp(null)}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/70 z-50" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-3xl border border-[var(--color-border)] bg-[var(--color-card)] p-8 shadow-2xl">
            <Dialog.Title className="text-xl font-semibold tracking-tight mb-2">
              Quick Deploy — {quickDeployApp?.name}
            </Dialog.Title>
            <p className="text-sm text-[var(--color-muted-foreground)] mb-6">
              This will create a Deployment and send a real signed Job::Deploy
              to a connected agent (if any).
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1.5">
                  Container Image
                </label>
                <input
                  value={quickDeployImage}
                  onChange={(e) => setQuickDeployImage(e.target.value)}
                  className="w-full rounded-2xl border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-2.5 text-sm font-mono"
                  placeholder="nginx:alpine or ghcr.io/you/app:v1"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1.5">
                  Target Agent ID (optional — leave empty for any connected)
                </label>
                <input
                  value={quickDeployAgent}
                  onChange={(e) => setQuickDeployAgent(e.target.value)}
                  className="w-full rounded-2xl border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-2.5 text-sm font-mono"
                  placeholder="uuid of enrolled agent"
                />
              </div>

              {/* Registry support for quick deploy - consistent Phase 1 polish */}
              <div className="pt-2 border-t border-[var(--color-border)]">
                <div className="text-xs font-medium text-[var(--color-muted-foreground)] mb-1.5">
                  Private Registry (optional)
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <input
                    value={quickDeployRegistryServer}
                    onChange={(e) =>
                      setQuickDeployRegistryServer(e.target.value)
                    }
                    className="rounded-xl border px-3 py-1.5 text-sm"
                    placeholder="registry host"
                  />
                  <input
                    value={quickDeployRegistryUser}
                    onChange={(e) => setQuickDeployRegistryUser(e.target.value)}
                    className="rounded-xl border px-3 py-1.5 text-sm"
                    placeholder="user"
                  />
                  <input
                    type="password"
                    value={quickDeployRegistryPass}
                    onChange={(e) => setQuickDeployRegistryPass(e.target.value)}
                    className="rounded-xl border px-3 py-1.5 text-sm"
                    placeholder="pass/token"
                  />
                </div>
              </div>
            </div>

            <div className="mt-8 flex justify-end gap-3">
              <Dialog.Close className="px-5 py-2.5 rounded-2xl border border-[var(--color-border)]">
                Cancel
              </Dialog.Close>
              <button
                onClick={() => quickDeployApp && quickDeploy(quickDeployApp)}
                disabled={isDeploying || !quickDeployImage.trim()}
                className="px-6 py-2.5 rounded-2xl bg-[var(--color-primary)] text-[var(--color-primary-foreground)] disabled:opacity-60 font-medium"
              >
                {isDeploying
                  ? "Dispatching signed job..."
                  : "Deploy Now (real)"}
              </button>
            </div>

            <div className="mt-4 text-[10px] text-[var(--color-muted-foreground)] text-center">
              Uses the same dispatch path as /debug/send-job and the Deployments
              page.
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
