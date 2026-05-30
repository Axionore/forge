"use client";

import React from "react";
import Link from "next/link";
import * as Dialog from "@radix-ui/react-dialog";
import { toast } from "sonner";
import { Plus, Search, X, ChevronRight, Boxes } from "lucide-react";
import { useAdminToken } from "../token-store";

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
    .then(() => toast.success("Copied to clipboard"))
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

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function kindLabel(kind: string | null): string {
  switch (kind) {
    case "git":
      return "Git";
    case "dockerfile":
      return "Dockerfile";
    case "compose":
      return "Compose";
    case "template":
      return "Template";
    default:
      return kind ?? "Git";
  }
}

function statusDotClass(status: string | null): string {
  switch (status) {
    case "healthy":
      return "status-dot-healthy";
    case "in_progress":
      return "status-dot-progress";
    case "failed":
    case "unhealthy":
      return "status-dot-failed";
    default:
      return "status-dot-pending";
  }
}

// ---- App Card (Dokploy-style service card) -----------------------------------

function AppCard({
  app,
  onQuickDeploy,
}: {
  app: Application;
  onQuickDeploy: (app: Application) => void;
}) {
  return (
    <div className="group relative flex flex-col rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] p-5 transition-all duration-150 hover:-translate-y-px hover:border-[oklch(1_0_0/0.14)] hover:shadow-[0_4px_24px_oklch(0_0_0/0.35)]">
      {/* Status dot — top-right */}
      <div className="absolute right-4 top-4">
        <span
          className={`status-dot ${statusDotClass(app.status)} ${app.status === "healthy" ? "pulse-dot text-[var(--color-success)]" : ""}`}
          title={app.status ?? "unknown"}
        />
      </div>

      {/* Name + kind chip */}
      <div className="mb-3 pr-4">
        <div className="truncate text-[13px] font-semibold tracking-tight text-[oklch(0.97_0_0)]">
          {app.name}
        </div>
        <div className="mt-1.5 inline-flex items-center rounded-[4px] border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.04)] px-2 py-px text-[10px] font-medium uppercase tracking-wide text-[oklch(1_0_0/0.45)]">
          {kindLabel(app.kind)}
        </div>
      </div>

      {/* Created */}
      <div className="mt-auto pt-3 text-[11px] text-[oklch(1_0_0/0.35)]">
        Created {relativeTime(app.created_at)}
      </div>

      {/* Actions — shown on hover */}
      <div className="mt-3 flex items-center gap-2 border-t border-[oklch(1_0_0/0.07)] pt-3">
        <Link
          href={`/admin/applications/${app.id}`}
          className="btn btn-ghost btn-sm flex-1 justify-center"
        >
          Open
          <ChevronRight className="h-3.5 w-3.5 opacity-60" />
        </Link>
        <button
          onClick={() => onQuickDeploy(app)}
          className="btn btn-primary btn-sm flex-1 justify-center"
        >
          Deploy
        </button>
      </div>
    </div>
  );
}

// ---- Page -------------------------------------------------------------------

export default function ApplicationsPage() {
  const [adminToken] = useAdminToken();
  const [applications, setApplications] = React.useState<Application[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState("");

  const [oneTimeSecret, setOneTimeSecret] = React.useState<string | null>(null);

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

  const [quickDeployApp, setQuickDeployApp] =
    React.useState<Application | null>(null);
  const [quickDeployImage, setQuickDeployImage] =
    React.useState("nginx:alpine");
  const [quickDeployAgent, setQuickDeployAgent] = React.useState("");
  const [isDeploying, setIsDeploying] = React.useState(false);

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

      toast.success(`Application "${created.name}" created`);
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Failed to create application";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  };

  async function quickDeploy(app: Application) {
    if (!adminToken) {
      setError("Enter your FORGE_ADMIN_TOKEN first");
      return;
    }
    setIsDeploying(true);
    setError(null);

    const container: Record<string, unknown> = {
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

    if (
      quickDeployRegistryServer &&
      (quickDeployRegistryUser || quickDeployRegistryPass)
    ) {
      container["registry_auth"] = {
        serveraddress: quickDeployRegistryServer,
        username: quickDeployRegistryUser || undefined,
        password: quickDeployRegistryPass || undefined,
      };
    }

    const spec: Record<string, unknown> = {
      containers: [container],
      networks: [],
      network_specs: [],
      volumes: [],
    };

    if (
      quickDeployRegistryServer &&
      (quickDeployRegistryUser || quickDeployRegistryPass)
    ) {
      spec["registry_credentials"] = [
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
        `Deploy dispatched for ${app.name} — check Deployments page for status`,
      );
      setQuickDeployApp(null);
      setQuickDeployImage("nginx:alpine");
      setQuickDeployAgent("");
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

  const filtered = React.useMemo(() => {
    if (!filter.trim()) return applications;
    const q = filter.toLowerCase();
    return applications.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        (a.kind ?? "").toLowerCase().includes(q),
    );
  }, [applications, filter]);

  return (
    <div className="page-root">
      {/* Header row */}
      <div className="mb-6 flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Applications</h1>
          <p className="mt-0.5 text-[13px] text-[oklch(1_0_0/0.45)]">
            Deployable units. Connect Git, Dockerfile, Compose, or templates.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/admin/enrollment-tokens"
            className="btn btn-ghost btn-sm"
          >
            Add server
          </Link>
          <button
            onClick={() => {
              setIsWizardOpen(true);
              setWizardStep("select");
              setSelectedKind(null);
              setFormData({});
            }}
            className="btn btn-primary btn-sm"
          >
            <Plus className="h-3.5 w-3.5" />
            New Application
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-5 flex items-center justify-between rounded-md border border-[var(--color-destructive)]/40 bg-[var(--color-destructive)]/10 px-4 py-3 text-sm text-[var(--color-destructive)]">
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            className="ml-4 font-medium underline underline-offset-2"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* One-time secret banner */}
      {oneTimeSecret && (
        <div className="mb-5 rounded-md border border-[var(--color-warning)]/40 bg-[var(--color-warning)]/10 p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="font-semibold text-[var(--color-warning)]">
                One-time secret — copy now
              </div>
              <p className="mt-0.5 text-sm text-[var(--color-warning)]/80">
                It will never be shown again.
              </p>
            </div>
            <button
              onClick={() => setOneTimeSecret(null)}
              className="text-[var(--color-warning)]/70 hover:text-[var(--color-warning)]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <pre className="mt-3 select-all overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-[var(--color-warning)]/25 bg-black/50 p-4 font-mono text-sm">
            {oneTimeSecret}
          </pre>
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => copyToClipboard(oneTimeSecret)}
              className="btn btn-primary btn-sm"
            >
              Copy secret
            </button>
            <button
              onClick={() => setOneTimeSecret(null)}
              className="btn btn-ghost btn-sm"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Filter + count row */}
      {applications.length > 0 && (
        <div className="mb-4 flex items-center gap-3">
          <div className="relative flex-1 max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[oklch(1_0_0/0.3)]" />
            <input
              type="search"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter applications…"
              className="input h-8 pl-8 text-[13px]"
            />
          </div>
          <span className="text-[12px] text-[oklch(1_0_0/0.38)] tabular-nums">
            {filtered.length} of {applications.length}
          </span>
        </div>
      )}

      {/* States */}
      {isLoading && applications.length === 0 ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-[156px] animate-pulse rounded-lg border border-[oklch(1_0_0/0.07)] bg-[oklch(0.185_0_0)]"
            />
          ))}
        </div>
      ) : !adminToken ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-16 text-center">
          <Boxes className="mb-3 h-8 w-8 text-[oklch(1_0_0/0.2)]" />
          <div className="text-sm font-medium text-[oklch(1_0_0/0.5)]">
            Set an admin token to view applications
          </div>
          <div className="mt-1 text-[12px] text-[oklch(1_0_0/0.3)]">
            Enter your token in the top bar
          </div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-16 text-center">
          <Boxes className="mb-3 h-8 w-8 text-[oklch(1_0_0/0.2)]" />
          {applications.length === 0 ? (
            <>
              <div className="text-sm font-medium text-[oklch(1_0_0/0.5)]">
                No applications yet
              </div>
              <div className="mt-1 text-[12px] text-[oklch(1_0_0/0.3)]">
                Create your first from Git, Dockerfile, Compose, or a template
              </div>
              <button
                onClick={() => {
                  setIsWizardOpen(true);
                  setWizardStep("select");
                }}
                className="btn btn-primary btn-sm mt-5"
              >
                <Plus className="h-3.5 w-3.5" />
                New Application
              </button>
            </>
          ) : (
            <>
              <div className="text-sm font-medium text-[oklch(1_0_0/0.5)]">
                No results for &ldquo;{filter}&rdquo;
              </div>
              <button
                onClick={() => setFilter("")}
                className="btn btn-ghost btn-sm mt-4"
              >
                Clear filter
              </button>
            </>
          )}
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 reveal">
          {filtered.map((app, i) => (
            <div
              key={app.id}
              className="reveal"
              style={{ animationDelay: `${i * 40}ms` }}
            >
              <AppCard app={app} onQuickDeploy={setQuickDeployApp} />
            </div>
          ))}
        </div>
      )}

      {/* ---- Create Application Wizard ---- */}
      <Dialog.Root open={isWizardOpen} onOpenChange={setIsWizardOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-7 shadow-2xl focus:outline-none">
            <div className="mb-5 flex items-center justify-between">
              <Dialog.Title className="text-lg font-semibold tracking-tight">
                New Application
              </Dialog.Title>
              <Dialog.Close asChild>
                <button className="grid h-7 w-7 place-items-center rounded-md text-[oklch(1_0_0/0.4)] transition-colors hover:bg-[oklch(1_0_0/0.07)] hover:text-[oklch(0.97_0_0)]">
                  <X className="h-4 w-4" />
                </button>
              </Dialog.Close>
            </div>

            {wizardStep === "select" && (
              <div>
                <p className="mb-4 text-[13px] text-[oklch(1_0_0/0.45)]">
                  Choose your source type
                </p>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {KINDS.map((k) => (
                    <button
                      key={k.kind}
                      onClick={() => {
                        setSelectedKind(k.kind);
                        setWizardStep("details");
                        setFormData({});
                      }}
                      className="group flex flex-col rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.03)] p-4 text-left transition-colors hover:border-[oklch(1_0_0/0.18)] hover:bg-[oklch(1_0_0/0.05)]"
                    >
                      <div className="text-[13px] font-semibold text-[oklch(0.97_0_0)]">
                        {k.label}
                      </div>
                      <div className="mt-1 text-[12px] text-[oklch(1_0_0/0.4)]">
                        {k.desc}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {wizardStep === "details" && selectedKind && (
              <div className="space-y-5">
                <button
                  onClick={() => setWizardStep("select")}
                  className="text-[12px] text-[oklch(1_0_0/0.4)] transition-colors hover:text-[oklch(1_0_0/0.7)]"
                >
                  ← Back
                </button>

                <div>
                  <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                    Application name
                  </label>
                  <input
                    value={formData.name || ""}
                    onChange={(e) =>
                      setFormData({ ...formData, name: e.target.value })
                    }
                    className="input"
                    placeholder="my-service"
                    autoFocus
                  />
                </div>

                {selectedKind === "git" && (
                  <>
                    <div>
                      <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                        Repository URL
                      </label>
                      <input
                        value={formData.repoUrl || ""}
                        onChange={(e) =>
                          setFormData({ ...formData, repoUrl: e.target.value })
                        }
                        className="input"
                        placeholder="https://github.com/org/repo.git"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                          Branch
                        </label>
                        <input
                          value={formData.branch || "main"}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              branch: e.target.value,
                            })
                          }
                          className="input"
                        />
                      </div>
                      <div>
                        <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                          Age key path{" "}
                          <span className="font-normal text-[oklch(1_0_0/0.3)]">
                            (optional)
                          </span>
                        </label>
                        <input
                          value={formData.ageKeyPath || ""}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              ageKeyPath: e.target.value,
                            })
                          }
                          className="input"
                          placeholder="~/.config/forge/age.key"
                        />
                      </div>
                    </div>
                  </>
                )}

                <div className="flex justify-end gap-2 border-t border-[oklch(1_0_0/0.07)] pt-4">
                  <Dialog.Close asChild>
                    <button className="btn btn-ghost btn-sm">Cancel</button>
                  </Dialog.Close>
                  <button
                    onClick={submitWizard}
                    disabled={!formData.name?.trim() || isLoading}
                    className="btn btn-primary btn-sm"
                  >
                    {isLoading ? "Creating…" : "Create Application"}
                  </button>
                </div>
              </div>
            )}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* ---- Quick Deploy Modal ---- */}
      <Dialog.Root
        open={!!quickDeployApp}
        onOpenChange={(o) => !o && setQuickDeployApp(null)}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-7 shadow-2xl focus:outline-none">
            <div className="mb-5 flex items-center justify-between">
              <Dialog.Title className="text-base font-semibold tracking-tight">
                Deploy — {quickDeployApp?.name}
              </Dialog.Title>
              <Dialog.Close asChild>
                <button className="grid h-7 w-7 place-items-center rounded-md text-[oklch(1_0_0/0.4)] transition-colors hover:bg-[oklch(1_0_0/0.07)] hover:text-[oklch(0.97_0_0)]">
                  <X className="h-4 w-4" />
                </button>
              </Dialog.Close>
            </div>

            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Container image
                </label>
                <input
                  value={quickDeployImage}
                  onChange={(e) => setQuickDeployImage(e.target.value)}
                  className="input font-mono"
                  placeholder="nginx:alpine or ghcr.io/you/app:v1"
                  autoFocus
                />
              </div>

              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Target agent ID{" "}
                  <span className="font-normal text-[oklch(1_0_0/0.3)]">
                    (optional — any connected if empty)
                  </span>
                </label>
                <input
                  value={quickDeployAgent}
                  onChange={(e) => setQuickDeployAgent(e.target.value)}
                  className="input font-mono"
                  placeholder="uuid of enrolled agent"
                />
              </div>

              <div className="rounded-md border border-[oklch(1_0_0/0.08)] p-3">
                <div className="section-label mb-2">
                  Private Registry (optional)
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <input
                    value={quickDeployRegistryServer}
                    onChange={(e) =>
                      setQuickDeployRegistryServer(e.target.value)
                    }
                    className="input text-[12px]"
                    placeholder="registry host"
                  />
                  <input
                    value={quickDeployRegistryUser}
                    onChange={(e) => setQuickDeployRegistryUser(e.target.value)}
                    className="input text-[12px]"
                    placeholder="username"
                  />
                  <input
                    type="password"
                    value={quickDeployRegistryPass}
                    onChange={(e) => setQuickDeployRegistryPass(e.target.value)}
                    className="input text-[12px]"
                    placeholder="token"
                  />
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <Dialog.Close asChild>
                <button className="btn btn-ghost btn-sm">Cancel</button>
              </Dialog.Close>
              <button
                onClick={() =>
                  quickDeployApp && void quickDeploy(quickDeployApp)
                }
                disabled={isDeploying || !quickDeployImage.trim()}
                className="btn btn-primary btn-sm"
              >
                {isDeploying ? "Dispatching…" : "Deploy Now"}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
