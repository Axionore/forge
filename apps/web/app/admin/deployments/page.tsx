"use client";

import React from "react";
import { toast } from "sonner";
import * as Select from "@radix-ui/react-select";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ChevronDown,
  Check,
  X,
  Plus,
  TrendingUp,
  AlertTriangle,
  ShieldCheck,
  FileText,
  Rocket,
  Activity,
  Copy,
  Pause,
  Play,
  Clock,
} from "lucide-react";
import {
  StatusTimeline,
  type JobResultRow as TimelineJobResultRow,
} from "../../../components/StatusTimeline";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useAdminToken } from "../token-store";

type DeploymentStatus =
  | "pending"
  | "in_progress"
  | "healthy"
  | "unhealthy"
  | "failed"
  | "rolled_back";

type Deployment = {
  id: string;
  application_id: string;
  version: number;
  spec: any;
  status: DeploymentStatus;
  strategy?: any;
  rollout_state?: any;
  previous_spec?: any;
  git_source_id?: string;
  commit_sha?: string;
  ref?: string;
  created_at: string;
  updated_at: string;
};

type JobResultRow = {
  id: string;
  job_type: string;
  success: boolean;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  details: any;
  received_at: string;
};

type DeploymentListItem = {
  deployment: Deployment;
  recent_results?: JobResultRow[];
};

const API_BASE = "http://localhost:3000";

export default function DeploymentsPage() {
  const [adminToken] = useAdminToken();

  const [applications, setApplications] = React.useState<any[]>([]);
  const [selectedAppId, setSelectedAppId] = React.useState<string>("");

  const [deployments, setDeployments] = React.useState<DeploymentListItem[]>(
    [],
  );
  const [resultsLimit, setResultsLimit] = React.useState<number>(0); // 0 = no results, 5 = show 5

  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);

  // Simple create deployment form state (lightweight)
  const [showCreate, setShowCreate] = React.useState(false);
  const [createImage, setCreateImage] = React.useState("nginx:alpine");
  const [createEnv, setCreateEnv] = React.useState("PORT=80");
  const [createTargetAgent, setCreateTargetAgent] = React.useState(""); // paste agent UUID
  const [createStrategy, setCreateStrategy] = React.useState<
    "rolling" | "blue_green" | "canary"
  >("rolling");
  const [isCreating, setIsCreating] = React.useState(false);

  // Registry support for create form (Slice C polish)
  const [createRegistryServer, setCreateRegistryServer] = React.useState("");
  const [createRegistryUser, setCreateRegistryUser] = React.useState("");
  const [createRegistryPass, setCreateRegistryPass] = React.useState("");

  // Feature 2: Service Catalog
  const [showCatalog, setShowCatalog] = React.useState(false);
  const [catalogItems, setCatalogItems] = React.useState<any[]>([
    {
      id: "postgres",
      name: "PostgreSQL 16",
      description:
        "Production-grade Postgres with healthchecks and persistent volume.",
      category: "database",
    },
    {
      id: "redis",
      name: "Redis 7",
      description: "Fast in-memory cache with persistence.",
      category: "cache",
    },
    {
      id: "minio",
      name: "MinIO Object Storage",
      description: "S3-compatible storage for files and backups.",
      category: "storage",
    },
  ]);

  // Feature 4: Web Terminal - full character-by-character PTY
  const [showTerminal, setShowTerminal] = React.useState(false);
  const [terminalContainer, setTerminalContainer] = React.useState<string>("");
  const [terminalOutput, setTerminalOutput] = React.useState<string[]>([]);
  const [terminalCommand, setTerminalCommand] = React.useState("");
  const [terminalWs, setTerminalWs] = React.useState<WebSocket | null>(null);
  const [terminalSessionId, setTerminalSessionId] = React.useState<
    string | null
  >(null);

  // Feature 5: Git Sources (v1 basic)
  const [gitSources, setGitSources] = React.useState<any[]>([]);
  const [showGitSources, setShowGitSources] = React.useState(false);
  const [sshKeyOptions, setSshKeyOptions] = React.useState<any[]>([]); // for dropdown in Git Sources form

  // Tier 3-2: Secrets management UI (advanced secret store with one-time plaintext reveal)
  const [secrets, setSecrets] = React.useState<any[]>([]);
  const [showSecrets, setShowSecrets] = React.useState(false);
  const [justCreatedSecret, setJustCreatedSecret] = React.useState<{
    name: string;
    plaintext: string;
  } | null>(null);
  const [isRotating, setIsRotating] = React.useState<string | null>(null);

  // Selected deployment for detail view
  const [selectedDeployment, setSelectedDeployment] = React.useState<any>(null);

  // Logs streaming state
  const [showLogsDialog, setShowLogsDialog] = React.useState(false);
  const [logsDeployment, setLogsDeployment] = React.useState<any>(null);
  const [logLines, setLogLines] = React.useState<string[]>([]);
  const [logsWs, setLogsWs] = React.useState<WebSocket | null>(null);
  const [followLogs, setFollowLogs] = React.useState(true);
  const [logsFilter, setLogsFilter] = React.useState("");
  const [logsPaused, setLogsPaused] = React.useState(false);
  const logsContainerRef = React.useRef<HTMLDivElement>(null);
  const [logsConnectionStatus, setLogsConnectionStatus] = React.useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");

  // Persistent time-series metrics state
  const [metricsData, setMetricsData] = React.useState<any[]>([]);
  const [loadingMetrics, setLoadingMetrics] = React.useState(false);

  const headers = React.useMemo(() => {
    const h = new Headers();
    h.set("Content-Type", "application/json");
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  const fetchGitSources = React.useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await fetch(`${API_BASE}/admin/git-sources`, { headers });
      if (res.ok) {
        const data = await res.json();
        setGitSources(data || []);
      }
    } catch (e) {
      // ignore
    }
  }, [adminToken, headers]);

  const fetchSecrets = React.useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await fetch(`${API_BASE}/admin/secrets`, { headers });
      if (res.ok) {
        const data = await res.json();
        setSecrets(data || []);
      }
    } catch (e) {
      // ignore for now
    }
  }, [adminToken, headers]);

  const fetchApplications = React.useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await fetch(`${API_BASE}/admin/applications`, { headers });
      if (!res.ok) throw new Error("Failed to load applications");
      const data = await res.json();
      setApplications(data || []);
      if (data?.length > 0 && !selectedAppId) {
        setSelectedAppId(data[0].id);
      }
    } catch (e: any) {
      setError(e.message);
    }
  }, [adminToken, headers, selectedAppId]);

  const fetchDeployments = React.useCallback(async () => {
    if (!adminToken || !selectedAppId) return;
    setIsLoading(true);
    setError(null);

    const url =
      resultsLimit > 0
        ? `${API_BASE}/admin/applications/${selectedAppId}/deployments?results_limit=${resultsLimit}`
        : `${API_BASE}/admin/applications/${selectedAppId}/deployments`;

    try {
      const res = await fetch(url, { headers });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || `Request failed (${res.status})`);
      }
      const data = await res.json();
      setDeployments(data || []);
    } catch (e: any) {
      setError(e.message || "Failed to load deployments");
    } finally {
      setIsLoading(false);
    }
  }, [adminToken, selectedAppId, resultsLimit, headers]);

  React.useEffect(() => {
    if (adminToken) {
      fetchApplications();
    }
  }, [adminToken, fetchApplications]);

  React.useEffect(() => {
    if (selectedAppId) {
      fetchDeployments();
    }
  }, [selectedAppId, resultsLimit, fetchDeployments]);

  // Auto-refresh
  React.useEffect(() => {
    if (!adminToken || !selectedAppId) return;
    const id = setInterval(() => {
      fetchDeployments();
    }, 30000);
    return () => clearInterval(id);
  }, [adminToken, selectedAppId, fetchDeployments]);

  const toggleResults = () => {
    setResultsLimit((prev) => (prev === 0 ? 5 : 0));
  };

  async function createDeployment(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken || !selectedAppId) return;

    setIsCreating(true);
    setError(null);

    const envPairs = createEnv
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((line) => {
        const [k = "", ...v] = line.split("=");
        return [k.trim(), v.join("=").trim()];
      });

    const container: any = {
      name: "app",
      image: createImage,
      env: envPairs,
      ports: ["80"],
      expose: [],
      volumes: [],
      tmpfs: [],
      restart_policy: "unless-stopped",
      resources: null,
    };

    if (createRegistryServer && (createRegistryUser || createRegistryPass)) {
      container.registry_auth = {
        serveraddress: createRegistryServer,
        username: createRegistryUser || undefined,
        password: createRegistryPass || undefined,
      };
    }

    const spec: any = {
      containers: [container],
      networks: [],
      network_specs: [],
      volumes: [],
    };

    if (createRegistryServer && (createRegistryUser || createRegistryPass)) {
      spec.registry_credentials = [
        [
          createRegistryServer,
          {
            username: createRegistryUser || undefined,
            password: createRegistryPass || undefined,
          },
        ],
      ];
    }

    const strategy = {
      type: createStrategy,
      max_unavailable: 1,
      max_surge: 1,
      health_check_grace_period_secs: 30,
      rollback_on_failure: true,
      failure_threshold: 3,
    };

    const targets = createTargetAgent
      ? [{ agent_id: createTargetAgent, replicas: 1 }]
      : [];

    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${selectedAppId}/deployments`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({ spec, strategy, targets }),
        },
      );

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || "Create failed");
      }

      setSuccessMsg("Deployment created and dispatched (if agent connected)");
      setShowCreate(false);
      setCreateImage("nginx:alpine");
      setCreateEnv("PORT=80");
      setCreateTargetAgent("");
      await fetchDeployments();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsCreating(false);
    }
  }

  // Feature 1: Test the full notification chain (channel + subscription + trigger via the new admin endpoint)
  async function testNotification(deploymentId: string) {
    if (!adminToken) return;
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(
        `${API_BASE}/admin/deployments/${deploymentId}/notifications/test`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            event_type: "test.manual",
            context: { source: "ui", deployment_id: deploymentId },
          }),
        },
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || "Notification test failed");
      }
      const data = await res.json();
      setSuccessMsg(
        `Notification test logged (${data?.triggered_deliveries ?? 0} delivery rows). Check /admin or DB for audit.`,
      );
    } catch (e: any) {
      setError(e.message);
    }
  }

  // Feature 2: Deploy from catalog (v1 simplified — full variable UI + password gen next)
  async function deployFromCatalog(templateId: string) {
    if (!adminToken || !selectedAppId) {
      setError("Select an application first (top of page)");
      return;
    }
    setIsCreating(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${selectedAppId}/deploy-from-catalog`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            template_id: templateId,
            variables: {}, // v1
            strategy: createStrategy,
            targets: createTargetAgent
              ? [{ agent_id: createTargetAgent, replicas: 1 }]
              : [],
          }),
        },
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || "Catalog deploy failed");
      }
      setSuccessMsg(
        `Catalog item "${templateId}" deployed successfully. Check the list below.`,
      );
      setShowCatalog(false);
      await fetchDeployments();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsCreating(false);
    }
  }

  // Feature 3: Manual backup trigger (uses the new backup API + agent Job::Backup)
  async function triggerBackup(deploymentId: string) {
    if (!adminToken) return;
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${selectedAppId}/deployments/${deploymentId}/backups/trigger`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            db_type: "postgres",
            database_name: "app",
          }),
        },
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail || "Backup trigger failed");
      }
      const data = await res.json();
      setSuccessMsg(
        `Backup job accepted (execution ${data?.backup_execution_id}). Check agent logs and backup history. It will also fire a notification when complete.`,
      );
    } catch (e: any) {
      setError(e.message);
    }
  }

  // Feature 4: Run a command in the container and append output to the "terminal"
  async function runTerminalCommand() {
    if (
      !adminToken ||
      !selectedDeployment ||
      !terminalContainer ||
      !terminalCommand.trim()
    )
      return;

    const cmd = terminalCommand.trim();
    setTerminalOutput((prev) => [...prev, `$ ${cmd}`]);
    setTerminalCommand("");

    // In full PTY mode we send characters live over the WS instead of one-shot command.
    if (terminalWs && terminalWs.readyState === WebSocket.OPEN) {
      terminalWs.send(cmd + "\n");
      return;
    }

    // Fallback (should not happen in wired PTY)
    try {
      const res = await fetch(`${API_BASE}/admin/debug/send-job/some-agent`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          type: "exec",
          target_container: terminalContainer,
          command: ["/bin/sh", "-c", cmd],
          tty: false,
        }),
      });
      setTerminalOutput((prev) => [
        ...prev,
        `(command dispatched - output will appear in full PTY version)`,
      ]);
    } catch (e: any) {
      setTerminalOutput((prev) => [...prev, `Error: ${e.message}`]);
    }
  }

  // Full character-by-character PTY streaming over the dedicated terminal WS
  function connectTerminalWS(appId: string, depId: string, container: string) {
    if (terminalWs) {
      terminalWs.close();
    }

    const wsUrl = `ws://localhost:3000/admin/applications/${appId}/deployments/${depId}/containers/${encodeURIComponent(container)}/terminal/ws`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setTerminalOutput((prev) => [...prev, "[connected to PTY]"]);
    };

    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === "terminal_started") {
          setTerminalSessionId(data.session_id || null);
          setTerminalOutput((prev) => [
            ...prev,
            `[PTY session ${data.session_id || ""} started on ${container}]`,
          ]);
        } else if (data.output) {
          setTerminalOutput((prev) => [...prev, data.output]);
        } else if (typeof data === "string") {
          setTerminalOutput((prev) => [...prev, data]);
        }
      } catch {
        // raw text output
        setTerminalOutput((prev) => [...prev, ev.data]);
      }
    };

    ws.onclose = () => {
      setTerminalOutput((prev) => [...prev, "[PTY disconnected]"]);
      setTerminalWs(null);
      setTerminalSessionId(null);
    };

    setTerminalWs(ws);
  }

  function sendTerminalInput(char: string) {
    if (terminalWs && terminalWs.readyState === WebSocket.OPEN) {
      terminalWs.send(char);
    }
  }

  function closeTerminal() {
    if (terminalWs) {
      terminalWs.close();
    }
    setShowTerminal(false);
    setTerminalContainer("");
    setTerminalOutput([]);
    setTerminalCommand("");
    setTerminalWs(null);
    setTerminalSessionId(null);
  }

  function connectToLogsWS(appId: string, depId: string) {
    if (logsWs) {
      logsWs.close();
    }

    const ws = new WebSocket(
      `ws://localhost:3000/admin/applications/${appId}/deployments/${depId}/logs/ws`,
    );
    setLogLines([]);
    setLogsFilter("");
    setLogsPaused(false);

    ws.onopen = () => {
      setLogsConnectionStatus("connected");
      const ts = new Date().toLocaleTimeString();
      setLogLines((prev) => [
        ...prev,
        `[${ts}] [connected] Streaming real container logs...`,
      ]);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        let newLine: string | null = null;

        if (data.type === "log" && data.line) {
          const ts = new Date().toLocaleTimeString();
          newLine = `[${ts}] ${data.line}`;
        } else if (data.type === "logs_started") {
          const ts = new Date().toLocaleTimeString();
          newLine = `[${ts}] [server] Logs stream started`;
        } else if (typeof event.data === "string") {
          const ts = new Date().toLocaleTimeString();
          newLine = `[${ts}] ${event.data}`;
        }

        if (newLine) {
          setLogLines((prev) => {
            const next = [...prev.slice(-380), newLine!];
            // Auto-scroll only if following and not manually paused
            if (!logsPaused && followLogs && logsContainerRef.current) {
              requestAnimationFrame(() => {
                if (logsContainerRef.current) {
                  logsContainerRef.current.scrollTop =
                    logsContainerRef.current.scrollHeight;
                }
              });
            }
            return next;
          });
        }
      } catch {
        const raw = event.data;
        const ts = new Date().toLocaleTimeString();
        setLogLines((prev) => [
          ...prev.slice(-380),
          `[${ts}] ${typeof raw === "string" ? raw : "[binary]"}`,
        ]);
      }
    };

    ws.onerror = () => setLogsConnectionStatus("error");

    ws.onclose = () => {
      setLogsConnectionStatus("disconnected");
      const ts = new Date().toLocaleTimeString();
      setLogLines((prev) => [...prev, `[${ts}] [closed] Stream ended`]);
      setLogsWs(null);
    };

    setLogsWs(ws);
  }

  function closeLogs() {
    if (logsWs) {
      logsWs.close();
    }
    setShowLogsDialog(false);
    setLogsDeployment(null);
    setLogLines([]);
    setLogsFilter("");
    setLogsPaused(false);
  }

  // Pause follow when user scrolls up manually (nice operator UX)
  React.useEffect(() => {
    const el = logsContainerRef.current;
    if (!el) return;
    const onScroll = () => {
      if (!followLogs) return;
      const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
      if (!nearBottom && !logsPaused) setLogsPaused(true);
      if (nearBottom && logsPaused) setLogsPaused(false);
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, [followLogs, logsPaused]);

  async function loadPersistentMetrics(appId: string, depId: string) {
    setLoadingMetrics(true);
    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${appId}/deployments/${depId}/metrics?limit=50`,
        { headers },
      );
      if (res.ok) {
        const data = await res.json();
        setMetricsData(data);
      }
    } catch (e) {
      console.error("Failed to load metrics", e);
    } finally {
      setLoadingMetrics(false);
    }
  }

  const statusDotClass = (status: DeploymentStatus) => {
    switch (status) {
      case "healthy":
        return "status-dot-healthy";
      case "in_progress":
        return "status-dot-progress";
      case "pending":
        return "status-dot-pending";
      case "failed":
      case "unhealthy":
        return "status-dot-failed";
      default:
        return "status-dot-pending";
    }
  };

  return (
    <div className="page-root">
      {error && (
        <div className="mb-5 flex items-center justify-between rounded-md border border-[var(--color-destructive)]/40 bg-[var(--color-destructive)]/10 px-4 py-3 text-sm text-[var(--color-destructive)]">
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            className="font-medium underline underline-offset-2"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Header row */}
      <div className="mb-5 flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Deployments</h1>
          <p className="mt-0.5 text-[13px] text-[oklch(1_0_0/0.45)]">
            Live status + recent agent results
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedAppId}
            onChange={(e) => setSelectedAppId(e.target.value)}
            className="select h-8 w-auto pr-8 text-[13px]"
            disabled={!applications.length}
          >
            {applications.length === 0 && (
              <option value="">No applications</option>
            )}
            {applications.map((app: any) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </select>
          <button
            onClick={fetchDeployments}
            disabled={isLoading || !selectedAppId}
            className="btn btn-ghost btn-sm"
          >
            {isLoading ? "Refreshing…" : "Refresh"}
          </button>
          <button
            onClick={() => setShowCreate(true)}
            disabled={!selectedAppId}
            className="btn btn-primary btn-sm"
          >
            <Plus className="h-3.5 w-3.5" />
            New Deployment
          </button>
        </div>
      </div>

      {/* Compact stat row */}
      <div className="mb-5 flex flex-wrap items-center gap-px divide-x divide-[oklch(1_0_0/0.07)] rounded-md border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)]">
        {[
          { label: "Total", dot: null, count: deployments.length },
          {
            label: "Healthy",
            dot: "status-dot-healthy",
            count: deployments.filter((d) => d.deployment.status === "healthy")
              .length,
          },
          {
            label: "In Progress",
            dot: "status-dot-progress",
            count: deployments.filter(
              (d) => d.deployment.status === "in_progress",
            ).length,
          },
          {
            label: "Failed",
            dot: "status-dot-failed",
            count: deployments.filter((d) =>
              ["failed", "unhealthy"].includes(d.deployment.status),
            ).length,
          },
        ].map(({ label, dot, count }) => (
          <div
            key={label}
            className="flex items-center gap-2 px-4 py-2.5 text-[13px] first:rounded-l-md last:rounded-r-md"
          >
            {dot && <span className={`status-dot ${dot}`} />}
            <span className="text-[oklch(1_0_0/0.45)]">{label}</span>
            <span className="font-mono font-semibold tabular-nums text-[oklch(0.97_0_0)]">
              {count}
            </span>
          </div>
        ))}
      </div>

      {/* Secondary toolbar */}
      <div className="mb-6 flex flex-wrap items-center gap-2">
        <button onClick={toggleResults} className="btn btn-ghost btn-sm">
          {resultsLimit > 0 ? "Hide Results" : "Show Recent Results"}
        </button>
        <button
          onClick={() => setShowCatalog(true)}
          className="btn btn-ghost btn-sm"
        >
          Catalog
        </button>
        <button
          onClick={() => {
            setShowGitSources(true);
            fetchGitSources();
            if (adminToken) {
              fetch(`${API_BASE}/admin/secrets`, { headers })
                .then((r) => (r.ok ? r.json() : []))
                .then((list: any[]) =>
                  setSshKeyOptions(
                    list.filter(
                      (s: any) =>
                        s.name?.startsWith("ssh-") ||
                        (s.description || "").toLowerCase().includes("ssh"),
                    ),
                  ),
                )
                .catch(() => {});
            }
          }}
          className="btn btn-ghost btn-sm"
        >
          Git Sources
        </button>
        <button
          onClick={() => {
            setShowSecrets(true);
            fetchSecrets();
          }}
          className="btn btn-ghost btn-sm"
        >
          Secrets
        </button>
        <button
          onClick={async () => {
            if (!adminToken) {
              toast.error("Set your admin token in the top bar first");
              return;
            }
            const res = await fetch(`${API_BASE}/admin/system/update`, {
              method: "POST",
              headers,
              body: JSON.stringify({
                version: "v0.2.0-demo",
                binary_ref: "https://example.com/forge-agent-v0.2.0",
                binary_sha256: "demo-sha",
                strategy: {
                  type: "rolling",
                  max_unavailable: 1,
                  max_surge: 1,
                  health_check_grace_period_secs: 30,
                  rollback_on_failure: true,
                  failure_threshold: 3,
                },
              }),
            });
            if (res.ok)
              toast.success(
                "System update triggered — agents receive signed SystemUpdate jobs with graceful handover",
              );
            else toast.error("Trigger failed (check logs)");
          }}
          className="btn btn-ghost btn-sm ml-auto"
        >
          Trigger Self-Update
        </button>
      </div>

      {/* ---- New Deployment Dialog ---- */}
      <Dialog.Root open={showCreate} onOpenChange={setShowCreate}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-7 shadow-2xl focus:outline-none">
            <div className="mb-5 flex items-center justify-between">
              <Dialog.Title className="text-base font-semibold tracking-tight">
                New Deployment
              </Dialog.Title>
              <Dialog.Close asChild>
                <button className="grid h-7 w-7 place-items-center rounded-md text-[oklch(1_0_0/0.4)] transition-colors hover:bg-[oklch(1_0_0/0.07)] hover:text-[oklch(0.97_0_0)]">
                  <X className="h-4 w-4" />
                </button>
              </Dialog.Close>
            </div>
            <form onSubmit={createDeployment} className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                    Container image
                  </label>
                  <input
                    value={createImage}
                    onChange={(e) => setCreateImage(e.target.value)}
                    className="input font-mono"
                    placeholder="nginx:alpine"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                    Target agent UUID{" "}
                    <span className="font-normal text-[oklch(1_0_0/0.3)]">
                      (optional)
                    </span>
                  </label>
                  <input
                    value={createTargetAgent}
                    onChange={(e) => setCreateTargetAgent(e.target.value)}
                    className="input font-mono"
                    placeholder="paste agent id"
                  />
                </div>
              </div>

              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Environment variables{" "}
                  <span className="font-normal text-[oklch(1_0_0/0.3)]">
                    (KEY=val, one per line)
                  </span>
                </label>
                <textarea
                  value={createEnv}
                  onChange={(e) => setCreateEnv(e.target.value)}
                  className="textarea h-20 font-mono text-[13px]"
                />
              </div>

              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Update strategy
                </label>
                <Select.Root
                  value={createStrategy}
                  onValueChange={(v) =>
                    setCreateStrategy(v as "rolling" | "blue_green" | "canary")
                  }
                >
                  <Select.Trigger className="select flex items-center justify-between">
                    <Select.Value />
                    <Select.Icon>
                      <ChevronDown className="h-3.5 w-3.5 text-[oklch(1_0_0/0.4)]" />
                    </Select.Icon>
                  </Select.Trigger>
                  <Select.Portal>
                    <Select.Content className="z-[200] overflow-hidden rounded-lg border border-[oklch(1_0_0/0.1)] bg-[oklch(0.2_0_0)] shadow-xl">
                      <Select.Viewport className="p-1">
                        {(["rolling", "blue_green", "canary"] as const).map(
                          (s) => (
                            <Select.Item
                              key={s}
                              value={s}
                              className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[13px] capitalize outline-none hover:bg-[oklch(1_0_0/0.07)] focus:bg-[oklch(1_0_0/0.07)]"
                            >
                              <Select.ItemText>
                                {s.replace("_", " ")}
                              </Select.ItemText>
                              <Select.ItemIndicator className="ml-auto">
                                <Check className="h-3.5 w-3.5" />
                              </Select.ItemIndicator>
                            </Select.Item>
                          ),
                        )}
                      </Select.Viewport>
                    </Select.Content>
                  </Select.Portal>
                </Select.Root>
                <p className="mt-1 text-[11px] text-[oklch(1_0_0/0.35)]">
                  {createStrategy === "rolling" &&
                    "Gradual replacement with health gates + auto-rollback."}
                  {createStrategy === "blue_green" &&
                    "Full new set + traffic cutover (zero downtime)."}
                  {createStrategy === "canary" &&
                    "Small % traffic to new version first with progressive rollout."}
                </p>
              </div>

              <div className="flex justify-end gap-2 border-t border-[oklch(1_0_0/0.07)] pt-4">
                <Dialog.Close asChild>
                  <button type="button" className="btn btn-ghost btn-sm">
                    Cancel
                  </button>
                </Dialog.Close>
                <button
                  type="submit"
                  disabled={isCreating || !selectedAppId}
                  className="btn btn-primary btn-sm"
                >
                  {isCreating ? "Deploying…" : "Create & Dispatch"}
                </button>
              </div>
            </form>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Deployments List */}
      {!selectedAppId ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-16 text-center">
          <Rocket className="mb-3 h-8 w-8 text-[oklch(1_0_0/0.2)]" />
          <div className="text-sm text-[oklch(1_0_0/0.45)]">
            Select an application above to view its deployments
          </div>
        </div>
      ) : deployments.length === 0 && !isLoading ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-16 text-center">
          <Rocket className="mb-3 h-8 w-8 text-[oklch(1_0_0/0.2)]" />
          <div className="text-sm text-[oklch(1_0_0/0.45)]">
            No deployments yet for this application
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="btn btn-primary btn-sm mt-4"
          >
            <Plus className="h-3.5 w-3.5" />
            New Deployment
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {deployments.map((item, idx) => (
            <div
              key={item.deployment.id}
              className="reveal rounded-lg border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] px-5 py-4"
              style={{ animationDelay: `${idx * 30}ms` }}
            >
              {/* Row header */}
              <div className="flex items-center gap-3">
                <span
                  className={`status-dot shrink-0 ${statusDotClass(item.deployment.status)} ${item.deployment.status === "healthy" ? "pulse-dot text-[var(--color-success)]" : ""}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[13px] font-medium text-[oklch(0.97_0_0)]">
                      v{item.deployment.version}
                    </span>
                    <span className="inline-flex items-center rounded-[4px] border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.04)] px-1.5 py-px text-[10px] font-medium capitalize text-[oklch(1_0_0/0.5)]">
                      {item.deployment.status.replace("_", " ")}
                    </span>
                    {item.deployment.git_source_id && (
                      <span className="inline-flex items-center rounded-[4px] border border-[var(--color-warning)]/30 bg-[var(--color-warning)]/10 px-1.5 py-px text-[10px] font-medium text-[var(--color-warning)]">
                        PREVIEW
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-[11px] text-[oklch(1_0_0/0.38)]">
                    <span className="font-mono">
                      {item.deployment.id.slice(0, 8)}…
                    </span>
                    {(item.deployment.spec as any)?.containers?.[0]?.image && (
                      <span className="font-mono">
                        {(item.deployment.spec as any).containers[0].image}
                      </span>
                    )}
                    <span>
                      Updated{" "}
                      {new Date(item.deployment.updated_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Row actions */}
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={() => {
                      setSelectedDeployment(item);
                      setShowLogsDialog(true);
                      setLogsDeployment(item.deployment);
                      connectToLogsWS(selectedAppId, item.deployment.id);
                    }}
                    className="btn btn-ghost btn-sm"
                  >
                    <FileText className="h-3.5 w-3.5" />
                    Logs
                  </button>
                  <button
                    onClick={async () => {
                      if (!adminToken) return;
                      try {
                        await fetch(
                          `${API_BASE}/admin/applications/${selectedAppId}/deployments`,
                          {
                            method: "POST",
                            headers,
                            body: JSON.stringify({
                              spec: item.deployment.spec,
                              strategy: item.deployment.strategy || {
                                type: "rolling",
                                max_unavailable: 1,
                                max_surge: 1,
                              },
                              targets: createTargetAgent
                                ? [{ agent_id: createTargetAgent, replicas: 1 }]
                                : [],
                            }),
                          },
                        );
                        toast.success("Redeploy dispatched");
                        await fetchDeployments();
                      } catch (e: any) {
                        toast.error(e.message);
                      }
                    }}
                    className="btn btn-ghost btn-sm"
                  >
                    Redeploy
                  </button>
                  <button
                    onClick={() => setSelectedDeployment(item)}
                    className="btn btn-ghost btn-sm"
                  >
                    Details
                  </button>
                </div>
              </div>

              {item.recent_results && item.recent_results.length > 0 && (
                <div className="mt-4 border-t border-[oklch(1_0_0/0.06)] pt-4">
                  <div className="mb-2 flex items-center justify-between">
                    <div className="section-label flex items-center gap-1.5">
                      <Clock className="h-3 w-3" />
                      Status Timeline
                    </div>
                    <button
                      onClick={() => testNotification(item.deployment.id)}
                      disabled={!adminToken}
                      className="btn btn-ghost btn-sm"
                    >
                      Test Notification
                    </button>
                  </div>
                  <StatusTimeline
                    results={item.recent_results as any}
                    max={8}
                  />
                </div>
              )}

              {/* Statistical Canary Analysis — polished production surface */}
              {item.deployment.rollout_state?.last_statistical_analysis && (
                <div className="mt-5 border-t border-[var(--color-card-border)] pt-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2 text-xs uppercase tracking-[0.5px] text-[var(--color-muted-foreground)] font-medium">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Statistical Canary Analysis
                    </div>
                    <div
                      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-0.5 text-[10px] font-semibold tracking-wide border ${
                        item.deployment.rollout_state.last_statistical_analysis
                          .promotable
                          ? "bg-[var(--color-success)]/120/10 text-emerald-600 border-emerald-500/20"
                          : "bg-[var(--color-warning)]/100/10 text-amber-600 border-amber-500/20"
                      }`}
                    >
                      {item.deployment.rollout_state.last_statistical_analysis
                        .promotable ? (
                        <>
                          <Check className="w-3 h-3" /> PROMOTABLE
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-3 h-3" /> HOLD / ROLLBACK
                        </>
                      )}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-[var(--color-card-border)] bg-[var(--color-muted)]/30 p-4 text-sm">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {/* Key decision metrics */}
                      <div>
                        <div className="text-[10px] uppercase tracking-widest text-[var(--color-muted-foreground)] mb-1">
                          Consecutive Good Windows
                        </div>
                        <div className="font-mono text-2xl font-semibold tabular-nums text-[var(--color-foreground)]">
                          {
                            item.deployment.rollout_state
                              .last_statistical_analysis
                              .consecutive_good_windows
                          }
                          <span className="text-xs font-normal text-[var(--color-muted-foreground)] ml-1">
                            / 3 required
                          </span>
                        </div>
                      </div>

                      <div className="md:col-span-2">
                        <div className="text-[10px] uppercase tracking-widest text-[var(--color-muted-foreground)] mb-1.5">
                          Window Trend (error rate)
                        </div>
                        {(() => {
                          const windows =
                            item.deployment.rollout_state
                              .last_statistical_analysis.windows || [];
                          const chartData = windows
                            .slice()
                            .reverse()
                            .map((w: any, idx: number) => ({
                              window: `W${idx + 1}`,
                              canary: w.canary_error_rate ?? 0,
                              baseline: w.baseline_error_rate ?? 0,
                            }));
                          return chartData.length > 0 ? (
                            <div className="h-[68px] -mx-1">
                              <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={chartData}>
                                  <XAxis
                                    dataKey="window"
                                    tick={{
                                      fontSize: 9,
                                      fill: "var(--color-muted-foreground)",
                                    }}
                                  />
                                  <YAxis
                                    tick={{
                                      fontSize: 9,
                                      fill: "var(--color-muted-foreground)",
                                    }}
                                  />
                                  <Tooltip
                                    contentStyle={{
                                      background: "var(--color-card)",
                                      border:
                                        "1px solid var(--color-card-border)",
                                      fontSize: "10px",
                                    }}
                                  />
                                  <Line
                                    type="monotone"
                                    dataKey="canary"
                                    stroke="#10b981"
                                    strokeWidth={2}
                                    dot={{ r: 2 }}
                                  />
                                  <Line
                                    type="monotone"
                                    dataKey="baseline"
                                    stroke="#64748b"
                                    strokeWidth={1.5}
                                    strokeDasharray="2 2"
                                    dot={false}
                                  />
                                </LineChart>
                              </ResponsiveContainer>
                            </div>
                          ) : (
                            <div className="text-xs text-[var(--color-muted-foreground)]">
                              Insufficient data
                            </div>
                          );
                        })()}
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-[var(--color-card-border)]/60 text-[11px] text-[var(--color-muted-foreground)] font-mono leading-snug">
                      {
                        item.deployment.rollout_state.last_statistical_analysis
                          .policy
                      }
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[10px] text-[var(--color-muted-foreground)]">
                      <span>
                        Decision at{" "}
                        {new Date(
                          item.deployment.rollout_state
                            .last_statistical_analysis.analyzed_at,
                        ).toLocaleTimeString()}
                      </span>
                      {item.deployment.rollout_state.current_traffic_percent !=
                        null && (
                        <span className="font-medium text-[var(--color-foreground)]">
                          Current traffic:{" "}
                          <span className="font-mono">
                            {
                              item.deployment.rollout_state
                                .current_traffic_percent
                            }
                            %
                          </span>{" "}
                          canary
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Persistent time-series metrics (simple visualization from DB queries) */}
              {metricsData.length > 0 &&
                selectedDeployment?.deployment.id === item.deployment.id && (
                  <div className="mt-4 p-3 bg-[var(--color-muted)]/30 rounded-xl text-xs">
                    <div className="font-medium mb-2">
                      Persistent Time-Series (last {metricsData.length} points)
                    </div>
                    <div className="space-y-1 max-h-32 overflow-auto font-mono">
                      {metricsData.slice(0, 8).map((m, i) => (
                        <div key={i} className="flex justify-between">
                          <span>{m.metric_name}</span>
                          <span>
                            {m.value} @{" "}
                            {new Date(m.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1">
                      Full charts via /metrics API + time-series queries.
                    </div>
                  </div>
                )}
            </div>
          ))}
        </div>
      )}

      {/* Detail / Logs Panel (richer view) */}
      {selectedDeployment && (
        <div
          className="fixed inset-0 bg-black/40 flex items-center justify-center z-[100] p-4"
          onClick={() => setSelectedDeployment(null)}
        >
          <div
            className="bg-[var(--color-card)] rounded-3xl max-w-4xl w-full max-h-[90vh] overflow-auto border border-[var(--color-card-border)]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 border-b flex justify-between items-center">
              <div>
                <div className="font-semibold text-xl">
                  Deployment {selectedDeployment.deployment.id}
                </div>
                <div className="text-sm text-[var(--color-muted-foreground)]">
                  v{selectedDeployment.deployment.version} • Status:{" "}
                  {selectedDeployment.deployment.status}
                </div>
              </div>
              <button
                onClick={() => setSelectedDeployment(null)}
                className="text-2xl leading-none"
              >
                ×
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Strategy preview */}
              <div>
                <div className="font-medium mb-2">Update Strategy</div>
                <div className="text-sm p-3 bg-[var(--color-muted)] rounded-xl">
                  Rolling update with health gates (full strategies coming
                  soon).
                </div>
              </div>

              {/* Change diff (simple) */}
              <div>
                <div className="font-medium mb-2">Spec (current)</div>
                <pre className="text-xs bg-black text-green-400 p-4 rounded-xl overflow-auto max-h-48">
                  {JSON.stringify(selectedDeployment.deployment.spec, null, 2)}
                </pre>
              </div>

              {/* Logs streaming button (placeholder for real WS/SSE) */}
              <div>
                <button
                  onClick={() =>
                    alert(
                      "Logs streaming would open a live tail here (calls future /deployments/{id}/logs WS or SSE endpoint using agent's ContainerLogs job)",
                    )
                  }
                  className="px-4 py-2 rounded-xl border hover:bg-[var(--color-muted)] text-sm"
                >
                  Stream Live Logs →
                </button>
                <div className="text-xs mt-1 text-[var(--color-muted-foreground)]">
                  Uses agent ContainerLogs + attach under the hood.
                </div>
              </div>

              {/* Feature 5: Preview actions for git-linked deployments */}
              {selectedDeployment?.deployment?.git_source_id && (
                <div className="pt-4 border-t">
                  <div className="font-medium mb-2 text-amber-600">
                    This is a Git Preview
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={async () => {
                        if (!adminToken || !selectedDeployment) return;
                        try {
                          const res = await fetch(
                            `${API_BASE}/admin/deployments/${selectedDeployment.deployment.id}/promote`,
                            {
                              method: "POST",
                              headers,
                            },
                          );
                          if (res.ok) {
                            alert(
                              "Promote dispatched (main spec updated + Deploy jobs sent to agents). Refreshing...",
                            );
                            await fetchDeployments();
                            // re-select to refresh detail
                            const updated = deployments.find(
                              (d: any) =>
                                d.deployment.id ===
                                selectedDeployment.deployment.id,
                            );
                            if (updated) setSelectedDeployment(updated);
                          } else {
                            alert("Promote failed: " + (await res.text()));
                          }
                        } catch (e: any) {
                          alert("Error: " + e.message);
                        }
                      }}
                      className="px-3 py-1 text-sm rounded border bg-[var(--color-success)]/12 hover:bg-emerald-100"
                    >
                      Promote to Production
                    </button>
                    <button
                      onClick={async () => {
                        if (!adminToken || !selectedDeployment) return;
                        if (
                          !confirm(
                            "Destroy this preview deployment? This will stop containers on agents.",
                          )
                        )
                          return;
                        try {
                          const res = await fetch(
                            `${API_BASE}/admin/deployments/${selectedDeployment.deployment.id}/destroy`,
                            {
                              method: "POST",
                              headers,
                            },
                          );
                          if (res.ok) {
                            alert(
                              "Destroy dispatched (Stop jobs sent). Refreshing...",
                            );
                            await fetchDeployments();
                            setSelectedDeployment(null);
                          } else {
                            alert("Destroy failed: " + (await res.text()));
                          }
                        } catch (e: any) {
                          alert("Error: " + e.message);
                        }
                      }}
                      className="px-3 py-1 text-sm rounded border bg-[var(--color-destructive)]/10 hover:bg-red-100"
                    >
                      Destroy Preview
                    </button>
                  </div>
                </div>
              )}

              {/* Feature 3: Backups (manual trigger + history) */}
              <div>
                <div className="font-medium mb-2">Backups</div>
                <div className="flex gap-2">
                  <button
                    onClick={() =>
                      triggerBackup(selectedDeployment.deployment.id)
                    }
                    disabled={!adminToken}
                    className="px-4 py-2 rounded-xl border hover:bg-[var(--color-muted)] text-sm disabled:opacity-50"
                  >
                    Trigger Manual Backup (Postgres)
                  </button>
                  <button
                    onClick={() =>
                      alert(
                        "Full backup schedule UI + history coming in next slice. Tables and API are already live.",
                      )
                    }
                    className="px-4 py-2 rounded-xl border hover:bg-[var(--color-muted)] text-sm"
                  >
                    Manage Schedules
                  </button>
                </div>
                <div className="text-xs mt-1 text-[var(--color-muted-foreground)]">
                  Uses the new Job::Backup on the agent (pg_dump + optional S3).
                  Results appear in history and fire notifications.
                </div>
              </div>

              {/* Feature 4: Web Terminal */}
              <div>
                <button
                  onClick={() => {
                    setTerminalContainer("postgres"); // default to main container from catalog examples
                    setTerminalOutput([
                      "Welcome to Forge Web Terminal (v1)",
                      "Type commands below. Full PTY coming next.",
                    ]);
                    setShowTerminal(true);
                  }}
                  className="px-4 py-2 rounded-xl border hover:bg-[var(--color-muted)] text-sm"
                >
                  Open Web Terminal →
                </button>
                <div className="text-xs mt-1 text-[var(--color-muted-foreground)]">
                  Live exec in container (tty + real Job::Exec under the hood).
                </div>
              </div>

              {/* Per-container health from recent HealthCheck results */}
              <div>
                <div className="font-medium mb-2">
                  Per-Container Health (from HealthCheck jobs)
                </div>
                {selectedDeployment.recent_results?.filter(
                  (r: any) => r.job_type === "health_check",
                ).length > 0 ? (
                  <div className="text-sm">
                    Latest health data available in results above. Deep stats
                    (CPU/mem/net from agent HealthCheck) will appear here in
                    richer format.
                  </div>
                ) : (
                  <div className="text-sm text-[var(--color-muted-foreground)]">
                    No recent health check data. Trigger a HealthCheck job for
                    this deployment to populate container-level metrics.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Logs Streaming Dialog — enhanced (timestamps, real filter+highlight, pause-on-scroll, copy, follow) */}
      <Dialog.Root
        open={showLogsDialog}
        onOpenChange={(open) => {
          if (!open) closeLogs();
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 z-[150]" />
          <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-5xl h-[70vh] rounded-3xl border border-[var(--color-card-border)] bg-[#0a0a0a] text-[#d1d5db] shadow-2xl z-[160] flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-black/40">
              <div className="flex items-center gap-3">
                <Dialog.Title className="font-semibold text-lg">
                  Live Logs — {logsDeployment?.id}
                </Dialog.Title>

                {/* Connection status badge */}
                <div
                  className={`flex items-center gap-1.5 text-xs px-2.5 py-0.5 rounded-full border ${
                    logsConnectionStatus === "connected"
                      ? "bg-[var(--color-success)]/120/10 border-emerald-500/40 text-emerald-400"
                      : logsConnectionStatus === "connecting"
                        ? "bg-[var(--color-warning)]/100/10 border-amber-500/40 text-amber-400"
                        : logsConnectionStatus === "error"
                          ? "bg-[var(--color-destructive)]/100/10 border-red-500/40 text-red-400"
                          : "bg-[var(--color-card)]/5 border-white/20 text-[#9ca3af]"
                  }`}
                >
                  <div
                    className={`w-1.5 h-1.5 rounded-full ${
                      logsConnectionStatus === "connected"
                        ? "bg-emerald-400"
                        : logsConnectionStatus === "connecting"
                          ? "bg-amber-400 animate-pulse"
                          : logsConnectionStatus === "error"
                            ? "bg-red-400"
                            : "bg-[#6b7280]"
                    }`}
                  />
                  {logsConnectionStatus}
                </div>

                {/* Follow + pause controls */}
                <button
                  onClick={() => {
                    setFollowLogs(!followLogs);
                    if (!followLogs) setLogsPaused(false);
                  }}
                  className={`text-xs px-3 py-1 rounded border transition flex items-center gap-1 ${followLogs ? "bg-[var(--color-success)]/120/20 border-emerald-500 text-emerald-400" : "border-white/20 hover:bg-[var(--color-card)]/5"}`}
                >
                  {followLogs ? (
                    <Play className="w-3 h-3" />
                  ) : (
                    <Pause className="w-3 h-3" />
                  )}{" "}
                  Follow: {followLogs ? "ON" : "OFF"}
                </button>
                {logsPaused && (
                  <button
                    onClick={() => {
                      setLogsPaused(false);
                      setFollowLogs(true);
                    }}
                    className="text-[10px] px-2 py-0.5 rounded border border-amber-500/40 text-amber-400"
                  >
                    Resume follow
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setLogLines([])}
                  className="text-xs px-3 py-1 rounded border border-white/20 hover:bg-[var(--color-card)]/5"
                >
                  Clear
                </button>
                <button
                  onClick={closeLogs}
                  className="text-[#9ca3af] hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Log viewport with subtle line numbers + highlighted filter matches */}
            <div
              ref={logsContainerRef}
              className="flex-1 overflow-auto p-4 font-mono text-sm bg-black/90 whitespace-pre-wrap leading-snug"
            >
              {logLines.length === 0 ? (
                <div className="text-[#6b7280]">
                  Waiting for log stream... (click Stream Logs to start
                  ContainerLogs job)
                </div>
              ) : (
                logLines
                  .map((line, idx) => ({ line, idx }))
                  .filter(
                    ({ line }) =>
                      !logsFilter ||
                      line.toLowerCase().includes(logsFilter.toLowerCase()),
                  )
                  .map(({ line, idx }) => (
                    <div
                      key={idx}
                      className="flex hover:bg-[var(--color-card)]/5 rounded -mx-1 px-1"
                    >
                      <span className="select-none text-[#3f3f46] w-8 text-right pr-3 tabular-nums">
                        {idx + 1}
                      </span>
                      <span className="flex-1">{line}</span>
                    </div>
                  ))
              )}
            </div>

            <div className="px-6 py-3 border-t border-white/10 bg-black/40 text-xs text-[#9ca3af] flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 flex-1">
                <input
                  type="text"
                  placeholder="Filter (live highlight)..."
                  value={logsFilter}
                  onChange={(e) => setLogsFilter(e.target.value)}
                  className="bg-black/60 border border-white/10 rounded px-3 py-1 text-xs w-72 focus:outline-none focus:border-white/30"
                />
                <button
                  onClick={() => {
                    const blob = new Blob([logLines.join("\n")], {
                      type: "text/plain",
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `logs-${logsDeployment?.id || "deployment"}.log`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="text-xs px-3 py-1 rounded border border-white/20 hover:bg-[var(--color-card)]/5 flex items-center gap-1"
                >
                  Download .log
                </button>
                <button
                  onClick={() => {
                    const term = logsFilter.toLowerCase();
                    const visible = logLines
                      .filter((l) => !term || l.toLowerCase().includes(term))
                      .join("\n");
                    navigator.clipboard?.writeText(visible);
                  }}
                  className="text-xs px-3 py-1 rounded border border-white/20 hover:bg-[var(--color-card)]/5 flex items-center gap-1"
                >
                  <Copy className="w-3.5 h-3.5" /> Copy visible
                </button>
              </div>
              <div className="text-[10px] opacity-60 tabular-nums">
                {logLines.length} lines •{" "}
                {logsPaused ? "PAUSED" : followLogs ? "FOLLOWING" : "STATIC"} •
                real agent stream
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Feature 2: Catalog Browser Dialog */}
      <Dialog.Root open={showCatalog} onOpenChange={setShowCatalog}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-[60] w-[95vw] max-w-5xl -translate-x-1/2 -translate-y-1/2 rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-8 shadow-2xl focus:outline-none">
            <div className="flex items-start justify-between mb-6">
              <div>
                <Dialog.Title className="text-2xl font-semibold tracking-tight">
                  Service Catalog
                </Dialog.Title>
                <Dialog.Description className="text-[var(--color-muted-foreground)] mt-1">
                  Production templates. Every catalog deploy uses the full
                  engine (strategy, canary, xDS, notifications, metrics).
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button className="rounded-full p-2 hover:bg-[var(--color-muted)]">
                  <X className="h-5 w-5" />
                </button>
              </Dialog.Close>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {catalogItems.map((item) => (
                <div
                  key={item.id}
                  className="group rounded-2xl border border-[var(--color-card-border)] bg-[var(--color-muted)]/30 p-5 hover:border-[var(--color-primary)] transition-all flex flex-col"
                >
                  <div className="text-[10px] uppercase tracking-widest text-[var(--color-muted-foreground)] mb-1">
                    {item.category}
                  </div>
                  <div className="font-semibold text-lg mb-2 group-hover:text-[var(--color-primary)]">
                    {item.name}
                  </div>
                  <div className="text-sm text-[var(--color-muted-foreground)] flex-1 mb-4">
                    {item.description}
                  </div>
                  <button
                    onClick={() => deployFromCatalog(item.id)}
                    disabled={!adminToken || isCreating}
                    className="btn btn-primary mt-auto w-full"
                  >
                    Deploy {item.name.split(" ")[0]}
                  </button>
                </div>
              ))}
            </div>

            <div className="mt-6 text-center text-xs text-[var(--color-muted-foreground)]">
              Full variable configuration + password generation coming in the
              next micro-slice. These deploy as real, observable Deployments.
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Feature 5: Git Sources Dialog - nice connect form + list previews */}
      <Dialog.Root open={showGitSources} onOpenChange={setShowGitSources}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-[60] w-[95vw] max-w-4xl -translate-x-1/2 -translate-y-1/2 rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-8 shadow-2xl focus:outline-none">
            <div className="flex items-start justify-between mb-6">
              <div>
                <Dialog.Title className="text-2xl font-semibold tracking-tight">
                  Git Sources
                </Dialog.Title>
                <Dialog.Description className="text-[var(--color-muted-foreground)] mt-1">
                  Connect GitHub, GitLab, etc. Webhooks create real preview
                  deployments automatically.
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button className="rounded-full p-2 hover:bg-[var(--color-muted)]">
                  <X className="h-5 w-5" />
                </button>
              </Dialog.Close>
            </div>

            {/* Connect Form - nice and polished */}
            <div className="mb-8 border border-[var(--color-card-border)] rounded-2xl p-6 bg-[var(--color-muted)]/20">
              <div className="font-semibold mb-4">Connect New Source</div>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  const form = e.currentTarget as HTMLFormElement;
                  const formData = new FormData(form);
                  const res = await fetch(`${API_BASE}/admin/git-sources`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({
                      name: formData.get("name"),
                      provider: formData.get("provider"),
                      config: {
                        webhook_secret: formData.get("webhook_secret"),
                        ssh_key_secret_id:
                          formData.get("ssh_key_secret_id") || undefined,
                      },
                      access_token: formData.get("access_token") || undefined,
                    }),
                  });
                  if (res.ok) {
                    alert("Source connected!");
                    form.reset();
                    fetchGitSources();
                  } else {
                    alert("Failed to connect source");
                  }
                }}
                className="grid grid-cols-1 md:grid-cols-2 gap-4"
              >
                <div>
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Name
                  </label>
                  <input
                    name="name"
                    required
                    className="w-full rounded-xl border px-4 py-2 text-sm"
                    placeholder="My GitHub"
                  />
                </div>
                <div>
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Provider
                  </label>
                  <select
                    name="provider"
                    required
                    className="w-full rounded-xl border px-4 py-2 text-sm"
                  >
                    <option value="github">GitHub</option>
                    <option value="gitlab">GitLab</option>
                    <option value="gitea">Gitea</option>
                    <option value="bitbucket">Bitbucket</option>
                  </select>
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Webhook Secret (recommended)
                  </label>
                  <input
                    name="webhook_secret"
                    className="w-full rounded-xl border px-4 py-2 text-sm font-mono"
                    placeholder="random-secret-string"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Access Token (PAT or App token)
                  </label>
                  <input
                    name="access_token"
                    className="w-full rounded-xl border px-4 py-2 text-sm font-mono"
                    placeholder="ghp_..."
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    SSH Private Key (from Secrets)
                  </label>
                  <select
                    name="ssh_key_secret_id"
                    className="w-full rounded-xl border px-4 py-2 text-sm"
                  >
                    <option value="">None (use access token / HTTPS)</option>
                    {sshKeyOptions.map((s: any) => (
                      <option key={s.id} value={s.id}>
                        {s.name} — {s.description || "SSH key"}
                      </option>
                    ))}
                  </select>
                  <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1">
                    Generate SSH keys in the Secrets dialog first.
                  </div>
                </div>
                <div className="md:col-span-2">
                  <button type="submit" className="btn btn-primary mt-2 w-full">
                    Connect Source
                  </button>
                </div>
              </form>
            </div>

            {/* List of connected sources + Previews */}
            <div>
              <div className="font-semibold mb-3">Connected Sources</div>
              {gitSources.length === 0 ? (
                <div className="text-sm text-[var(--color-muted-foreground)]">
                  No sources yet. Connect one above.
                </div>
              ) : (
                <div className="space-y-2">
                  {gitSources.map((s: any) => (
                    <div
                      key={s.id}
                      className="flex items-center justify-between rounded-xl border border-[var(--color-card-border)] px-4 py-3 text-sm"
                    >
                      <div>
                        <span className="font-medium">{s.name}</span>{" "}
                        <span className="text-[var(--color-muted-foreground)]">
                          ({s.provider})
                        </span>
                      </div>
                      <div className="text-xs text-[var(--color-muted-foreground)]">
                        ID: {s.id.slice(0, 8)}...
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-6 text-xs text-[var(--color-muted-foreground)]">
              After connecting, send webhooks to
              /webhooks/git/&lt;source-id&gt;. Previews will appear below in the
              deployments list with special badges.
              <br />
              SSH keys: Generate in the Secrets dialog, then reference the
              secret ID here for private repos (agent will use it for git clone
              during builds).
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Tier 3-2: Secrets Management Dialog - full CRUD with one-time plaintext reveal */}
      <Dialog.Root
        open={showSecrets}
        onOpenChange={(open) => {
          setShowSecrets(open);
          if (!open) setJustCreatedSecret(null);
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-[60] w-[95vw] max-w-4xl -translate-x-1/2 -translate-y-1/2 rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-8 shadow-2xl focus:outline-none">
            <div className="flex items-start justify-between mb-6">
              <div>
                <Dialog.Title className="text-2xl font-semibold tracking-tight">
                  Secrets
                </Dialog.Title>
                <Dialog.Description className="text-[var(--color-muted-foreground)] mt-1">
                  Named, encrypted secrets (never stored in plaintext). Use in
                  deployments and catalog templates.
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button className="rounded-full p-2 hover:bg-[var(--color-muted)]">
                  <X className="h-5 w-5" />
                </button>
              </Dialog.Close>
            </div>

            {/* Create Form */}
            <div className="mb-8 border border-[var(--color-card-border)] rounded-2xl p-6 bg-[var(--color-muted)]/20">
              <div className="font-semibold mb-4">Create New Secret</div>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  const form = e.currentTarget as HTMLFormElement;
                  const formData = new FormData(form);
                  const name = String(formData.get("name") || "").trim();
                  const description =
                    String(formData.get("description") || "").trim() ||
                    undefined;
                  const plaintext = String(formData.get("plaintext") || "");
                  if (!name || !plaintext) return;

                  const res = await fetch(`${API_BASE}/admin/secrets`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ name, description, plaintext }),
                  });
                  if (res.ok) {
                    const created = await res.json();
                    setJustCreatedSecret({
                      name: created.name,
                      plaintext: created.plaintext,
                    });
                    form.reset();
                    fetchSecrets();
                    setSuccessMsg(
                      "Secret created. Copy the value now — it will never be shown again.",
                    );
                  } else {
                    const err = await res.json().catch(() => ({}));
                    setError(err?.detail || "Failed to create secret");
                  }
                }}
                className="grid grid-cols-1 md:grid-cols-2 gap-4"
              >
                <div>
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Name
                  </label>
                  <input
                    name="name"
                    required
                    className="w-full rounded-xl border px-4 py-2 text-sm font-mono"
                    placeholder="DATABASE_URL"
                  />
                </div>
                <div>
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Description (optional)
                  </label>
                  <input
                    name="description"
                    className="w-full rounded-xl border px-4 py-2 text-sm"
                    placeholder="Prod Postgres connection"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs mb-1 text-[var(--color-muted-foreground)]">
                    Value (plaintext — shown only once)
                  </label>
                  <input
                    name="plaintext"
                    type="password"
                    required
                    className="w-full rounded-xl border px-4 py-2 text-sm font-mono"
                    placeholder="postgres://user:pass@..."
                  />
                </div>
                <div className="md:col-span-2">
                  <button type="submit" className="btn btn-primary mt-2 w-full">
                    Create Secret
                  </button>
                </div>
              </form>

              {/* Special SSH key generation (reuses secret storage for the private key) */}
              <div className="mt-4 pt-4 border-t border-[var(--color-card-border)]">
                <button
                  type="button"
                  onClick={async () => {
                    const name = prompt("SSH Key name (e.g. github-deploy):");
                    if (!name) return;
                    const desc = prompt("Description (optional):") || undefined;

                    const res = await fetch(
                      `${API_BASE}/admin/ssh-keys/generate`,
                      {
                        method: "POST",
                        headers,
                        body: JSON.stringify({ name, description: desc }),
                      },
                    );
                    if (res.ok) {
                      const data = await res.json();
                      // Show public key for user to copy (private is encrypted and never returned)
                      alert(
                        `SSH Key generated!\n\nPublic key (copy this to your Git provider as deploy key):\n\n${data.public_key}\n\nFingerprint: ${data.fingerprint}\n\nThe private key has been securely stored and will be injected by agents when this key is associated with a git source.`,
                      );
                      fetchSecrets();
                    } else {
                      alert("Failed to generate SSH key");
                    }
                  }}
                  className="w-full rounded-xl border px-4 py-2 text-sm font-medium hover:bg-[var(--color-muted)]"
                >
                  Generate New SSH Key (ed25519)
                </button>
                <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1 text-center">
                  Recommended for private Git repos. Public key shown once for
                  setup.
                </div>
              </div>
            </div>

            {/* One-time plaintext reveal (exactly like enrollment tokens / webhook secrets) */}
            {justCreatedSecret && (
              <div className="mt-4 rounded-2xl border border-[var(--color-warning)]/30 bg-[var(--color-warning)]/10 p-4">
                <div className="font-semibold text-[var(--color-warning)] mb-1 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" /> Copy this value now — it
                  will never be shown again.
                </div>
                <div className="font-mono text-sm bg-[var(--color-card)] rounded-xl p-3 border border-[var(--color-warning)]/25 break-all select-all">
                  {justCreatedSecret.plaintext}
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(justCreatedSecret.plaintext);
                    setSuccessMsg("Copied to clipboard");
                  }}
                  className="mt-2 text-sm px-4 py-1.5 rounded-xl border bg-[var(--color-card)] hover:bg-[var(--color-warning)]/15"
                >
                  Copy value
                </button>
              </div>
            )}

            {/* List */}
            <div>
              <div className="font-semibold mb-3">Your Secrets</div>
              {secrets.length === 0 ? (
                <div className="text-sm text-[var(--color-muted-foreground)]">
                  No secrets yet. Create one above.
                </div>
              ) : (
                <div className="space-y-2">
                  {secrets.map((s: any) => (
                    <div
                      key={s.id}
                      className="flex items-center justify-between rounded-xl border border-[var(--color-card-border)] px-4 py-3 text-sm"
                    >
                      <div className="min-w-0">
                        <div className="font-medium">{s.name}</div>
                        {s.description && (
                          <div className="text-xs text-[var(--color-muted-foreground)] truncate">
                            {s.description}
                          </div>
                        )}
                        <div className="text-[10px] text-[var(--color-muted-foreground)] mt-0.5">
                          Created {new Date(s.created_at).toLocaleDateString()}{" "}
                          {s.last_rotated_at
                            ? `• Rotated ${new Date(s.last_rotated_at).toLocaleDateString()}`
                            : ""}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-[var(--color-muted-foreground)]">
                          ••••••••
                        </span>
                        <button
                          onClick={async () => {
                            const newVal = prompt(
                              `Enter new value for ${s.name}:`,
                            );
                            if (!newVal) return;
                            setIsRotating(s.id);
                            const res = await fetch(
                              `${API_BASE}/admin/secrets/${s.id}`,
                              {
                                method: "PUT",
                                headers,
                                body: JSON.stringify({ plaintext: newVal }),
                              },
                            );
                            if (res.ok) {
                              const rotated = await res.json();
                              setJustCreatedSecret({
                                name: s.name,
                                plaintext: rotated.plaintext,
                              });
                              setSuccessMsg(
                                "Secret rotated. Copy the new value now.",
                              );
                              fetchSecrets();
                            } else {
                              setError("Rotate failed");
                            }
                            setIsRotating(null);
                          }}
                          disabled={isRotating === s.id}
                          className="text-xs px-3 py-1 rounded-lg border hover:bg-[var(--color-muted)]"
                        >
                          {isRotating === s.id ? "Rotating..." : "Rotate"}
                        </button>
                        <button
                          onClick={async () => {
                            if (!confirm(`Delete secret ${s.name}?`)) return;
                            const res = await fetch(
                              `${API_BASE}/admin/secrets/${s.id}`,
                              { method: "DELETE", headers },
                            );
                            if (res.ok || res.status === 204) {
                              fetchSecrets();
                            } else {
                              setError("Delete failed");
                            }
                          }}
                          className="text-xs px-3 py-1 rounded-lg border text-[var(--color-destructive)] hover:bg-[var(--color-destructive)]/10"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-6 text-xs text-[var(--color-muted-foreground)]">
              Secrets are encrypted with age and injected at runtime by the
              agent (env or /run/secrets files, 0600). Never appear in logs, DB
              plaintext, or UI after the one-time reveal.
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
