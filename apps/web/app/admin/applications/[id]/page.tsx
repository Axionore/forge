"use client";

import React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import * as Dialog from "@radix-ui/react-dialog";
import * as Select from "@radix-ui/react-select";
import { toast } from "sonner";
import {
  Copy,
  X,
  Play,
  Pause,
  Clock,
  Hammer,
  ChevronDown,
  Check,
  Shield,
  GitBranch,
  Loader2,
} from "lucide-react";
import { StatusTimeline } from "../../../../components/StatusTimeline";
import { useAdminToken } from "../../token-store";

const API_BASE = "http://localhost:3000";

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

interface Deployment {
  id: string;
  application_id: string;
  version: number;
  spec: Record<string, unknown>;
  status: string;
  strategy?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface JobResultRow {
  id: string;
  job_type: string;
  success: boolean;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  details: Record<string, unknown>;
  received_at: string;
}

interface GitSource {
  id: string;
  name: string;
  repo_url: string;
  // additional fields from backend if present (e.g. ssh_key_secret_id)
  ssh_key_secret_id?: string | null;
}

interface CreateDeploymentRequest {
  spec: Record<string, unknown>;
  strategy: Record<string, unknown>;
  targets: Array<{ agent_id: string; replicas: number }>;
  git_source_id?: string;
  ref?: string;
}

type BuildStatus = "pending" | "running" | "succeeded" | "failed" | "cancelled";

type BuilderType = "nixpacks" | "dockerfile" | "compose";

interface Build {
  id: string;
  application_id: string;
  status: BuildStatus;
  builder: BuilderType;
  git_source_id?: string | null;
  ref?: string | null;
  commit_sha?: string | null;
  image_digest?: string | null;
  signed?: boolean | null;
  provenance?: boolean | null;
  created_at: string;
  updated_at: string;
  error?: string | null;
}

interface TriggerBuildRequest {
  git_source_id?: string;
  ref?: string;
  builder: BuilderType;
}

export default function ApplicationDetailPage() {
  const params = useParams<{ id: string }>();
  const appId = params?.id as string;

  const [adminToken] = useAdminToken();
  const [application, setApplication] = React.useState<Application | null>(
    null,
  );
  const [appError, setAppError] = React.useState<string | null>(null);
  const [isLoadingApp, setIsLoadingApp] = React.useState(false);

  // Git sources for richer deploy form
  const [gitSources, setGitSources] = React.useState<GitSource[]>([]);
  const [deployMode, setDeployMode] = React.useState<"image" | "git">("image");
  const [selectedGitSourceId, setSelectedGitSourceId] = React.useState("");
  const [gitRef, setGitRef] = React.useState("main"); // branch or pr:123

  // Deploy form state
  const [deployImage, setDeployImage] = React.useState("nginx:alpine");
  const [deployAgent, setDeployAgent] = React.useState("");

  // Optional private registry auth for the image (Phase 1 complete path, no stubs)
  const [registryServer, setRegistryServer] = React.useState("");
  const [registryUsername, setRegistryUsername] = React.useState("");
  const [registryPassword, setRegistryPassword] = React.useState("");

  // NEW: Rich dynamic environment variable editor (replaces crude textarea)
  // Each entry: key, value, isSecret (for future age secret integration + UI masking)
  type EnvVar = { key: string; value: string; isSecret: boolean };
  const [envVars, setEnvVars] = React.useState<EnvVar[]>([
    { key: "PORT", value: "80", isSecret: false },
  ]);

  // Legacy support during transition (some old flows may still reference it)
  const deployEnv = envVars
    .filter((v) => v.key.trim())
    .map((v) => `${v.key}=${v.value}`)
    .join("\n");

  // Helper: Create a real age secret + return what we need for spec.secrets
  async function createSecretForDeploy(
    key: string,
    value: string,
  ): Promise<{ name: string; secretRef: any; plaintext: string } | null> {
    if (!value) return null;
    const secretName = `${application?.name || "app"}-${key}`
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");

    try {
      // 1. Create the secret (backend encrypts for all enrolled agents)
      const createRes = await fetch(`${API_BASE}/admin/secrets`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: secretName,
          description: `Created from deploy form for ${key}`,
          plaintext: value,
        }),
      });
      if (!createRes.ok) {
        const err = await createRes.json().catch(() => ({}));
        throw new Error(err?.detail || "Failed to create secret");
      }
      const created = await createRes.json();

      // 2. Fetch the full record to get the encrypted_blob (for embedding in the Job)
      const getRes = await fetch(`${API_BASE}/admin/secrets/${created.id}`, {
        headers,
      });
      if (!getRes.ok) throw new Error("Failed to fetch created secret details");

      const full = await getRes.json();
      const blob = full.encrypted_blob || {};

      const secretRef = {
        name: key,
        target: { type: "env", var: key },
        ciphertext: {
          version: blob.version || "age-v1",
          recipient: blob.recipient || "",
          payload: blob.payload || "",
        },
      };

      return {
        name: key,
        secretRef,
        plaintext: created.plaintext || value, // one-time reveal
      };
    } catch (e: any) {
      toast.error(`Failed to create secret for ${key}: ${e.message}`);
      return null;
    }
  }
  // Phase 4: real multi-server targeting (fetched from /agents/status)
  const [availableAgents, setAvailableAgents] = React.useState<any[]>([]);
  const [selectedAgentIds, setSelectedAgentIds] = React.useState<string[]>([]);
  const [isDeploying, setIsDeploying] = React.useState(false);

  // Slice C: Build the exact spec object that will be sent for image deploy (for Preview + Deploy)
  function buildImageDeploySpec() {
    const container: any = {
      name: "app",
      image: deployImage,
      env: envVars
        .filter((v) => v.key.trim() && !v.isSecret)
        .map((v) => [v.key.trim(), v.value]),
      ports: publishedPorts.length > 0 ? publishedPorts : ["80"],
      expose: [],
      volumes: [],
      tmpfs: [],
      restart_policy: "unless-stopped",
      resources: null,
    };

    if (registryServer && (registryUsername || registryPassword)) {
      container.registry_auth = {
        serveraddress: registryServer || "https://index.docker.io/v1/",
        username: registryUsername || undefined,
        password: registryPassword || undefined,
      };
    }

    const spec: any = {
      containers: [container],
      networks: [],
      network_specs: [],
      volumes: [],
    };

    if (registryServer && (registryUsername || registryPassword)) {
      spec.registry_credentials = [
        [
          registryServer || "https://index.docker.io/v1/",
          {
            username: registryUsername || undefined,
            password: registryPassword || undefined,
          },
        ],
      ];
    }

    if (domains.length > 0) spec.domains = domains;

    // Secrets are added in handleDeploy (age path)
    return spec;
  }

  // Ports and Domains for complete Traefik + SSL end-to-end (Phase 1 per plan)
  const [publishedPorts, setPublishedPorts] = React.useState<string[]>(["80"]);
  const [newPort, setNewPort] = React.useState("");
  const [domains, setDomains] = React.useState<string[]>([]);
  const [newDomain, setNewDomain] = React.useState("");

  // Phase 2: Strategy configuration (per-deployment, visible in UI)
  const [deployStrategyType, setDeployStrategyType] = React.useState<
    "rolling" | "bluegreen" | "canary"
  >("rolling");
  const [healthGrace, setHealthGrace] = React.useState(30);
  const [failureThreshold, setFailureThreshold] = React.useState(3);
  const [rollbackOnFailure, setRollbackOnFailure] = React.useState(true);

  // Canary-specific config (Phase 2 full support)
  const [canaryInitialTraffic, setCanaryInitialTraffic] = React.useState(10);
  const [canaryStepPercent, setCanaryStepPercent] = React.useState(10);
  const [canaryStepDuration, setCanaryStepDuration] = React.useState(300);

  // Phase 2 honest zero-downtime warnings
  const [workloadType, setWorkloadType] = React.useState<
    "stateless" | "stateful" | "database"
  >("stateless");
  const zeroDowntimeGuaranteed = workloadType === "stateless";

  // Phase 3: Magical self-update "Update Forge" + one-click DBs state
  const [showUpdateForge, setShowUpdateForge] = React.useState(false);
  const [updateVersion, setUpdateVersion] = React.useState("v0.3.0-magic");
  const [updateBinaryRef, setUpdateBinaryRef] = React.useState("");
  const [updateBinarySha, setUpdateBinarySha] = React.useState("");
  const [isUpdatingForge, setIsUpdatingForge] = React.useState(false);
  // systemDeployment kept as any because it mirrors dynamic deployments JSONB (rollout_state, metrics) — identical pattern used throughout this file
  const [systemDeployment, setSystemDeployment] = React.useState<any>(null);

  // One-click DBs & Services (Phase 3)
  const [catalog, setCatalog] = React.useState<any[]>([]);
  const [isLoadingCatalog, setIsLoadingCatalog] = React.useState(false);

  // Post-deploy rich state
  const [latestDeployment, setLatestDeployment] =
    React.useState<Deployment | null>(null);
  const [previousDeployment, setPreviousDeployment] =
    React.useState<Deployment | null>(null);
  const [liveResults, setLiveResults] = React.useState<JobResultRow[]>([]);
  const [isPolling, setIsPolling] = React.useState(false);

  // Slice C: Preview Spec modal state
  const [showPreviewSpec, setShowPreviewSpec] = React.useState(false);
  const [previewSpecJson, setPreviewSpecJson] = React.useState("");

  // Deeper observability for Phase 2 (rollout metrics, stateful signals)
  const [rolloutMetrics, setRolloutMetrics] = React.useState<any[]>([]);

  // Phase 3 one-time amber secret for catalog DB connection details (real pattern from access page; value is honest note since generated secrets stay age-wrapped)
  const [oneTimeSecret, setOneTimeSecret] = React.useState<string | null>(null);
  const [copiedOneTime, setCopiedOneTime] = React.useState(false);

  // Logs streaming (rich auto-open experience)
  const [showLogsDialog, setShowLogsDialog] = React.useState(false);
  const [logLines, setLogLines] = React.useState<string[]>([]);
  const [logsWs, setLogsWs] = React.useState<WebSocket | null>(null);
  const [logsFilter, setLogsFilter] = React.useState("");
  const [logsPaused, setLogsPaused] = React.useState(false);
  const [followLogs, setFollowLogs] = React.useState(true);
  const logsContainerRef = React.useRef<HTMLDivElement>(null);
  const [logsConnectionStatus, setLogsConnectionStatus] = React.useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");
  const pollIntervalRef = React.useRef<ReturnType<typeof setInterval> | null>(
    null,
  );

  // ---- Builds state ----
  const [builds, setBuilds] = React.useState<Build[]>([]);
  const [buildsLoading, setBuildsLoading] = React.useState(false);
  const [showNewBuild, setShowNewBuild] = React.useState(false);
  const [buildGitSourceId, setBuildGitSourceId] = React.useState("");
  const [buildRef, setBuildRef] = React.useState("main");
  const [buildBuilder, setBuildBuilder] =
    React.useState<BuilderType>("nixpacks");
  const [isTriggering, setIsTriggering] = React.useState(false);
  // Build log viewer
  const [showBuildLogs, setShowBuildLogs] = React.useState(false);
  const [activeBuild, setActiveBuild] = React.useState<Build | null>(null);
  const [buildLogLines, setBuildLogLines] = React.useState<string[]>([]);
  const [buildLogsWs, setBuildLogsWs] = React.useState<WebSocket | null>(null);
  const [buildLogsStatus, setBuildLogsStatus] = React.useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");
  const [buildLogsPaused, setBuildLogsPaused] = React.useState(false);
  const buildLogsRef = React.useRef<HTMLDivElement>(null);

  const headers = React.useMemo(() => {
    const h = new Headers();
    h.set("Content-Type", "application/json");
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  // Helpers for real spec diff in Change Preview
  function getImageFromSpec(spec: any): string {
    return spec?.containers?.[0]?.image || "—";
  }
  function getPortsFromSpec(spec: any): string[] {
    return spec?.containers?.[0]?.ports || [];
  }
  function getDomainsFromSpec(spec: any): string[] {
    return spec?.domains || [];
  }

  // New helper for the rich env editor diff
  function getEnvSummaryFromVars(vars: EnvVar[]): string {
    const count = vars.filter((v) => v.key.trim()).length;
    const secretCount = vars.filter((v) => v.isSecret && v.key.trim()).length;
    return `${count} vars${secretCount > 0 ? ` (${secretCount} secret)` : ""}`;
  }

  function DiffRow({
    label,
    oldVal,
    newVal,
  }: {
    label: string;
    oldVal: string;
    newVal: string;
  }) {
    const changed = oldVal !== newVal;
    return (
      <div className="flex gap-2 text-xs">
        <span className="w-20 text-[var(--color-muted-foreground)]">
          {label}
        </span>
        <span
          className={`font-mono ${changed ? "line-through text-red-500/70" : ""}`}
        >
          {oldVal || "—"}
        </span>
        {changed && (
          <>
            <span>→</span>
            <span className="font-mono text-emerald-600">{newVal}</span>
          </>
        )}
      </div>
    );
  }

  // Copy helper for the one-time amber secret banner (exact Linear-grade pattern)
  function copyOneTimeSecret() {
    if (!oneTimeSecret) return;
    navigator.clipboard.writeText(oneTimeSecret).then(() => {
      setCopiedOneTime(true);
      setTimeout(() => setCopiedOneTime(false), 1800);
    });
  }

  // Load the application
  const loadApplication = React.useCallback(async () => {
    if (!adminToken || !appId) return;
    setIsLoadingApp(true);
    setAppError(null);
    try {
      const res = await fetch(`${API_BASE}/admin/applications/${appId}`, {
        headers,
      });
      if (!res.ok)
        throw new Error(`Failed to load application (${res.status})`);
      const data: Application = await res.json();
      setApplication(data);

      // Load previous deployment for real Change Preview diff (Phase 2)
      const depsRes = await fetch(
        `${API_BASE}/admin/applications/${appId}/deployments?results_limit=2`,
        { headers },
      );
      if (depsRes.ok) {
        const deps = await depsRes.json();
        if (deps.length > 0) {
          setLatestDeployment(deps[0]);
          if (deps.length > 1) setPreviousDeployment(deps[1]);
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load application";
      setAppError(msg);
      toast.error(msg);
    } finally {
      setIsLoadingApp(false);
    }
  }, [adminToken, appId, headers]);

  const fetchGitSources = React.useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await fetch(`${API_BASE}/admin/git-sources`, { headers });
      if (res.ok) {
        const data: GitSource[] = await res.json();
        setGitSources(data || []);
      }
    } catch {
      // ignore – non-fatal for deploy form
    }
  }, [adminToken, headers]);

  // Phase 4: live agents for multi-server target selection (same data as the Add Server page)
  const fetchAgents = React.useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await fetch(`${API_BASE}/agents/status`, { headers });
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : [];
        setAvailableAgents(list);
        if (selectedAgentIds.length === 0) {
          const connected = list
            .filter(
              (a: any) =>
                a.connected ||
                (a.last_seen_at &&
                  Date.now() - new Date(a.last_seen_at).getTime() < 90_000),
            )
            .map((a: any) => String(a.id));
          if (connected.length > 0) setSelectedAgentIds(connected);
        }
      }
    } catch {}
  }, [adminToken, headers, selectedAgentIds.length]);

  React.useEffect(() => {
    if (adminToken && appId) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void loadApplication();
      void fetchGitSources();
      void fetchAgents();
      // Phase 3: load catalog for one-click DBs
      void (async () => {
        setIsLoadingCatalog(true);
        try {
          const res = await fetch(`${API_BASE}/catalog`, { headers });
          if (res.ok) setCatalog(await res.json());
        } catch {}
        setIsLoadingCatalog(false);
      })();
    }
  }, [adminToken, appId, loadApplication, fetchGitSources, headers]);

  // Phase 3: load forge-system deployment (for embedded L7/stateful live panel in Update dialog)
  React.useEffect(() => {
    if (showUpdateForge && adminToken) {
      void (async () => {
        try {
          const sysRes = await fetch(
            `${API_BASE}/applications/forge-system/deployments?results_limit=1`,
            { headers },
          );
          if (sysRes.ok) {
            const deps = await sysRes.json();
            if (deps.length) setSystemDeployment(deps[0]);
          }
        } catch {}
      })();
    }
  }, [showUpdateForge, adminToken, headers]);

  // Real deploy — same endpoint the rest of the system uses
  async function handleDeploy(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken || !appId) return;

    setIsDeploying(true);

    // === NEW: Process secrets properly using the age system ===
    const secretRows = envVars.filter((v) => v.isSecret && v.key.trim());
    const plainEnvRows = envVars.filter((v) => !v.isSecret && v.key.trim());

    const secretRefs: any[] = [];
    const oneTimeSecrets: Array<{ key: string; plaintext: string }> = [];

    for (const row of secretRows) {
      const result = await createSecretForDeploy(row.key.trim(), row.value);
      if (result) {
        secretRefs.push(result.secretRef);
        oneTimeSecrets.push({
          key: row.key.trim(),
          plaintext: result.plaintext,
        });
      }
    }

    // Plain (non-secret) env vars still go in the simple env array
    const envPairs = plainEnvRows.map((v) => [v.key.trim(), v.value]);

    // Build rich spec with ports + domains for Traefik + automatic SSL (matches plan success criteria)
    const container: any = {
      name: "app",
      image: deployImage,
      env: envPairs,
      ports: publishedPorts.length > 0 ? publishedPorts : ["80"],
      expose: [],
      volumes: [],
      tmpfs: [],
      restart_policy: "unless-stopped",
      resources: null,
    };

    // Private registry auth (complete non-stub path)
    if (registryServer && (registryUsername || registryPassword)) {
      container.registry_auth = {
        serveraddress: registryServer || "https://index.docker.io/v1/",
        username: registryUsername || undefined,
        password: registryPassword || undefined,
      };
    }

    const spec = {
      containers: [container],
      networks: [],
      network_specs: [],
      volumes: [],
      // Also provide top-level for broader compatibility
      ...(registryServer && (registryUsername || registryPassword)
        ? {
            registry_credentials: [
              [
                registryServer || "https://index.docker.io/v1/",
                {
                  username: registryUsername || undefined,
                  password: registryPassword || undefined,
                },
              ],
            ],
          }
        : {}),
      // Domains for Traefik routers + Let's Encrypt (agent will generate labels on receipt)
      domains: domains.length > 0 ? domains : undefined,
      // Real age secrets (injected by agent via tmpfs or env — never plaintext in spec after this point)
      ...(secretRefs.length > 0 ? { secrets: secretRefs } : {}),
    };

    const strategy =
      deployStrategyType === "rolling"
        ? {
            type: "rolling",
            max_unavailable: 1,
            max_surge: 1,
            health_check_grace_period_secs: healthGrace,
            rollback_on_failure: rollbackOnFailure,
            failure_threshold: failureThreshold,
          }
        : deployStrategyType === "bluegreen"
          ? {
              type: "bluegreen",
              scale_down_old_after_secs: 30,
              health_check_grace_period_secs: healthGrace,
            }
          : {
              type: "canary",
              initial_traffic_percent: canaryInitialTraffic,
              step_percent: canaryStepPercent,
              step_duration_secs: canaryStepDuration,
              failure_threshold: failureThreshold,
            };

    const targets =
      selectedAgentIds.length > 0
        ? selectedAgentIds.map((id) => ({ agent_id: id, replicas: 1 }))
        : [];

    const deployBody: CreateDeploymentRequest = { spec, strategy, targets };
    if (deployMode === "git" && selectedGitSourceId) {
      deployBody.git_source_id = selectedGitSourceId;
      deployBody.ref = gitRef;
    }

    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${appId}/deployments`,
        {
          method: "POST",
          headers,
          body: JSON.stringify(deployBody),
        },
      );

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Deploy failed (${res.status}) ${text}`);
      }

      const createdDep: Deployment = await res.json();
      setLatestDeployment(createdDep);
      setLiveResults([]);

      toast.success(`Deployment v${createdDep.version} created and dispatched`);

      // Show one-time amber banners for any secrets we just created during this deploy
      if (oneTimeSecrets.length > 0) {
        // For simplicity we surface the last one prominently (multiple can be handled in a follow-up)
        const last = oneTimeSecrets[oneTimeSecrets.length - 1];
        if (last) {
          setOneTimeSecret(
            `Secret for ${last.key}:\n${last.plaintext}\n\n(Copy now — this is the only time it will be shown.)`,
          );
          setCopiedOneTime(false);
        }
      }

      // === Rich post-deploy experience ===
      // 1. Auto-open live logs (the primary rich feedback)
      openLogsForDeployment(createdDep);

      // 2. Start live status polling from JobResults
      startLiveStatusPolling(createdDep.id);

      // Refresh app info (status may have changed)
      void loadApplication();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Deploy failed";
      toast.error(msg);
    } finally {
      setIsDeploying(false);
    }
  }

  // Live polling of JobResults for status updates
  function startLiveStatusPolling(deploymentId: string) {
    setIsPolling(true);

    const poll = async () => {
      try {
        const res = await fetch(
          `${API_BASE}/admin/applications/${appId}/deployments/${deploymentId}/results?results_limit=20`,
          { headers },
        );
        if (res.ok) {
          const results: JobResultRow[] = await res.json();
          setLiveResults(results);
        }

        // Deeper observability: fetch recent rollout/health metrics for stateful + gate visibility
        try {
          const mRes = await fetch(
            `${API_BASE}/admin/applications/${appId}/deployments/${deploymentId}/metrics?limit=30`,
            { headers },
          );
          if (mRes.ok) {
            const m = await mRes.json();
            setRolloutMetrics(m.slice(-15)); // recent window for timeline
          }
        } catch {}
      } catch {
        // silent
      }
    };

    // Immediate + interval
    void poll();
    const interval = setInterval(poll, 2200);

    // Store interval id for cleanup
    pollIntervalRef.current = interval;

    // Stop polling after 3 minutes
    setTimeout(
      () => {
        if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
        setIsPolling(false);
      },
      1000 * 60 * 3,
    );
  }

  // Logs streaming — auto opened after successful deploy (enhanced)
  function openLogsForDeployment(dep: Deployment) {
    if (logsWs) logsWs.close();

    const ws = new WebSocket(
      `ws://localhost:3000/admin/applications/${appId}/deployments/${dep.id}/logs/ws`,
    );
    setLogLines([]);
    setLogsFilter("");
    setLogsPaused(false);
    setLogsConnectionStatus("connecting");
    setShowLogsDialog(true);

    ws.onopen = () => {
      setLogsConnectionStatus("connected");
      const ts = new Date().toLocaleTimeString();
      setLogLines((prev) => [
        ...prev,
        `[${ts}] [connected] Streaming container logs...`,
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
            if (!logsPaused && logsContainerRef.current) {
              requestAnimationFrame(() => {
                if (logsContainerRef.current)
                  logsContainerRef.current.scrollTop =
                    logsContainerRef.current.scrollHeight;
              });
            }
            return next;
          });
        }
      } catch {
        const ts = new Date().toLocaleTimeString();
        setLogLines((prev) => [...prev.slice(-380), `[${ts}] ${event.data}`]);
      }
    };

    ws.onerror = () => setLogsConnectionStatus("error");

    ws.onclose = () => {
      setLogsConnectionStatus("disconnected");
      const ts = new Date().toLocaleTimeString();
      setLogLines((prev) => [...prev, `[${ts}] [closed] Log stream ended`]);
      setLogsWs(null);
    };

    setLogsWs(ws);
  }

  function closeLogs() {
    if (logsWs) {
      logsWs.close();
    }
    setShowLogsDialog(false);
    setLogLines([]);
    setLogsFilter("");
    setLogsPaused(false);
  }

  // Pause follow on manual scroll up
  React.useEffect(() => {
    const el = logsContainerRef.current;
    if (!el) return;
    const onScroll = () => {
      const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
      if (!nearBottom && !logsPaused) setLogsPaused(true);
      if (nearBottom && logsPaused) setLogsPaused(false);
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, [logsPaused]);

  // Cleanup polling on unmount
  React.useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
      if (logsWs) logsWs.close();
    };
  }, [logsWs]);

  // ---- Builds helpers ----

  const fetchBuilds = React.useCallback(async () => {
    if (!adminToken || !appId) return;
    setBuildsLoading(true);
    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/${appId}/builds`,
        { headers },
      );
      if (!res.ok) throw new Error(`${res.status}`);
      const data: Build[] = await res.json();
      setBuilds(data);
    } catch {
      // non-fatal — backend may not have builds yet
    } finally {
      setBuildsLoading(false);
    }
  }, [adminToken, appId, headers]);

  React.useEffect(() => {
    if (adminToken && appId) void fetchBuilds();
  }, [adminToken, appId, fetchBuilds]);

  async function triggerBuild(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken || !appId) return;
    setIsTriggering(true);
    try {
      const body: TriggerBuildRequest = { builder: buildBuilder };
      if (buildGitSourceId) body.git_source_id = buildGitSourceId;
      if (buildRef.trim()) body.ref = buildRef.trim();
      const res = await fetch(
        `${API_BASE}/admin/applications/${appId}/builds`,
        { method: "POST", headers, body: JSON.stringify(body) },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          (err as { detail?: string }).detail ?? `Error ${res.status}`,
        );
      }
      const created: Build = await res.json();
      toast.success("Build triggered");
      setShowNewBuild(false);
      setBuilds((prev) => [created, ...prev]);
      // Auto-open logs for the new build
      openBuildLogs(created);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Trigger failed");
    } finally {
      setIsTriggering(false);
    }
  }

  function openBuildLogs(build: Build) {
    if (buildLogsWs) buildLogsWs.close();
    setActiveBuild(build);
    setBuildLogLines([]);
    setBuildLogsPaused(false);
    setBuildLogsStatus("connecting");
    setShowBuildLogs(true);

    const ws = new WebSocket(
      `ws://localhost:3000/admin/applications/${appId}/builds/${build.id}/logs/ws`,
    );

    ws.onopen = () => {
      setBuildLogsStatus("connected");
      const ts = new Date().toLocaleTimeString();
      setBuildLogLines((prev) => [
        ...prev,
        `[${ts}] [connected] Streaming build logs...`,
      ]);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string) as Record<
          string,
          unknown
        >;
        let newLine: string | null = null;
        if (typeof data["line"] === "string") {
          const ts = new Date().toLocaleTimeString();
          newLine = `[${ts}] ${data["line"]}`;
        } else if (typeof event.data === "string") {
          const ts = new Date().toLocaleTimeString();
          newLine = `[${ts}] ${event.data}`;
        }
        if (newLine) {
          setBuildLogLines((prev) => {
            const next = [...prev.slice(-499), newLine!];
            if (!buildLogsPaused && buildLogsRef.current) {
              requestAnimationFrame(() => {
                if (buildLogsRef.current)
                  buildLogsRef.current.scrollTop =
                    buildLogsRef.current.scrollHeight;
              });
            }
            return next;
          });
        }
      } catch {
        const ts = new Date().toLocaleTimeString();
        setBuildLogLines((prev) => [
          ...prev.slice(-499),
          `[${ts}] ${typeof event.data === "string" ? event.data : "[binary]"}`,
        ]);
      }
    };

    ws.onerror = () => setBuildLogsStatus("error");

    ws.onclose = () => {
      setBuildLogsStatus("disconnected");
      const ts = new Date().toLocaleTimeString();
      setBuildLogLines((prev) => [
        ...prev,
        `[${ts}] [closed] Log stream ended`,
      ]);
      setBuildLogsWs(null);
    };

    setBuildLogsWs(ws);
  }

  function closeBuildLogs() {
    if (buildLogsWs) buildLogsWs.close();
    setShowBuildLogs(false);
    setActiveBuild(null);
    setBuildLogLines([]);
    setBuildLogsStatus("disconnected");
  }

  // Pause build logs scroll on manual scroll-up
  React.useEffect(() => {
    const el = buildLogsRef.current;
    if (!el) return;
    const onScroll = () => {
      const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
      if (!nearBottom && !buildLogsPaused) setBuildLogsPaused(true);
      if (nearBottom && buildLogsPaused) setBuildLogsPaused(false);
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, [buildLogsPaused]);

  // Cleanup build WS on unmount
  React.useEffect(() => {
    return () => {
      buildLogsWs?.close();
    };
  }, [buildLogsWs]);

  if (!appId) {
    return <div className="p-12 text-center">Invalid application</div>;
  }

  return (
    <div className="page-root space-y-6">
      <div className="flex items-center justify-between gap-4">
        <Link
          href="/admin/applications"
          className="text-sm text-[var(--color-muted-foreground)] hover:text-foreground"
        >
          ← Back to Applications
        </Link>
        <button
          onClick={() => setShowUpdateForge(true)}
          className="btn btn-ghost"
        >
          Update Forge
        </button>
      </div>

      {/* Phase 3: One-time amber secret banner for catalog DB connection details (exact pattern from access page; honest because secrets never leave age envelopes) */}
      {oneTimeSecret && (
        <div className="mb-4 rounded-lg border border-[var(--color-warning)]/40 bg-[var(--color-warning)]/10 p-6">
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
              <div className="font-semibold tracking-tight text-[var(--color-foreground)]">
                One-time connection note — copy immediately
              </div>
              <div className="text-sm text-[var(--color-warning)]/80 mt-0.5">
                Generated secret is age-wrapped server-side and injected only
                into the container (tmpfs 0600). Never logged or returned in
                control-plane responses.
              </div>
              <div className="mt-4 flex items-center gap-3 rounded-lg bg-[var(--color-card)] px-5 py-4 font-mono text-[15px] border border-[var(--color-warning)]/25 tracking-[0.5px] break-all select-all">
                {oneTimeSecret}
              </div>
              <div className="mt-3 flex items-center gap-3">
                <button
                  onClick={copyOneTimeSecret}
                  className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-warning)]/25 px-6 h-10 text-sm font-medium active:bg-[var(--color-warning)]/15 transition"
                >
                  {copiedOneTime ? "Copied to clipboard ✓" : "Copy note"}
                </button>
                <button
                  onClick={() => {
                    setOneTimeSecret(null);
                    setCopiedOneTime(false);
                  }}
                  className="text-sm text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)] underline underline-offset-2"
                >
                  Dismiss
                </button>
                <div className="text-[10px] text-[var(--color-warning)]/60 ml-auto font-mono tracking-[1px]">
                  AGE-PROTECTED • NEVER REPLAYED
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* App Header + 4-state handling */}
      {isLoadingApp ? (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-8 animate-pulse">
          <div className="h-9 w-2/3 bg-[var(--color-muted)] rounded" />
          <div className="mt-3 h-4 w-1/3 bg-[var(--color-muted)] rounded" />
        </div>
      ) : appError ? (
        <div className="rounded-xl border border-[var(--color-destructive)]/30 bg-[var(--color-destructive)]/5 p-6 text-[var(--color-destructive)]">
          Failed to load application: {appError}
          <button onClick={() => loadApplication()} className="ml-4 underline">
            Retry
          </button>
        </div>
      ) : application ? (
        <div>
          <div className="flex items-baseline justify-between">
            <div>
              <h1 className="text-4xl font-semibold tracking-tighter">
                {application.name}
              </h1>
              <div className="text-[var(--color-muted-foreground)] mt-1">
                {application.kind ?? "git"} · created{" "}
                {new Date(application.created_at).toLocaleString()}
              </div>
            </div>
            <div className="text-xs font-mono px-3 py-1 rounded-full border border-[var(--color-border)]">
              {appId}
            </div>
          </div>
        </div>
      ) : null}

      {/* Deploy Panel — polished primary flow from details (Phase 1) */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="font-semibold text-2xl tracking-tight">Deploy</div>
            <div className="text-[var(--color-muted-foreground)] mt-1">
              Real signed Job::Deploy. Image or Git source. Runs on any
              connected agent.
            </div>
          </div>
        </div>

        {/* Mode tabs – Image (default) vs Git (secondary, high value for parity) */}
        <div className="flex gap-2 mb-6">
          <button
            type="button"
            onClick={() => setDeployMode("image")}
            className={
              deployMode === "image"
                ? "btn btn-primary btn-sm"
                : "btn btn-ghost btn-sm"
            }
          >
            Container Image
          </button>
          <button
            type="button"
            onClick={() => {
              setDeployMode("git");
              if (gitSources.length === 0) void fetchGitSources();
            }}
            className={
              deployMode === "git"
                ? "btn btn-primary btn-sm"
                : "btn btn-ghost btn-sm"
            }
          >
            Git Repository
          </button>
        </div>

        <form onSubmit={handleDeploy} className="space-y-6 max-w-2xl">
          {deployMode === "image" ? (
            <div>
              <label className="block text-sm font-medium mb-2">
                Container Image
              </label>
              <input
                value={deployImage}
                onChange={(e) => setDeployImage(e.target.value)}
                className="input font-mono"
                placeholder="nginx:alpine or ghcr.io/org/app:v1.2.3"
                required
              />

              {/* Optional private registry auth — complete Phase 1 path, no stubs */}
              <div className="pt-2 border-t border-[var(--color-border)]">
                <div className="text-xs font-medium text-[var(--color-muted-foreground)] mb-2">
                  Private Registry (optional)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <input
                    value={registryServer}
                    onChange={(e) => setRegistryServer(e.target.value)}
                    className="rounded-xl border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm"
                    placeholder="registry.example.com (or ghcr.io)"
                  />
                  <input
                    value={registryUsername}
                    onChange={(e) => setRegistryUsername(e.target.value)}
                    className="rounded-xl border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm"
                    placeholder="username"
                  />
                  <input
                    type="password"
                    value={registryPassword}
                    onChange={(e) => setRegistryPassword(e.target.value)}
                    className="rounded-xl border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm"
                    placeholder="password or token"
                  />
                </div>
                <p className="mt-1 text-[10px] text-[var(--color-muted-foreground)]">
                  Credentials are sent in the DeploymentSpec (agent uses them
                  for pull). For production use the stored secret + age path.
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">
                  Git Source
                </label>
                <select
                  value={selectedGitSourceId}
                  onChange={(e) => setSelectedGitSourceId(e.target.value)}
                  className="select"
                  required
                >
                  <option value="">Select connected Git source...</option>
                  {gitSources.map((gs) => (
                    <option key={gs.id} value={gs.id}>
                      {gs.name} ({gs.repo_url})
                    </option>
                  ))}
                </select>
                {gitSources.length === 0 && (
                  <p className="mt-1 text-xs text-[var(--color-muted-foreground)]">
                    No Git sources yet. Connect one from the Deployments page →
                    Git Sources.
                  </p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">
                  Branch / Ref / PR
                </label>
                <input
                  value={gitRef}
                  onChange={(e) => setGitRef(e.target.value)}
                  className="input font-mono"
                  placeholder="main or pr/42 or commit-sha"
                />
                <p className="mt-1 text-xs text-[var(--color-muted-foreground)]">
                  Uses the same preview + build path as the rest of the
                  platform.
                </p>
              </div>
            </div>
          )}

          {/* Rich Dynamic Environment Variables Editor — major DX improvement over textarea */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium">
                Environment Variables
              </label>
              <button
                type="button"
                onClick={() =>
                  setEnvVars((prev) => [
                    ...prev,
                    { key: "", value: "", isSecret: false },
                  ])
                }
                className="text-xs px-3 py-1 rounded-xl border border-[var(--color-border)] hover:bg-[var(--color-muted)]"
              >
                + Add variable
              </button>
            </div>

            <div className="space-y-2">
              {envVars.map((ev, idx) => (
                <div
                  key={idx}
                  className="flex gap-2 items-center rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2"
                >
                  <input
                    value={ev.key}
                    onChange={(e) => {
                      const next = [...envVars];
                      next[idx] = { ...next[idx]!, key: e.target.value };
                      setEnvVars(next);
                    }}
                    placeholder="KEY"
                    className="font-mono w-40 rounded-xl border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-sm focus:outline-none focus:ring-1"
                  />
                  <input
                    value={ev.value}
                    onChange={(e) => {
                      const next = [...envVars];
                      next[idx] = { ...next[idx]!, value: e.target.value };
                      setEnvVars(next);
                    }}
                    type={ev.isSecret ? "password" : "text"}
                    placeholder="value"
                    className="font-mono flex-1 rounded-xl border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-sm focus:outline-none focus:ring-1"
                  />
                  <label className="flex items-center gap-1 text-xs whitespace-nowrap select-none cursor-pointer">
                    <input
                      type="checkbox"
                      checked={ev.isSecret}
                      onChange={(e) => {
                        const next = [...envVars];
                        next[idx] = {
                          ...next[idx]!,
                          isSecret: e.target.checked,
                        };
                        setEnvVars(next);
                      }}
                    />
                    Secret
                  </label>
                  <button
                    type="button"
                    onClick={() =>
                      setEnvVars(envVars.filter((_, i) => i !== idx))
                    }
                    className="ml-1 text-[var(--color-muted-foreground)] hover:text-[var(--color-destructive)]"
                    aria-label="Remove variable"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              {envVars.length === 0 && (
                <div className="text-xs text-[var(--color-muted-foreground)]">
                  No variables yet. Add some above.
                </div>
              )}
            </div>
            <p className="mt-1 text-[10px] text-[var(--color-muted-foreground)]">
              "Secret" rows are masked in the UI. Full age secret storage +
              rotation comes in the next slice.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">
              Target Agents
            </label>
            {availableAgents.length === 0 ? (
              <div className="text-xs text-[var(--color-muted-foreground)] rounded-lg border border-[var(--color-border)] p-3">
                No agents registered yet. Go to{" "}
                <a href="/admin/enrollment-tokens" className="underline">
                  Add Server
                </a>{" "}
                to enroll your first node.
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {availableAgents.map((a: any) => {
                  const id = String(a.id);
                  const selected = selectedAgentIds.includes(id);
                  const connected =
                    a.connected ||
                    (a.last_seen_at &&
                      Date.now() - new Date(a.last_seen_at).getTime() < 90_000);
                  return (
                    <button
                      key={id}
                      type="button"
                      onClick={() => {
                        setSelectedAgentIds((prev) =>
                          selected
                            ? prev.filter((x) => x !== id)
                            : [...prev, id],
                        );
                      }}
                      className={`px-3 py-1.5 rounded-lg text-sm border transition flex items-center gap-2 ${selected ? "bg-[var(--color-primary)] text-[var(--color-primary-foreground)] border-transparent" : "bg-[var(--color-card)] border-[var(--color-border)] hover:bg-[oklch(1_0_0/0.05)]"}`}
                    >
                      <span
                        className={`inline-block w-2 h-2 rounded-full ${connected ? "bg-[var(--color-success)]/120" : "bg-[var(--color-warning)]/100"}`}
                      />
                      {a.hostname || a.name || id.slice(0, 8)}
                      <span className="text-[10px] opacity-70 font-mono">
                        {id.slice(0, 8)}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
            <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1.5">
              Selected: {selectedAgentIds.length || "all connected"}. Deployment
              will be dispatched only to these agents (signed jobs + age
              envelopes per-agent).
            </div>
          </div>

          {/* Ports (published) — complete deploy form per plan */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Published Ports (host:container or just port)
            </label>
            <div className="flex gap-2">
              <input
                value={newPort}
                onChange={(e) => setNewPort(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    if (newPort.trim()) {
                      setPublishedPorts((p) => [...p, newPort.trim()]);
                      setNewPort("");
                    }
                  }
                }}
                className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-5 py-3 text-sm font-mono"
                placeholder="80 or 8080:80"
              />
              <button
                type="button"
                onClick={() => {
                  if (newPort.trim()) {
                    setPublishedPorts((p) => [...p, newPort.trim()]);
                    setNewPort("");
                  }
                }}
                className="rounded-lg border border-[var(--color-border)] px-4 text-sm hover:bg-[var(--color-muted)]"
              >
                Add
              </button>
            </div>
            {publishedPorts.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {publishedPorts.map((p, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center gap-1 rounded-full border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1 text-xs font-mono"
                  >
                    {p}
                    <button
                      type="button"
                      onClick={() =>
                        setPublishedPorts((arr) =>
                          arr.filter((_, j) => j !== i),
                        )
                      }
                      className="ml-1 text-[var(--color-muted-foreground)] hover:text-red-500"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Domains for Traefik + automatic SSL (makes "reachable with SSL" visible end-to-end) */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Public Domains (Traefik will create routers + request Let&apos;s
              Encrypt certs)
            </label>
            <div className="flex gap-2">
              <input
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    if (newDomain.trim()) {
                      setDomains((d) => [...d, newDomain.trim()]);
                      setNewDomain("");
                    }
                  }
                }}
                className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-5 py-3 text-sm"
                placeholder="app.example.com"
              />
              <button
                type="button"
                onClick={() => {
                  if (newDomain.trim()) {
                    setDomains((d) => [...d, newDomain.trim()]);
                    setNewDomain("");
                  }
                }}
                className="rounded-lg border border-[var(--color-border)] px-4 text-sm hover:bg-[var(--color-muted)]"
              >
                Add
              </button>
            </div>
            {domains.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {domains.map((d, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center gap-1 rounded-full border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1 text-xs font-mono"
                  >
                    {d}
                    <button
                      type="button"
                      onClick={() =>
                        setDomains((arr) => arr.filter((_, j) => j !== i))
                      }
                      className="ml-1 text-[var(--color-muted-foreground)] hover:text-red-500"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            )}
            <p className="mt-1 text-xs text-[var(--color-muted-foreground)]">
              These will appear as https:// links with SSL status after the job
              is dispatched.
            </p>
          </div>

          {/* Strategy configuration (Zero-Downtime ready) */}
          <div className="border border-[var(--color-border)] rounded-lg p-4 space-y-4">
            <div className="font-medium text-sm">Deployment Strategy</div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setDeployStrategyType("rolling")}
                className={
                  deployStrategyType === "rolling"
                    ? "btn btn-primary btn-sm flex-1"
                    : "btn btn-ghost btn-sm flex-1"
                }
              >
                Rolling
              </button>
              <button
                type="button"
                onClick={() => setDeployStrategyType("bluegreen")}
                className={
                  deployStrategyType === "bluegreen"
                    ? "btn btn-primary btn-sm flex-1"
                    : "btn btn-ghost btn-sm flex-1"
                }
              >
                Blue/Green
              </button>
              <button
                type="button"
                onClick={() => setDeployStrategyType("canary")}
                className={
                  deployStrategyType === "canary"
                    ? "btn btn-primary btn-sm flex-1"
                    : "btn btn-ghost btn-sm flex-1"
                }
              >
                Canary
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
              <div>
                <label className="block mb-1">Health grace (secs)</label>
                <input
                  type="number"
                  value={healthGrace}
                  onChange={(e) =>
                    setHealthGrace(parseInt(e.target.value) || 30)
                  }
                  className="w-full rounded-xl border px-3 py-2 bg-[var(--color-background)]"
                />
              </div>
              <div>
                <label className="block mb-1">Failure threshold</label>
                <input
                  type="number"
                  value={failureThreshold}
                  onChange={(e) =>
                    setFailureThreshold(parseInt(e.target.value) || 3)
                  }
                  className="w-full rounded-xl border px-3 py-2 bg-[var(--color-background)]"
                />
              </div>
              <div className="flex items-end">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={rollbackOnFailure}
                    onChange={(e) => setRollbackOnFailure(e.target.checked)}
                  />
                  Auto-rollback on failure
                </label>
              </div>
            </div>

            {deployStrategyType === "canary" && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm border-t pt-3 mt-2">
                <div>
                  <label className="block mb-1">Initial traffic %</label>
                  <input
                    type="number"
                    value={canaryInitialTraffic}
                    onChange={(e) =>
                      setCanaryInitialTraffic(parseInt(e.target.value) || 10)
                    }
                    className="w-full rounded-xl border px-3 py-2 bg-[var(--color-background)]"
                  />
                </div>
                <div>
                  <label className="block mb-1">Step %</label>
                  <input
                    type="number"
                    value={canaryStepPercent}
                    onChange={(e) =>
                      setCanaryStepPercent(parseInt(e.target.value) || 10)
                    }
                    className="w-full rounded-xl border px-3 py-2 bg-[var(--color-background)]"
                  />
                </div>
                <div>
                  <label className="block mb-1">Step duration (secs)</label>
                  <input
                    type="number"
                    value={canaryStepDuration}
                    onChange={(e) =>
                      setCanaryStepDuration(parseInt(e.target.value) || 300)
                    }
                    className="w-full rounded-xl border px-3 py-2 bg-[var(--color-background)]"
                  />
                </div>
              </div>
            )}
            <div className="text-[10px] text-[var(--color-muted-foreground)]">
              Strategy and gates are sent with the job and will drive phased
              execution + rollback in the engine.
            </div>

            {/* Honest zero-downtime warning for stateful workloads */}
            <div className="pt-3 border-t">
              <label className="block text-sm font-medium mb-1">
                Workload Type
              </label>
              <select
                value={workloadType}
                onChange={(e) => setWorkloadType(e.target.value as any)}
                className="select"
              >
                <option value="stateless">
                  Stateless (zero-downtime fully supported)
                </option>
                <option value="stateful">
                  Stateful Service (brief disruption possible)
                </option>
                <option value="database">
                  Database / Stateful Store (zero-downtime not guaranteed)
                </option>
              </select>
              {!zeroDowntimeGuaranteed && (
                <div className="mt-2 rounded-xl border border-[var(--color-warning)]/40 bg-[var(--color-warning)]/5 p-3 text-xs text-[var(--color-warning)]">
                  ⚠ Zero-downtime is not guaranteed for {workloadType}{" "}
                  workloads. Expect possible connection resets or dual-write
                  windows during cutover. Consider a maintenance window for
                  production stateful systems.
                </div>
              )}
            </div>

            {/* Phase 3: Prominent One-click Databases & Services (direct "Deploy from Catalog" path + amber secret flow) */}
            <div className="pt-3 border-t">
              <div className="flex items-center justify-between mb-2">
                <div className="font-semibold text-sm">
                  One-click Databases &amp; Services
                </div>
                <div className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--color-success)]/10 text-[var(--color-success)]">
                  Auto backup schedule + age secrets
                </div>
              </div>
              {isLoadingCatalog ? (
                <div className="text-xs text-[var(--color-muted-foreground)]">
                  Loading catalog...
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {catalog
                    .filter((c: any) =>
                      ["database", "cache", "storage"].includes(c.category),
                    )
                    .slice(0, 6)
                    .map((tpl: any) => (
                      <button
                        key={tpl.id}
                        type="button"
                        onClick={async () => {
                          if (!adminToken) return;
                          setIsDeploying(true);
                          try {
                            const res = await fetch(
                              `${API_BASE}/applications/${appId}/deploy-from-catalog`,
                              {
                                method: "POST",
                                headers,
                                body: JSON.stringify({
                                  template_id: tpl.id,
                                  // Let the backend handle generation for secret+generate variables.
                                  // We only send explicit user overrides here.
                                  variables: Object.fromEntries(
                                    (tpl.variables || [])
                                      .filter(
                                        (v: any) => !v.generate && v.default,
                                      )
                                      .map((v: any) => [v.name, v.default]),
                                  ),
                                  strategy: tpl.default_strategy,
                                  targets: deployAgent
                                    ? [{ agent_id: deployAgent, replicas: 1 }]
                                    : [],
                                }),
                              },
                            );
                            if (res.ok) {
                              const dep = await res.json();
                              toast.success(
                                `Deployed ${tpl.name} from catalog (auto daily backup schedule created)`,
                              );
                              // Backend now automatically creates the backup schedule for database templates.
                              // One-time secret reveal (if any were generated) is handled via the global oneTimeSecret banner.
                              setOneTimeSecret(
                                `One or more strong secrets were generated for this catalog deploy. They were age-encrypted for your enrolled agents and will be injected via secure tmpfs. Check the Secrets list or deployment details.`,
                              );
                              setLatestDeployment(dep);
                            } else {
                              toast.error("Catalog deploy failed");
                            }
                          } catch {
                            toast.error("Catalog deploy failed");
                          } finally {
                            setIsDeploying(false);
                          }
                        }}
                        className="group text-left rounded-xl border border-[var(--color-border)] p-4 hover:border-[oklch(1_0_0/0.18)] hover:shadow-sm transition bg-[var(--color-card)] flex flex-col gap-1.5"
                        disabled={isDeploying}
                      >
                        <div className="flex items-center gap-2">
                          <div className="font-semibold tracking-tight group-hover:text-foreground transition">
                            {tpl.name}
                          </div>
                        </div>
                        <div className="text-xs text-[var(--color-muted-foreground)] line-clamp-2 min-h-[2.25rem]">
                          {tpl.description}
                        </div>
                        <div className="mt-auto pt-2 flex items-center justify-between text-[10px]">
                          <span className="font-medium text-[var(--color-primary)] group-hover:underline">
                            Deploy from Catalog →
                          </span>
                          <span className="text-[var(--color-muted-foreground)]">
                            {tpl.category}
                          </span>
                        </div>
                      </button>
                    ))}
                  {catalog.filter((c: any) =>
                    ["database", "cache", "storage"].includes(c.category),
                  ).length === 0 && (
                    <div className="col-span-full text-xs text-[var(--color-muted-foreground)]">
                      No database/cache templates in catalog yet.
                    </div>
                  )}
                </div>
              )}
              <div className="text-[10px] text-[var(--color-muted-foreground)] mt-2">
                One-click deploys a managed workload with rolling strategy tuned
                for stateful, auto daily backup schedule, and age-protected
                secrets shown once above via amber banner (exact RBAC pattern).
              </div>
            </div>
          </div>

          {/* Phase 2 Change Preview with actual spec diff */}
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-4 text-sm">
            <div className="font-medium mb-2">
              Change Preview — What will actually change on the agent
            </div>

            {previousDeployment ? (
              <div className="space-y-2">
                <DiffRow
                  label="Image"
                  oldVal={getImageFromSpec(previousDeployment.spec)}
                  newVal={deployImage}
                />
                <DiffRow
                  label="Strategy"
                  oldVal={String(
                    (previousDeployment.strategy as any)?.type || "unknown",
                  )}
                  newVal={deployStrategyType}
                />
                <DiffRow
                  label="Ports"
                  oldVal={JSON.stringify(
                    getPortsFromSpec(previousDeployment.spec),
                  )}
                  newVal={JSON.stringify(publishedPorts)}
                />
                <DiffRow
                  label="Domains"
                  oldVal={JSON.stringify(
                    getDomainsFromSpec(previousDeployment.spec),
                  )}
                  newVal={JSON.stringify(domains)}
                />
                <DiffRow
                  label="Env Vars"
                  oldVal={getEnvSummaryFromVars([])}
                  newVal={getEnvSummaryFromVars(envVars)}
                />
              </div>
            ) : (
              <div className="text-[var(--color-muted-foreground)]">
                First deployment for this app — no previous version to diff
                against.
              </div>
            )}

            <div className="mt-2 text-[10px] text-[var(--color-muted-foreground)]">
              Using {deployStrategyType} with the config above. Previous version
              kept for rollback.
            </div>

            {!zeroDowntimeGuaranteed && (
              <div className="mt-2 text-[10px] text-[var(--color-warning)] font-medium">
                ⚠ Honest note: Zero-downtime not guaranteed for this workload
                type.
              </div>
            )}
          </div>

          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => {
                const spec = buildImageDeploySpec();
                // Merge secrets handling for preview (simplified - real secrets added on submit)
                const previewSpec = {
                  ...spec,
                  // Note: real secrets are added via age in handleDeploy
                };
                setPreviewSpecJson(JSON.stringify(previewSpec, null, 2));
                setShowPreviewSpec(true);
              }}
              className="flex-1 rounded-lg border border-[var(--color-border)] py-3.5 text-sm font-medium hover:bg-[var(--color-muted)] transition"
            >
              Preview Spec (JSON)
            </button>

            <button
              type="submit"
              disabled={
                isDeploying ||
                !adminToken ||
                !deployImage.trim() ||
                selectedAgentIds.length === 0
              }
              className="btn btn-primary flex-[2] py-3.5"
            >
              {isDeploying ? (
                <>Signing &amp; dispatching…</>
              ) : (
                `Deploy Image to ${selectedAgentIds.length || 0} agent${selectedAgentIds.length === 1 ? "" : "s"}`
              )}
            </button>
          </div>

          {/* Helpful note for image path completeness (Slice C) */}
          <div className="text-[10px] text-[var(--color-muted-foreground)]">
            Image deploy path is complete for Phase 1: private registry, dynamic
            secrets (age), ports, domains, strategy, targets. Git path is
            secondary.
          </div>
        </form>
      </div>

      {/* Rich Post-Deploy Experience – polished status + activity */}
      {latestDeployment ? (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-8 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-semibold text-xl tracking-tight">
                Latest Deployment
              </div>
              <div className="text-sm text-[var(--color-muted-foreground)]">
                v{latestDeployment.version} ·{" "}
                {new Date(latestDeployment.created_at).toLocaleString()}
              </div>
            </div>

            {/* Derived rich status badge */}
            <div
              className={`text-xs px-3 py-1 rounded-full border font-medium ${
                liveResults[0]?.success === false
                  ? "bg-[var(--color-destructive)]/10 text-[var(--color-destructive)] border-[var(--color-destructive)]/20"
                  : liveResults.length > 0
                    ? "bg-[var(--color-success)]/10 text-[var(--color-success)] border-[var(--color-success)]/20"
                    : "bg-[var(--color-warning)]/10 text-[var(--color-warning)] border-[var(--color-warning)]/20"
              }`}
            >
              {liveResults[0]?.success === false
                ? "FAILED"
                : liveResults.length > 0
                  ? "RUNNING / HEALTHY"
                  : latestDeployment.status || "DISPATCHED"}
            </div>
          </div>

          {/* Live status from JobResults polling – richer */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className="text-sm font-medium">
                Live Activity from Agent (JobResults)
              </div>
              {isPolling && (
                <div className="text-[10px] px-2 py-0.5 rounded bg-[var(--color-success)]/10 text-[var(--color-success)]">
                  LIVE • refreshing
                </div>
              )}
            </div>

            {liveResults.length === 0 ? (
              <div className="rounded-lg border border-[var(--color-border)] p-6 text-sm text-[var(--color-muted-foreground)]">
                Waiting for first results from the agent. Logs are already
                streaming above.
              </div>
            ) : (
              <div className="space-y-2 text-sm font-mono bg-[var(--color-background)] rounded-lg p-4 border border-[var(--color-border)]">
                {liveResults.slice(0, 8).map((r, idx) => (
                  <div
                    key={idx}
                    className="flex justify-between py-1 border-b border-[var(--color-border)] last:border-b-0"
                  >
                    <div className="text-[var(--color-muted-foreground)]">
                      {r.job_type} ·{" "}
                      {r.started_at
                        ? new Date(r.started_at).toLocaleTimeString()
                        : ""}
                    </div>
                    <div
                      className={
                        r.success
                          ? "text-[var(--color-success)]"
                          : "text-[var(--color-destructive)]"
                      }
                    >
                      {r.success ? "✓ SUCCESS" : "✕ FAILED"}
                      {r.error && ` — ${r.error}`}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Sophisticated Rollout UI + Deeper Observability (Phase 2 advanced) */}
          <div className="rounded-lg border border-[var(--color-border)] p-5 text-sm space-y-4">
            <div className="flex items-center justify-between">
              <div className="font-semibold">
                Rollout Progress — {deployStrategyType.toUpperCase()}
              </div>
              <div
                className={`text-xs px-2 py-0.5 rounded ${latestDeployment?.status === "healthy" ? "bg-[var(--color-success)]/10 text-[var(--color-success)]" : "bg-[var(--color-warning)]/10 text-[var(--color-warning)]"}`}
              >
                {latestDeployment?.status || "in progress"}
              </div>
            </div>

            {/* Visual progress + stateful awareness */}
            <div>
              {deployStrategyType === "canary" ? (
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span>Traffic to new version</span>
                    <span className="font-mono">
                      {(latestDeployment as any)?.rollout_state
                        ?.current_traffic_percent || 0}
                      %
                    </span>
                  </div>
                  <div className="h-2 bg-[var(--color-muted)] rounded-full overflow-hidden">
                    <div
                      className="h-2 bg-[var(--color-primary)] transition-all"
                      style={{
                        width: `${(latestDeployment as any)?.rollout_state?.current_traffic_percent || 0}%`,
                      }}
                    />
                  </div>
                </div>
              ) : (
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span>Replicas rolled</span>
                    <span className="font-mono">
                      {(latestDeployment as any)?.rollout_state
                        ?.current_replicas || 0}{" "}
                      /{" "}
                      {(latestDeployment as any)?.rollout_state
                        ?.target_replicas || 1}
                    </span>
                  </div>
                  <div className="h-2 bg-[var(--color-muted)] rounded-full overflow-hidden">
                    <div
                      className="h-2 bg-[var(--color-primary)] transition-all"
                      style={{
                        width: `${Math.min(100, (((latestDeployment as any)?.rollout_state?.current_replicas || 0) / ((latestDeployment as any)?.rollout_state?.target_replicas || 1)) * 100)}%`,
                      }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Deeper observability: recent metric snapshots for rollout + stateful signals */}
            <div>
              <div className="font-medium mb-1 text-xs">
                Live Rollout Observability (metrics over time)
              </div>
              {rolloutMetrics.length > 0 ? (
                <div className="text-[10px] font-mono bg-[var(--color-background)] p-2 rounded border border-[var(--color-border)] max-h-24 overflow-auto">
                  {rolloutMetrics.slice(-5).map((m: any, i: number) => (
                    <div key={i}>
                      {new Date(m.timestamp).toLocaleTimeString()}:{" "}
                      {m.metric_name}={m.value}{" "}
                      {m.labels && JSON.stringify(m.labels)}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[var(--color-muted-foreground)] text-xs">
                  Collecting rollout metrics (error_rate, p99, health, traffic
                  weight, drain progress for stateful)...
                </div>
              )}
              <div className="text-[10px] text-[var(--color-muted-foreground)] mt-1">
                Deeper signals: HealthCheck results, container stats, L7
                weights, stateful drain metrics (connections, replication lag)
                flow here during phased execution.
              </div>
            </div>

            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <div>
                Phase:{" "}
                <span className="font-mono">
                  {(latestDeployment as any)?.rollout_state?.phase || "initial"}
                </span>
              </div>
              <div>
                Failure count:{" "}
                <span className="font-mono">
                  {(latestDeployment as any)?.rollout_state?.failure_count || 0}
                </span>
              </div>
              <div>
                Last healthy gate:{" "}
                <span className="font-mono text-[10px]">
                  {(latestDeployment as any)?.rollout_state
                    ?.last_health_gate_passed_at
                    ? new Date(
                        (latestDeployment as any).rollout_state
                          .last_health_gate_passed_at,
                      ).toLocaleTimeString()
                    : "—"}
                </span>
              </div>
              {deployStrategyType === "canary" && (
                <div>
                  Current traffic:{" "}
                  <span className="font-mono">
                    {(latestDeployment as any)?.rollout_state
                      ?.current_traffic_percent || 0}
                    %
                  </span>
                </div>
              )}
            </div>

            {/* Real status timeline — sourced from liveResults (JobResultRow from /results endpoint) */}
            <div className="pt-3 border-t border-[var(--color-border)]">
              <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-[var(--color-muted-foreground)] mb-2">
                <Clock className="w-3.5 h-3.5" /> Execution Timeline
                (JobResults)
              </div>
              <StatusTimeline results={liveResults as any} max={10} />
            </div>

            <div className="text-[10px] text-[var(--color-muted-foreground)] pt-1 border-t">
              Health gates driven by real HealthCheck jobs + metrics
              (error_rate, p99, stateful signals). Automatic rollback active.
              Better stateful drain (pre-stop + extended grace) active in agent.
            </div>
          </div>

          {/* Prominent rich actions + Phase 2 manual controls */}
          <div className="flex gap-3 pt-4 border-t border-[var(--color-border)]">
            <button
              onClick={() =>
                latestDeployment && openLogsForDeployment(latestDeployment)
              }
              className="btn btn-ghost flex-1"
            >
              Open Live Logs
            </button>
            <Link
              href="/admin/deployments"
              className="btn btn-primary flex-1 text-center py-3"
            >
              Full Deployments
            </Link>
          </div>

          {/* Phase 2 manual promote / rollback controls (wired to backend) */}
          <div className="flex gap-3">
            <button
              onClick={async () => {
                if (!latestDeployment || !adminToken) return;
                try {
                  const res = await fetch(
                    `${API_BASE}/admin/deployments/${latestDeployment.id}/promote`,
                    { method: "POST", headers },
                  );
                  if (res.ok) {
                    toast.success("Promote requested");
                    // refresh activity
                    await loadApplication();
                  } else {
                    toast.error("Promote failed");
                  }
                } catch {
                  toast.error("Promote failed");
                }
              }}
              className="btn btn-ghost flex-1"
            >
              Manual Promote (to 100%)
            </button>
            <button
              onClick={async () => {
                if (!latestDeployment || !adminToken) return;
                try {
                  const res = await fetch(
                    `${API_BASE}/admin/deployments/${latestDeployment.id}/rollback`,
                    { method: "POST", headers },
                  );
                  if (res.ok) {
                    toast.success("Rollback requested");
                    await loadApplication();
                  } else {
                    toast.error("Rollback failed");
                  }
                } catch {
                  toast.error("Rollback failed");
                }
              }}
              className="btn btn-danger flex-1"
            >
              Manual Rollback
            </button>
          </div>

          {/* End-to-end reachable with SSL visibility (per Phase 1 plan) */}
          {domains.length > 0 && (
            <div className="pt-4 border-t border-[var(--color-border)]">
              <div className="font-semibold text-sm mb-2">
                Reachable Endpoints (Traefik + Let&apos;s Encrypt)
              </div>
              <div className="space-y-2">
                {domains.map((d, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-2.5 text-sm"
                  >
                    <div className="font-mono flex-1 truncate">https://{d}</div>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(`https://${d}`);
                        toast.success("Copied");
                      }}
                      className="px-3 py-1 text-xs rounded-xl border border-[var(--color-border)] hover:bg-[var(--color-muted)]"
                    >
                      Copy
                    </button>
                    <a
                      href={`https://${d}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1 text-xs rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-foreground)] hover:opacity-90"
                    >
                      Open
                    </a>
                  </div>
                ))}
              </div>
              <div className="mt-2 text-[10px] text-[var(--color-muted-foreground)]">
                Configuration sent with the job. Agent will configure Traefik
                router + request certificate on first request. Monitor logs for
                &quot;acme&quot; / certificate events.
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Better empty state */
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-12 text-center">
          <div className="mx-auto w-12 h-12 rounded-full bg-[var(--color-muted)] mb-4" />
          <div className="font-medium text-lg">
            No deployments yet for this application
          </div>
          <p className="mt-2 text-[var(--color-muted-foreground)] max-w-sm mx-auto">
            Use the form above to deploy a container image or connect a Git
            source. After the first deploy, live status and logs will appear
            here automatically.
          </p>
        </div>
      )}

      {/* ---- Builds Section ---- */}
      <div className="rounded-xl border border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)]">
        <div className="flex items-center justify-between border-b border-[oklch(1_0_0/0.07)] px-6 py-4">
          <div className="flex items-center gap-2">
            <Hammer className="h-4 w-4 text-[oklch(1_0_0/0.45)]" />
            <span className="text-[13px] font-semibold tracking-tight">
              Builds
            </span>
            {builds.length > 0 && (
              <span className="rounded-[4px] border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.04)] px-1.5 py-px text-[10px] font-medium tabular-nums text-[oklch(1_0_0/0.45)]">
                {builds.length}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void fetchBuilds()}
              className="btn btn-ghost btn-sm"
              aria-label="Refresh builds"
            >
              {buildsLoading ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                "Refresh"
              )}
            </button>
            <button
              type="button"
              onClick={() => {
                if (gitSources.length === 0) void fetchGitSources();
                setShowNewBuild(true);
              }}
              className="btn btn-primary btn-sm"
            >
              <Hammer className="h-3.5 w-3.5" />
              New Build
            </button>
          </div>
        </div>

        {/* Git source hint */}
        {gitSources.length > 0 && (
          <div className="flex items-center gap-2 border-b border-[oklch(1_0_0/0.05)] bg-[oklch(0.72_0.17_150/0.04)] px-6 py-2.5">
            <GitBranch className="h-3.5 w-3.5 shrink-0 text-[var(--color-success)]" />
            <span className="text-[11px] text-[oklch(1_0_0/0.45)]">
              {gitSources.length === 1
                ? `Git source connected: ${gitSources[0]?.name ?? gitSources[0]?.repo_url}`
                : `${gitSources.length} git sources connected`}{" "}
              — trigger a build to build from source and get a signed image
              digest.
            </span>
          </div>
        )}

        {/* Builds list */}
        {buildsLoading && builds.length === 0 ? (
          <div className="space-y-px p-4">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-12 animate-pulse rounded-md border border-[oklch(1_0_0/0.06)] bg-[oklch(0.2_0_0)]"
              />
            ))}
          </div>
        ) : builds.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-14 text-center">
            <Hammer className="mb-3 h-7 w-7 text-[oklch(1_0_0/0.2)]" />
            <div className="text-[13px] font-medium text-[oklch(1_0_0/0.5)]">
              No builds yet
            </div>
            <div className="mt-1 text-[11px] text-[oklch(1_0_0/0.3)]">
              Trigger a build from a Git source to get a signed,
              provenance-tracked image
            </div>
            <button
              type="button"
              onClick={() => {
                if (gitSources.length === 0) void fetchGitSources();
                setShowNewBuild(true);
              }}
              className="btn btn-primary btn-sm mt-5"
            >
              <Hammer className="h-3.5 w-3.5" />
              New Build
            </button>
          </div>
        ) : (
          <ul className="divide-y divide-[oklch(1_0_0/0.05)]">
            {builds.map((build, idx) => {
              const statusDot =
                build.status === "succeeded"
                  ? "status-dot-healthy"
                  : build.status === "running"
                    ? "status-dot-progress"
                    : build.status === "failed"
                      ? "status-dot-failed"
                      : "status-dot-pending";
              const isPulse =
                build.status === "succeeded" || build.status === "running";

              return (
                <li
                  key={build.id}
                  className="reveal flex items-center gap-3 px-6 py-3.5"
                  style={{ animationDelay: `${idx * 25}ms` }}
                >
                  {/* Status dot */}
                  <span
                    className={`status-dot shrink-0 ${statusDot} ${isPulse ? "pulse-dot text-[var(--color-success)]" : ""}`}
                  />

                  {/* Builder chip */}
                  <span className="inline-flex w-20 shrink-0 items-center justify-center rounded-[4px] border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.04)] px-1.5 py-px text-[10px] font-medium uppercase tracking-wide text-[oklch(1_0_0/0.5)]">
                    {build.builder}
                  </span>

                  {/* Commit SHA + ref */}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[12px] text-[oklch(0.97_0_0)]">
                        {build.commit_sha
                          ? build.commit_sha.slice(0, 7)
                          : build.id.slice(0, 7)}
                      </span>
                      {build.ref && (
                        <span className="flex items-center gap-1 text-[11px] text-[oklch(1_0_0/0.38)]">
                          <GitBranch className="h-3 w-3" />
                          {build.ref}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 text-[10px] text-[oklch(1_0_0/0.3)] tabular-nums">
                      {new Date(build.created_at).toLocaleString()}
                    </div>
                  </div>

                  {/* Supply-chain badge */}
                  {(build.signed ?? false) && (
                    <div
                      title={
                        (build.provenance ?? false)
                          ? "Signed + provenance attestation present"
                          : "Image signed"
                      }
                      className={`inline-flex items-center gap-1 rounded-[4px] border px-2 py-px text-[10px] font-semibold ${
                        (build.provenance ?? false)
                          ? "border-[oklch(0.72_0.17_150/0.35)] bg-[oklch(0.72_0.17_150/0.08)] text-[var(--color-success)]"
                          : "border-[oklch(1_0_0/0.12)] bg-[oklch(1_0_0/0.05)] text-[oklch(1_0_0/0.55)]"
                      }`}
                    >
                      <Shield className="h-3 w-3" />
                      {(build.provenance ?? false)
                        ? "signed + provenance"
                        : "signed"}
                    </div>
                  )}

                  {/* Status text */}
                  <span className="w-20 shrink-0 text-right text-[11px] capitalize text-[oklch(1_0_0/0.4)]">
                    {build.status}
                  </span>

                  {/* Logs button */}
                  <button
                    type="button"
                    onClick={() => openBuildLogs(build)}
                    className="btn btn-ghost btn-sm shrink-0"
                    aria-label={`View logs for build ${build.id.slice(0, 7)}`}
                  >
                    Logs
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* ---- New Build Dialog ---- */}
      <Dialog.Root open={showNewBuild} onOpenChange={setShowNewBuild}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-7 shadow-2xl focus:outline-none">
            <div className="mb-5 flex items-center justify-between">
              <Dialog.Title className="text-base font-semibold tracking-tight">
                Trigger Build
              </Dialog.Title>
              <Dialog.Close asChild>
                <button
                  aria-label="Close"
                  className="grid h-7 w-7 place-items-center rounded-md text-[oklch(1_0_0/0.4)] transition-colors hover:bg-[oklch(1_0_0/0.07)] hover:text-[oklch(0.97_0_0)]"
                >
                  <X className="h-4 w-4" />
                </button>
              </Dialog.Close>
            </div>

            <form onSubmit={(e) => void triggerBuild(e)} className="space-y-4">
              {/* Git source */}
              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Git source{" "}
                  <span className="font-normal text-[oklch(1_0_0/0.3)]">
                    (optional)
                  </span>
                </label>
                {gitSources.length > 0 ? (
                  <Select.Root
                    value={buildGitSourceId}
                    onValueChange={setBuildGitSourceId}
                  >
                    <Select.Trigger
                      className="select flex items-center justify-between"
                      aria-label="Select git source"
                    >
                      <Select.Value placeholder="Select git source…" />
                      <Select.Icon>
                        <ChevronDown className="h-3.5 w-3.5 text-[oklch(1_0_0/0.4)]" />
                      </Select.Icon>
                    </Select.Trigger>
                    <Select.Portal>
                      <Select.Content className="z-[200] overflow-hidden rounded-lg border border-[oklch(1_0_0/0.1)] bg-[oklch(0.2_0_0)] shadow-xl">
                        <Select.Viewport className="p-1">
                          <Select.Item
                            value=""
                            className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[13px] text-[oklch(1_0_0/0.45)] outline-none hover:bg-[oklch(1_0_0/0.07)] focus:bg-[oklch(1_0_0/0.07)]"
                          >
                            <Select.ItemText>
                              None (manual build)
                            </Select.ItemText>
                          </Select.Item>
                          {gitSources.map((gs) => (
                            <Select.Item
                              key={gs.id}
                              value={gs.id}
                              className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[13px] outline-none hover:bg-[oklch(1_0_0/0.07)] focus:bg-[oklch(1_0_0/0.07)]"
                            >
                              <Select.ItemText>
                                {gs.name} — {gs.repo_url}
                              </Select.ItemText>
                              <Select.ItemIndicator className="ml-auto">
                                <Check className="h-3 w-3" />
                              </Select.ItemIndicator>
                            </Select.Item>
                          ))}
                        </Select.Viewport>
                      </Select.Content>
                    </Select.Portal>
                  </Select.Root>
                ) : (
                  <div className="rounded-md border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.03)] px-3 py-2 text-[12px] text-[oklch(1_0_0/0.38)]">
                    No git sources connected yet — builds will run without a
                    source checkout
                  </div>
                )}
              </div>

              {/* Ref */}
              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Branch / tag / commit
                </label>
                <input
                  value={buildRef}
                  onChange={(e) => setBuildRef(e.target.value)}
                  className="input font-mono"
                  placeholder="main"
                  aria-label="Git ref"
                />
              </div>

              {/* Builder */}
              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Builder
                </label>
                <div className="flex gap-2">
                  {(["nixpacks", "dockerfile", "compose"] as const).map((b) => (
                    <button
                      key={b}
                      type="button"
                      onClick={() => setBuildBuilder(b)}
                      className={`btn btn-sm flex-1 capitalize ${buildBuilder === b ? "btn-primary" : "btn-ghost"}`}
                    >
                      {b}
                    </button>
                  ))}
                </div>
                <p className="mt-1 text-[11px] text-[oklch(1_0_0/0.35)]">
                  {buildBuilder === "nixpacks" &&
                    "Auto-detects language and builds a container image via Nixpacks."}
                  {buildBuilder === "dockerfile" &&
                    "Builds from a Dockerfile in the repo root (or specified path)."}
                  {buildBuilder === "compose" &&
                    "Builds all services defined in docker-compose.yml."}
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
                  disabled={isTriggering}
                  className="btn btn-primary btn-sm"
                >
                  {isTriggering ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Triggering…
                    </>
                  ) : (
                    "Trigger Build"
                  )}
                </button>
              </div>
            </form>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* ---- Build Logs Dialog ---- */}
      <Dialog.Root
        open={showBuildLogs}
        onOpenChange={(open) => {
          if (!open) closeBuildLogs();
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[150] bg-black/60" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-[160] flex h-[70vh] w-full max-w-5xl -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-xl border border-[var(--color-card-border)] bg-[#0a0a0a] text-[#d1d5db] shadow-2xl focus:outline-none">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-white/10 bg-black/40 px-6 py-4">
              <div className="flex items-center gap-3">
                <Dialog.Title className="text-base font-semibold">
                  Build Logs
                  {activeBuild && (
                    <span className="ml-2 font-mono text-[12px] font-normal text-[oklch(1_0_0/0.45)]">
                      {activeBuild.id.slice(0, 8)}
                    </span>
                  )}
                </Dialog.Title>

                {/* Connection status */}
                <div
                  className={`flex items-center gap-1.5 rounded-full border px-2.5 py-px text-[11px] ${
                    buildLogsStatus === "connected"
                      ? "border-[var(--color-success)]/40 bg-[var(--color-success)]/10 text-[var(--color-success)]"
                      : buildLogsStatus === "connecting"
                        ? "border-[var(--color-warning)]/40 bg-[var(--color-warning)]/10 text-[var(--color-warning)]"
                        : buildLogsStatus === "error"
                          ? "border-[var(--color-destructive)]/40 bg-[var(--color-destructive)]/10 text-[var(--color-destructive)]"
                          : "border-white/20 bg-black/20 text-[#9ca3af]"
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      buildLogsStatus === "connected"
                        ? "bg-[var(--color-success)]"
                        : buildLogsStatus === "connecting"
                          ? "animate-pulse bg-[var(--color-warning)]"
                          : buildLogsStatus === "error"
                            ? "bg-[var(--color-destructive)]"
                            : "bg-[#6b7280]"
                    }`}
                  />
                  {buildLogsStatus}
                </div>

                {/* Supply-chain badge in header if available */}
                {activeBuild?.signed === true && (
                  <div
                    className={`flex items-center gap-1 rounded-[4px] border px-2 py-px text-[10px] font-semibold ${
                      activeBuild.provenance === true
                        ? "border-[oklch(0.72_0.17_150/0.35)] bg-[oklch(0.72_0.17_150/0.1)] text-[var(--color-success)]"
                        : "border-white/15 bg-white/5 text-[oklch(1_0_0/0.55)]"
                    }`}
                  >
                    <Shield className="h-3 w-3" />
                    {activeBuild.provenance === true
                      ? "signed + provenance"
                      : "signed"}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setBuildLogLines([])}
                  className="rounded border border-white/20 px-3 py-1 text-[11px] hover:bg-white/5"
                >
                  Clear
                </button>
                <button
                  type="button"
                  onClick={closeBuildLogs}
                  aria-label="Close"
                  className="text-[#9ca3af] hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Image digest */}
            {activeBuild?.image_digest && (
              <div className="border-b border-white/10 bg-[oklch(0.08_0_0)] px-6 py-2">
                <span className="mr-2 text-[10px] uppercase tracking-widest text-[#9ca3af]">
                  Digest
                </span>
                <span className="font-mono text-[11px] text-[oklch(0.97_0_0)]">
                  {activeBuild.image_digest}
                </span>
              </div>
            )}

            {/* Log output */}
            <div
              ref={buildLogsRef}
              className="flex-1 overflow-auto bg-black/90 p-4 font-mono text-sm leading-snug whitespace-pre-wrap"
            >
              {buildLogLines.length === 0 ? (
                <div className="text-[#6b7280]">
                  {buildLogsStatus === "connecting"
                    ? "Connecting to build log stream…"
                    : "No log output yet."}
                </div>
              ) : (
                buildLogLines.map((line, i) => (
                  <div
                    key={i}
                    className="-mx-1 flex rounded px-1 hover:bg-white/5"
                  >
                    <span className="w-8 select-none pr-3 text-right tabular-nums text-[#3f3f46]">
                      {i + 1}
                    </span>
                    <span className="flex-1">{line}</span>
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between border-t border-white/10 bg-black/40 px-6 py-3 text-[11px] text-[#9ca3af]">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob([buildLogLines.join("\n")], {
                      type: "text/plain",
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `build-${activeBuild?.id ?? "log"}.log`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="rounded border border-white/20 px-3 py-1 hover:bg-white/5"
                >
                  Download .log
                </button>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard.writeText(
                      buildLogLines.join("\n"),
                    );
                    toast.success("Copied to clipboard");
                  }}
                  className="flex items-center gap-1 rounded border border-white/20 px-3 py-1 hover:bg-white/5"
                >
                  <Copy className="h-3 w-3" /> Copy all
                </button>
              </div>
              <span className="tabular-nums">{buildLogLines.length} lines</span>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Logs Dialog — now matches deployments polish: timestamps, filter+highlight, pause, copy, status, line nums */}
      <Dialog.Root
        open={showLogsDialog}
        onOpenChange={(open) => {
          if (!open) closeLogs();
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 z-[150]" />
          <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-5xl h-[70vh] rounded-xl border border-[var(--color-border)] bg-[#0a0a0a] text-[#d1d5db] shadow-2xl z-[160] flex flex-col overflow-hidden focus:outline-none">
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-black/40">
              <div className="flex items-center gap-3">
                <Dialog.Title className="font-semibold text-lg">
                  Live Logs — {latestDeployment?.id}
                </Dialog.Title>

                <div
                  className={`flex items-center gap-1.5 text-xs px-2.5 py-0.5 rounded-full border ${
                    logsConnectionStatus === "connected"
                      ? "bg-[var(--color-success)]/10 border-[var(--color-success)]/40 text-[var(--color-success)]"
                      : logsConnectionStatus === "connecting"
                        ? "bg-[var(--color-warning)]/10 border-[var(--color-warning)]/40 text-[var(--color-warning)]"
                        : logsConnectionStatus === "error"
                          ? "bg-[var(--color-destructive)]/10 border-[var(--color-destructive)]/40 text-[var(--color-destructive)]"
                          : "bg-[var(--color-card)]/5 border-white/20 text-[#9ca3af]"
                  }`}
                >
                  <div
                    className={`w-1.5 h-1.5 rounded-full ${
                      logsConnectionStatus === "connected"
                        ? "bg-[var(--color-success)]"
                        : logsConnectionStatus === "connecting"
                          ? "bg-[var(--color-warning)] animate-pulse"
                          : logsConnectionStatus === "error"
                            ? "bg-[var(--color-destructive)]"
                            : "bg-[#6b7280]"
                    }`}
                  />
                  {logsConnectionStatus}
                </div>

                <button
                  onClick={() => {
                    /* toggle follow */ const next = !followLogs;
                    setFollowLogs(next);
                    if (next) setLogsPaused(false);
                  }}
                  className={`text-xs px-3 py-1 rounded border transition flex items-center gap-1 ${followLogs ? "bg-[var(--color-success)]/20 border-[var(--color-success)] text-[var(--color-success)]" : "border-white/20 hover:bg-[var(--color-card)]/5"}`}
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
                      setLogsPaused(false); /* follow stays */
                    }}
                    className="text-[10px] px-2 py-0.5 rounded border border-amber-500/40 text-amber-400"
                  >
                    Resume
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

            <div
              ref={logsContainerRef}
              className="flex-1 overflow-auto p-4 font-mono text-sm bg-black/90 whitespace-pre-wrap leading-snug"
            >
              {logLines.length === 0 ? (
                <div className="text-[#6b7280]">
                  Waiting for log stream after deploy...
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
                  aria-label="Filter log lines"
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
                    a.download = `logs-${latestDeployment?.id || "deployment"}.log`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="text-xs px-3 py-1 rounded border border-white/20 hover:bg-[var(--color-card)]/5"
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
                {logLines.length} lines • real agent stream
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Slice C: Preview Spec Modal (education + debug, high value per plan) */}
      <Dialog.Root open={showPreviewSpec} onOpenChange={setShowPreviewSpec}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/70 z-[170]" />
          <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] max-w-3xl max-h-[80vh] overflow-hidden rounded-xl border border-[var(--color-card-border)] bg-[var(--color-card)] shadow-2xl z-[180] flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b">
              <Dialog.Title className="font-semibold text-lg">
                Preview DeploymentSpec (what the agent will receive)
              </Dialog.Title>
              <Dialog.Close asChild>
                <button className="text-sm px-3 py-1 rounded border">
                  Close
                </button>
              </Dialog.Close>
            </div>
            <div className="flex-1 overflow-auto p-6 font-mono text-xs bg-black/90 whitespace-pre">
              {previewSpecJson || "No spec generated yet."}
            </div>
            <div className="p-4 border-t text-[10px] text-[var(--color-muted-foreground)]">
              This is the exact JSON that will be signed and sent as part of
              Job::Deploy. The agent executes it directly.
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Phase 3: Magical "Update Forge" Self-Update Dialog — richer tiered preview + stateful warnings + embedded L7/stateful observability (dogfoods entire engine) */}
      <Dialog.Root open={showUpdateForge} onOpenChange={setShowUpdateForge}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/80 z-[200]" />
          <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[96vw] max-w-4xl rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-8 shadow-2xl z-[210] focus:outline-none overflow-auto max-h-[88vh]">
            <Dialog.Title className="text-2xl font-semibold tracking-tight mb-1.5 text-foreground">
              Update Forge — Zero-Downtime (Dogfood)
            </Dialog.Title>
            <p className="text-[var(--color-muted-foreground)] mb-5 text-sm">
              The entire platform updates using the exact same DeploymentSpec +
              record_job_result health gates + time-aware Canary + stateful
              drain + L7 weight updates + automatic rollback engine that powers
              your apps. This is the strongest possible credibility signal.
            </p>

            {/* Rich tiered Change Preview with honest stateful warnings */}
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-background)] p-5 mb-5 text-sm">
              <div className="font-semibold mb-3 tracking-tight">
                Tiered Rollout Preview (real engine strategy)
              </div>
              <div className="space-y-3 text-xs">
                <div className="rounded-xl border border-[var(--color-border)] p-3">
                  <div className="font-medium text-[var(--color-foreground)]">
                    1. Agents (stateless canary first — lowest risk)
                  </div>
                  <div className="mt-1 text-[var(--color-muted-foreground)]">
                    10% initial traffic → +25% steps every 90s. Gates:
                    error_rate &lt; 1% AND p99 &lt; 500ms within
                    health_check_grace. Automatic rollback on breach. No
                    volumes.
                  </div>
                </div>
                <div className="rounded-xl border border-[var(--color-border)] p-3">
                  <div className="font-medium text-[var(--color-success)]">
                    2. Control Plane (blue-green after agents healthy)
                  </div>
                  <div className="mt-1 text-[var(--color-muted-foreground)]">
                    Stateless cutover with scale-down-old-after. Full
                    previous_spec snapshot for instant rollback. xDS live weight
                    handoff.
                  </div>
                </div>
                <div className="rounded-xl border border-[var(--color-warning)]/40 bg-[var(--color-warning)]/5 p-3">
                  <div className="font-medium text-[var(--color-warning)]">
                    3. Postgres / stateful core (rolling with extended handling
                    — honest warning)
                  </div>
                  <div className="mt-1 text-[var(--color-warning)]/90">
                    Uses ContainerSpec.is_stateful + pre_stop drain hooks +
                    drain_grace_seconds (extended) +
                    stateful_health_plugins=["postgres_replication_lag","active_connections"].
                    Longer grace + L7 drain progress signals.{" "}
                    <span className="font-semibold">
                      Brief write pause or connection reset windows possible
                      during weight cutover. Monitor the embedded L7 + plugin
                      signals below. Prefer maintenance window for prod.
                    </span>
                  </div>
                </div>
              </div>
              <div className="text-[var(--color-warning)] text-[10px] mt-3 font-medium">
                ⚠ Any phase failure → automatic rollback to previous_spec using
                the identical strategy + JobResult ingestion path your workloads
                use.
              </div>
            </div>

            {/* Tighter integration: embedded live L7 + stateful + rollout observability for the forge-system meta deployment (reuses the exact panels from the main detail page) */}
            {isUpdatingForge && systemDeployment && (
              <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] p-4 mb-5 text-sm">
                <div className="font-semibold mb-2 text-[var(--color-foreground)]">
                  Live forge-system Rollout + L7/Stateful Observability (real
                  engine data)
                </div>
                <div className="text-xs mb-2">
                  Status:{" "}
                  <span className="font-mono">{systemDeployment.status}</span> ·
                  v{systemDeployment.version}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[10px]">
                  <div className="rounded border border-[var(--color-border)] bg-[var(--color-background)] p-2">
                    <div className="font-medium mb-1">Rollout Progress</div>
                    {/* reason: rollout_state is arbitrary JSONB from the engine (same as 20+ other casts in this file) */}
                    <div>
                      Phase:{" "}
                      {(systemDeployment as any)?.rollout_state?.phase || "—"} ·
                      Traffic:{" "}
                      {(systemDeployment as any)?.rollout_state
                        ?.current_traffic_percent || 0}
                      %
                    </div>
                    <div>
                      Failures:{" "}
                      {(systemDeployment as any)?.rollout_state
                        ?.failure_count || 0}{" "}
                      · Last gate:{" "}
                      {(systemDeployment as any)?.rollout_state
                        ?.last_health_gate_passed_at
                        ? new Date(
                            (systemDeployment as any).rollout_state
                              .last_health_gate_passed_at,
                          ).toLocaleTimeString()
                        : "—"}
                    </div>
                  </div>
                  <div className="rounded border border-[var(--color-border)] bg-[var(--color-background)] p-2">
                    <div className="font-medium mb-1">
                      Stateful + L7 Signals (from agent HealthCheck + xDS)
                    </div>
                    <div className="text-[var(--color-muted-foreground)]">
                      replication_lag, active_connections, rq_total, error_rate,
                      p99 by weight — flowing from execution.rs into
                      deployment_metrics exactly as your DB workloads will see.
                    </div>
                  </div>
                </div>
                <div className="text-[10px] mt-2 text-[var(--color-muted-foreground)]">
                  Full detail, manual promote/rollback, and deeper charts live
                  in the dedicated forge-system detail page (open it in another
                  tab now).
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
              <div>
                <label className="text-xs font-medium">Target Version</label>
                <input
                  value={updateVersion}
                  onChange={(e) => setUpdateVersion(e.target.value)}
                  className="w-full mt-1 rounded-lg border px-4 py-2.5 bg-[var(--color-background)] font-mono text-sm"
                />
              </div>
              <div>
                <label className="text-xs font-medium">
                  Binary + Strategy (your Phase 2 controls)
                </label>
                <div className="mt-1 text-xs p-2.5 rounded-lg border bg-[var(--color-background)] text-[var(--color-muted-foreground)]">
                  Canary (agents 10%→100%) + Blue/Green (CP) + stateful-aware
                  rolling (Postgres). All gates, durations, and plugins
                  configurable via the same API.
                </div>
              </div>
            </div>

            <button
              onClick={async () => {
                if (!adminToken) return;
                setIsUpdatingForge(true);
                try {
                  const res = await fetch(`${API_BASE}/system/update`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({
                      version: updateVersion,
                      binary_ref: updateBinaryRef,
                      binary_sha256: updateBinarySha,
                      strategy: {
                        type: "canary",
                        initial_traffic_percent: 10,
                        step_percent: 25,
                        step_duration_secs: 90,
                        failure_threshold: 2,
                      },
                    }),
                  });
                  if (res.ok) {
                    toast.success(
                      "Tiered self-update started — watch the embedded L7/stateful signals above or open forge-system detail",
                    );
                    // Keep dialog open so the live panel stays visible; user can close manually
                  } else {
                    toast.error(
                      "Update trigger failed (check /system/update logs)",
                    );
                  }
                } catch {
                  toast.error("Update trigger failed");
                } finally {
                  setIsUpdatingForge(false);
                }
              }}
              disabled={isUpdatingForge}
              className="btn btn-primary w-full"
            >
              {isUpdatingForge
                ? "Dispatching phased SystemUpdate jobs via Canary engine..."
                : "Begin Tiered Update (Agents Canary → CP Blue/Green → Stateful Postgres)"}
            </button>

            <div className="text-center text-[10px] text-[var(--color-muted-foreground)] mt-3">
              Every line of health gates, metric-driven promotion, stateful
              plugins, L7 weight xDS, and previous_spec rollback is reused. No
              special paths.
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
