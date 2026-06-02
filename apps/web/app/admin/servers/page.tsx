"use client";

import React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import * as Select from "@radix-ui/react-select";
import { toast } from "sonner";
import {
  Server,
  Plus,
  Trash2,
  ChevronDown,
  Check,
  X,
  RefreshCw,
  AlertTriangle,
  Globe,
  HardDrive,
  Shield,
} from "lucide-react";
import { useAdminToken } from "../token-store";

const API_BASE = "http://localhost:3000";

// ---- Types ------------------------------------------------------------------

interface ProviderCapabilities {
  provision_servers: boolean;
  manage_networks: boolean;
  manage_firewalls: boolean;
  manage_volumes: boolean;
  manage_load_balancers: boolean;
  manage_dns: boolean;
}

interface Provider {
  name: string;
  display_name: string;
  capabilities: ProviderCapabilities;
}

interface CatalogRegion {
  id: string;
  name: string;
  description?: string | null;
}

interface CatalogServerType {
  id: string;
  name: string;
  description?: string | null;
  cores?: number | null;
  memory_gb?: number | null;
  disk_gb?: number | null;
}

interface CatalogImage {
  id: string;
  name: string;
  description?: string | null;
  os_flavor?: string | null;
}

interface ProviderCatalog {
  regions: CatalogRegion[];
  server_types: CatalogServerType[];
  images: CatalogImage[];
}

interface ProvisionedResource {
  id: string;
  name: string;
  kind: string;
  region?: string | null;
  status?: string | null;
  created_at?: string | null;
  provider_id?: string | null;
  ip_address?: string | null;
}

type ConnectionStatus = "idle" | "loading" | "error";

// ---- Helpers ----------------------------------------------------------------

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function resourceStatusDot(status: string | null | undefined): string {
  switch ((status ?? "").toLowerCase()) {
    case "running":
    case "active":
      return "status-dot-healthy";
    case "initializing":
    case "starting":
      return "status-dot-progress";
    case "off":
    case "stopped":
      return "status-dot-pending";
    case "error":
    case "failed":
      return "status-dot-failed";
    default:
      return "status-dot-pending";
  }
}

// ---- Provider card ----------------------------------------------------------

function ProviderCard({
  provider,
  active,
  onClick,
}: {
  provider: Provider;
  active: boolean;
  onClick: () => void;
}) {
  const isHetzner = provider.name === "hetzner";
  const capable = provider.capabilities.provision_servers;

  return (
    <button
      type="button"
      disabled={!capable}
      onClick={capable ? onClick : undefined}
      aria-pressed={active}
      className={`relative flex flex-col rounded-lg border p-5 text-left transition-all duration-150 ${
        !capable
          ? "cursor-not-allowed border-[oklch(1_0_0/0.05)] bg-[oklch(0.16_0_0)] opacity-50"
          : active
            ? "border-[oklch(0.97_0_0)] bg-[oklch(0.22_0_0)]"
            : "border-[oklch(1_0_0/0.08)] bg-[oklch(0.185_0_0)] hover:border-[oklch(1_0_0/0.16)] hover:bg-[oklch(0.2_0_0)]"
      }`}
    >
      {active && (
        <span className="absolute right-3 top-3 flex h-5 w-5 items-center justify-center rounded-full bg-[oklch(0.97_0_0)]">
          <Check className="h-3 w-3 text-[oklch(0.14_0_0)]" />
        </span>
      )}
      {!capable && (
        <span className="absolute right-3 top-3 rounded-[4px] border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.04)] px-1.5 py-px text-[9px] font-semibold uppercase tracking-widest text-[oklch(1_0_0/0.35)]">
          Coming soon
        </span>
      )}

      {/* Provider icon / initials */}
      <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-md border border-[oklch(1_0_0/0.1)] bg-[oklch(1_0_0/0.05)]">
        {isHetzner ? (
          <svg
            viewBox="0 0 32 32"
            width="18"
            height="18"
            fill="none"
            aria-hidden="true"
          >
            <path d="M8 4h6v10h4V4h6v24h-6V18h-4v10H8z" fill="currentColor" />
          </svg>
        ) : (
          <Server className="h-4 w-4 text-[oklch(1_0_0/0.5)]" />
        )}
      </div>

      <div className="text-[13px] font-semibold tracking-tight text-[oklch(0.97_0_0)]">
        {provider.display_name}
      </div>
      <div className="mt-1 text-[11px] text-[oklch(1_0_0/0.38)]">
        {capable
          ? [
              provider.capabilities.manage_networks && "Networks",
              provider.capabilities.manage_firewalls && "Firewalls",
              provider.capabilities.manage_volumes && "Volumes",
            ]
              .filter(Boolean)
              .join(" · ") || "Compute"
          : "Not available yet"}
      </div>
    </button>
  );
}

// ---- Select item (Radix) ----------------------------------------------------

function SelectItem({
  value,
  children,
}: {
  value: string;
  children: React.ReactNode;
}) {
  return (
    <Select.Item
      value={value}
      className="flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-[13px] outline-none hover:bg-[oklch(1_0_0/0.07)] focus:bg-[oklch(1_0_0/0.07)]"
    >
      <Select.ItemText>{children}</Select.ItemText>
      <Select.ItemIndicator className="ml-auto">
        <Check className="h-3 w-3" />
      </Select.ItemIndicator>
    </Select.Item>
  );
}

// ---- Confirm delete dialog --------------------------------------------------

function DeleteConfirmDialog({
  open,
  resourceName,
  onConfirm,
  onCancel,
  deleting,
}: {
  open: boolean;
  resourceName: string;
  onConfirm: () => void;
  onCancel: () => void;
  deleting: boolean;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onCancel()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[200] bg-black/60 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-[201] w-full max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-6 shadow-2xl focus:outline-none">
          <div className="mb-4 flex items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[oklch(0.62_0.2_25/0.12)]">
              <AlertTriangle className="h-4 w-4 text-[var(--color-destructive)]" />
            </div>
            <div>
              <Dialog.Title className="text-[13px] font-semibold text-[oklch(0.97_0_0)]">
                Delete resource
              </Dialog.Title>
              <Dialog.Description className="mt-0.5 text-[12px] text-[oklch(1_0_0/0.45)]">
                This will permanently delete{" "}
                <strong className="font-medium text-[oklch(0.97_0_0)]">
                  {resourceName}
                </strong>
                . This action cannot be undone.
              </Dialog.Description>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="btn btn-ghost btn-sm"
              disabled={deleting}
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onConfirm}
              disabled={deleting}
              className="btn btn-danger btn-sm"
            >
              {deleting ? "Deleting…" : "Delete"}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ---- Page -------------------------------------------------------------------

export default function ServersPage() {
  const [adminToken] = useAdminToken();

  const headers = React.useMemo(() => {
    const h = new Headers();
    h.set("Content-Type", "application/json");
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  // Providers
  const [providers, setProviders] = React.useState<Provider[]>([]);
  const [providersStatus, setProvidersStatus] =
    React.useState<ConnectionStatus>("idle");
  const [selectedProvider, setSelectedProvider] = React.useState<string>("");

  // Catalog (for provision dialog)
  const [catalog, setCatalog] = React.useState<ProviderCatalog | null>(null);
  const [catalogStatus, setCatalogStatus] =
    React.useState<ConnectionStatus>("idle");

  // Provisioned resources
  const [resources, setResources] = React.useState<ProvisionedResource[]>([]);
  const [resourcesStatus, setResourcesStatus] =
    React.useState<ConnectionStatus>("idle");

  // Provision dialog
  const [showProvision, setShowProvision] = React.useState(false);
  const [provisionName, setProvisionName] = React.useState("");
  const [provisionServerType, setProvisionServerType] = React.useState("");
  const [provisionImage, setProvisionImage] = React.useState("");
  const [provisionLocation, setProvisionLocation] = React.useState("");
  const [isProvisioning, setIsProvisioning] = React.useState(false);

  // Delete confirm
  const [deleteTarget, setDeleteTarget] =
    React.useState<ProvisionedResource | null>(null);
  const [isDeleting, setIsDeleting] = React.useState(false);

  // ---- Fetch helpers --------------------------------------------------------

  const fetchProviders = React.useCallback(async () => {
    if (!adminToken) return;
    setProvidersStatus("loading");
    try {
      const res = await fetch(`${API_BASE}/admin/providers`, { headers });
      if (!res.ok) throw new Error(`${res.status}`);
      const data: Provider[] = await res.json();
      setProviders(data);
      // Auto-select Hetzner if present and capable
      const hetzner = data.find(
        (p) => p.name === "hetzner" && p.capabilities.provision_servers,
      );
      if (hetzner && !selectedProvider) {
        setSelectedProvider("hetzner");
      }
      setProvidersStatus("idle");
    } catch {
      setProvidersStatus("error");
    }
  }, [adminToken, headers, selectedProvider]);

  const fetchCatalog = React.useCallback(
    async (providerName: string) => {
      if (!adminToken || !providerName) return;
      setCatalogStatus("loading");
      try {
        const res = await fetch(
          `${API_BASE}/admin/providers/${providerName}/catalog`,
          { headers },
        );
        if (!res.ok) throw new Error(`${res.status}`);
        const data: ProviderCatalog = await res.json();
        setCatalog(data);
        // Pre-select first options
        if (data.regions[0]) setProvisionLocation(data.regions[0].id);
        if (data.server_types[0])
          setProvisionServerType(data.server_types[0].id);
        if (data.images[0]) setProvisionImage(data.images[0].id);
        setCatalogStatus("idle");
      } catch {
        setCatalogStatus("error");
      }
    },
    [adminToken, headers],
  );

  const fetchResources = React.useCallback(
    async (providerName: string) => {
      if (!adminToken || !providerName) return;
      setResourcesStatus("loading");
      try {
        const res = await fetch(
          `${API_BASE}/admin/providers/${providerName}/resources`,
          { headers },
        );
        if (!res.ok) throw new Error(`${res.status}`);
        const data: ProvisionedResource[] = await res.json();
        setResources(data);
        setResourcesStatus("idle");
      } catch {
        setResourcesStatus("error");
      }
    },
    [adminToken, headers],
  );

  // ---- Effects --------------------------------------------------------------

  React.useEffect(() => {
    if (adminToken) void fetchProviders();
  }, [adminToken, fetchProviders]);

  React.useEffect(() => {
    if (selectedProvider) {
      void fetchResources(selectedProvider);
    }
  }, [selectedProvider, fetchResources]);

  // ---- Actions --------------------------------------------------------------

  async function handleProvision(e: React.FormEvent) {
    e.preventDefault();
    if (!adminToken || !selectedProvider) return;

    setIsProvisioning(true);
    try {
      const body = {
        name: provisionName.trim(),
        server_type: provisionServerType,
        image: provisionImage,
        location: provisionLocation,
      };
      const res = await fetch(
        `${API_BASE}/admin/providers/${selectedProvider}/servers`,
        { method: "POST", headers, body: JSON.stringify(body) },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          (err as { detail?: string }).detail ?? `Error ${res.status}`,
        );
      }
      toast.success(`Server "${provisionName}" provisioning started`);
      setShowProvision(false);
      setProvisionName("");
      void fetchResources(selectedProvider);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Provisioning failed";
      toast.error(msg);
    } finally {
      setIsProvisioning(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget || !adminToken || !selectedProvider) return;
    setIsDeleting(true);
    try {
      const res = await fetch(
        `${API_BASE}/admin/providers/${selectedProvider}/resources/${deleteTarget.id}`,
        { method: "DELETE", headers },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          (err as { detail?: string }).detail ?? `Error ${res.status}`,
        );
      }
      toast.success(`"${deleteTarget.name}" deleted`);
      setDeleteTarget(null);
      void fetchResources(selectedProvider);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Delete failed";
      toast.error(msg);
    } finally {
      setIsDeleting(false);
    }
  }

  // ---- Current provider object ----------------------------------------------

  const currentProvider = providers.find((p) => p.name === selectedProvider);

  // ---- Render ---------------------------------------------------------------

  return (
    <div className="page-root">
      {/* Page header */}
      <div className="mb-6 flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">
            Infrastructure
          </h1>
          <p className="mt-0.5 text-[13px] text-[oklch(1_0_0/0.45)]">
            Provision and manage cloud servers across providers
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              void fetchProviders();
              if (selectedProvider) void fetchResources(selectedProvider);
            }}
            className="btn btn-ghost btn-sm"
            aria-label="Refresh"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${
                providersStatus === "loading" || resourcesStatus === "loading"
                  ? "animate-spin"
                  : ""
              }`}
            />
          </button>

          <button
            type="button"
            disabled={
              !selectedProvider ||
              !currentProvider?.capabilities.provision_servers
            }
            onClick={() => {
              void fetchCatalog(selectedProvider);
              setShowProvision(true);
            }}
            className="btn btn-primary btn-sm"
            aria-label="Provision a new server"
          >
            <Plus className="h-3.5 w-3.5" />
            Provision server
          </button>
        </div>
      </div>

      {/* No token state */}
      {!adminToken && (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-16 text-center">
          <Server className="mb-3 h-8 w-8 text-[oklch(1_0_0/0.2)]" />
          <div className="text-sm font-medium text-[oklch(1_0_0/0.5)]">
            Set an admin token to view infrastructure
          </div>
          <div className="mt-1 text-[12px] text-[oklch(1_0_0/0.3)]">
            Enter your token in the top bar
          </div>
        </div>
      )}

      {adminToken && (
        <>
          {/* Provider selection */}
          <section className="mb-6">
            <div className="section-label mb-3 px-0.5">Cloud Providers</div>

            {providersStatus === "loading" && providers.length === 0 ? (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[1, 2, 3, 4].map((i) => (
                  <div
                    key={i}
                    className="h-[100px] animate-pulse rounded-lg border border-[oklch(1_0_0/0.07)] bg-[oklch(0.185_0_0)]"
                  />
                ))}
              </div>
            ) : providersStatus === "error" && providers.length === 0 ? (
              // Backend down — show Hetzner as placeholder so layout is never blank
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  { name: "hetzner", display_name: "Hetzner Cloud" },
                  { name: "aws", display_name: "Amazon Web Services" },
                  { name: "gcp", display_name: "Google Cloud" },
                  { name: "azure", display_name: "Microsoft Azure" },
                ].map((p) => (
                  <ProviderCard
                    key={p.name}
                    provider={{
                      name: p.name,
                      display_name: p.display_name,
                      capabilities: {
                        provision_servers: p.name === "hetzner",
                        manage_networks: p.name === "hetzner",
                        manage_firewalls: p.name === "hetzner",
                        manage_volumes: false,
                        manage_load_balancers: false,
                        manage_dns: false,
                      },
                    }}
                    active={selectedProvider === p.name}
                    onClick={() => setSelectedProvider(p.name)}
                  />
                ))}
              </div>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {providers.map((p) => (
                  <ProviderCard
                    key={p.name}
                    provider={p}
                    active={selectedProvider === p.name}
                    onClick={() => setSelectedProvider(p.name)}
                  />
                ))}
                {/* If fewer than 4 providers, pad with coming-soon slots */}
                {providers.length < 4 &&
                  [
                    { name: "aws", display_name: "Amazon Web Services" },
                    { name: "gcp", display_name: "Google Cloud" },
                    { name: "azure", display_name: "Microsoft Azure" },
                    { name: "digitalocean", display_name: "DigitalOcean" },
                  ]
                    .filter(
                      (stub) => !providers.some((p) => p.name === stub.name),
                    )
                    .slice(0, 4 - providers.length)
                    .map((stub) => (
                      <ProviderCard
                        key={stub.name}
                        provider={{
                          name: stub.name,
                          display_name: stub.display_name,
                          capabilities: {
                            provision_servers: false,
                            manage_networks: false,
                            manage_firewalls: false,
                            manage_volumes: false,
                            manage_load_balancers: false,
                            manage_dns: false,
                          },
                        }}
                        active={false}
                        onClick={() => {}}
                      />
                    ))}
              </div>
            )}
          </section>

          {/* Resources table */}
          {selectedProvider && (
            <section>
              <div className="mb-3 flex items-center justify-between">
                <div className="section-label">
                  {currentProvider?.display_name ?? selectedProvider} Resources
                </div>
                <div className="flex items-center gap-1.5 text-[11px] text-[oklch(1_0_0/0.35)]">
                  {resourcesStatus === "loading" && (
                    <RefreshCw className="h-3 w-3 animate-spin" />
                  )}
                  {resources.length > 0 && (
                    <span className="tabular-nums">
                      {resources.length} total
                    </span>
                  )}
                </div>
              </div>

              {resourcesStatus === "loading" && resources.length === 0 ? (
                <div className="space-y-px">
                  {[1, 2, 3].map((i) => (
                    <div
                      key={i}
                      className="h-12 animate-pulse rounded-md border border-[oklch(1_0_0/0.06)] bg-[oklch(0.185_0_0)]"
                    />
                  ))}
                </div>
              ) : resourcesStatus === "error" ? (
                <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-12 text-center">
                  <AlertTriangle className="mb-2 h-6 w-6 text-[var(--color-destructive)]/60" />
                  <div className="text-[13px] text-[oklch(1_0_0/0.45)]">
                    Could not reach the API — backend may be down
                  </div>
                </div>
              ) : resources.length === 0 ? (
                <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[oklch(1_0_0/0.1)] py-16 text-center">
                  <Server className="mb-3 h-8 w-8 text-[oklch(1_0_0/0.2)]" />
                  <div className="text-[13px] font-medium text-[oklch(1_0_0/0.5)]">
                    No provisioned resources yet
                  </div>
                  <div className="mt-1 text-[12px] text-[oklch(1_0_0/0.3)]">
                    Provision your first server to get started
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      void fetchCatalog(selectedProvider);
                      setShowProvision(true);
                    }}
                    className="btn btn-primary btn-sm mt-5"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    Provision server
                  </button>
                </div>
              ) : (
                <div className="rounded-lg border border-[oklch(1_0_0/0.07)] bg-[oklch(0.185_0_0)]">
                  {/* Table header */}
                  <div className="grid grid-cols-[2rem_1fr_6rem_8rem_8rem_6rem_3rem] items-center gap-3 border-b border-[oklch(1_0_0/0.07)] px-4 py-2">
                    {[
                      "",
                      "Name",
                      "Kind",
                      "Region",
                      "Created",
                      "Status",
                      "",
                    ].map((col, i) => (
                      <div
                        key={i}
                        className="section-label truncate text-[oklch(1_0_0/0.35)]"
                      >
                        {col}
                      </div>
                    ))}
                  </div>

                  {/* Table rows */}
                  <ul className="divide-y divide-[oklch(1_0_0/0.05)]">
                    {resources.map((r, idx) => (
                      <li
                        key={r.id}
                        className="reveal grid grid-cols-[2rem_1fr_6rem_8rem_8rem_6rem_3rem] items-center gap-3 px-4 py-3"
                        style={{ animationDelay: `${idx * 25}ms` }}
                      >
                        {/* Status dot */}
                        <div className="flex justify-center">
                          <span
                            className={`status-dot ${resourceStatusDot(r.status)} ${
                              r.status === "running" || r.status === "active"
                                ? "pulse-dot text-[var(--color-success)]"
                                : ""
                            }`}
                          />
                        </div>

                        {/* Name + ID */}
                        <div className="min-w-0">
                          <div className="truncate text-[13px] font-medium text-[oklch(0.97_0_0)]">
                            {r.name}
                          </div>
                          {r.ip_address && (
                            <div className="mt-0.5 truncate font-mono text-[10px] text-[oklch(1_0_0/0.35)]">
                              {r.ip_address}
                            </div>
                          )}
                        </div>

                        {/* Kind chip */}
                        <div>
                          <span className="inline-flex items-center rounded-[4px] border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.04)] px-1.5 py-px text-[10px] font-medium uppercase tracking-wide text-[oklch(1_0_0/0.5)]">
                            {r.kind}
                          </span>
                        </div>

                        {/* Region */}
                        <div className="truncate text-[12px] text-[oklch(1_0_0/0.45)]">
                          {r.region ?? "—"}
                        </div>

                        {/* Created */}
                        <div className="truncate text-[12px] text-[oklch(1_0_0/0.38)] tabular-nums">
                          {relativeTime(r.created_at)}
                        </div>

                        {/* Status label */}
                        <div className="truncate text-[12px] capitalize text-[oklch(1_0_0/0.45)]">
                          {r.status ?? "—"}
                        </div>

                        {/* Delete */}
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={() => setDeleteTarget(r)}
                            aria-label={`Delete ${r.name}`}
                            className="grid h-7 w-7 place-items-center rounded text-[oklch(1_0_0/0.3)] transition-colors hover:bg-[oklch(0.62_0.2_25/0.12)] hover:text-[var(--color-destructive)]"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Capability chips */}
              {currentProvider && (
                <div className="mt-4 flex flex-wrap gap-2">
                  {[
                    {
                      key: "manage_networks" as const,
                      icon: Globe,
                      label: "Networks",
                    },
                    {
                      key: "manage_firewalls" as const,
                      icon: Shield,
                      label: "Firewalls",
                    },
                    {
                      key: "manage_volumes" as const,
                      icon: HardDrive,
                      label: "Volumes",
                    },
                  ].map(({ key, icon: Icon, label }) => (
                    <div
                      key={key}
                      className={`inline-flex items-center gap-1.5 rounded-[4px] border px-2.5 py-1 text-[11px] font-medium ${
                        currentProvider.capabilities[key]
                          ? "border-[oklch(0.72_0.17_150/0.25)] bg-[oklch(0.72_0.17_150/0.06)] text-[var(--color-success)]"
                          : "border-[oklch(1_0_0/0.07)] bg-[oklch(1_0_0/0.03)] text-[oklch(1_0_0/0.3)]"
                      }`}
                    >
                      <Icon className="h-3 w-3" />
                      {label}
                      {!currentProvider.capabilities[key] && (
                        <span className="opacity-60"> · soon</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
        </>
      )}

      {/* ---- Provision Dialog ---- */}
      <Dialog.Root
        open={showProvision}
        onOpenChange={(open) => {
          if (!open) setShowProvision(false);
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-xl -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[oklch(1_0_0/0.1)] bg-[oklch(0.185_0_0)] p-7 shadow-2xl focus:outline-none">
            <div className="mb-5 flex items-center justify-between">
              <Dialog.Title className="text-base font-semibold tracking-tight">
                Provision Server
                {currentProvider && (
                  <span className="ml-2 text-[12px] font-normal text-[oklch(1_0_0/0.4)]">
                    via {currentProvider.display_name}
                  </span>
                )}
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

            {catalogStatus === "loading" ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-5 w-5 animate-spin text-[oklch(1_0_0/0.3)]" />
                <span className="ml-2 text-[13px] text-[oklch(1_0_0/0.45)]">
                  Loading catalog…
                </span>
              </div>
            ) : catalogStatus === "error" ? (
              <div className="rounded-md border border-[oklch(1_0_0/0.08)] bg-[oklch(1_0_0/0.03)] p-4 text-center">
                <AlertTriangle className="mx-auto mb-2 h-5 w-5 text-[var(--color-destructive)]/70" />
                <p className="text-[13px] text-[oklch(1_0_0/0.45)]">
                  Could not load provider catalog — API may be down.
                </p>
                <p className="mt-1 text-[11px] text-[oklch(1_0_0/0.3)]">
                  You can still submit with manual values.
                </p>
              </div>
            ) : null}

            <form onSubmit={handleProvision} className="space-y-4">
              {/* Name */}
              <div>
                <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                  Server name
                </label>
                <input
                  value={provisionName}
                  onChange={(e) => setProvisionName(e.target.value)}
                  className="input"
                  placeholder="my-server-01"
                  required
                  autoFocus
                  aria-label="Server name"
                />
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                {/* Location */}
                <div>
                  <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                    Region
                  </label>
                  {catalog && catalog.regions.length > 0 ? (
                    <Select.Root
                      value={provisionLocation}
                      onValueChange={setProvisionLocation}
                    >
                      <Select.Trigger
                        className="select flex items-center justify-between"
                        aria-label="Select region"
                      >
                        <Select.Value placeholder="Region…" />
                        <Select.Icon>
                          <ChevronDown className="h-3.5 w-3.5 text-[oklch(1_0_0/0.4)]" />
                        </Select.Icon>
                      </Select.Trigger>
                      <Select.Portal>
                        <Select.Content className="z-[200] max-h-48 overflow-y-auto rounded-lg border border-[oklch(1_0_0/0.1)] bg-[oklch(0.2_0_0)] shadow-xl">
                          <Select.Viewport className="p-1">
                            {catalog.regions.map((r) => (
                              <SelectItem key={r.id} value={r.id}>
                                {r.name || r.id}
                              </SelectItem>
                            ))}
                          </Select.Viewport>
                        </Select.Content>
                      </Select.Portal>
                    </Select.Root>
                  ) : (
                    <input
                      value={provisionLocation}
                      onChange={(e) => setProvisionLocation(e.target.value)}
                      className="input"
                      placeholder="e.g. nbg1"
                      aria-label="Region"
                    />
                  )}
                </div>

                {/* Server type */}
                <div>
                  <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                    Server type
                  </label>
                  {catalog && catalog.server_types.length > 0 ? (
                    <Select.Root
                      value={provisionServerType}
                      onValueChange={setProvisionServerType}
                    >
                      <Select.Trigger
                        className="select flex items-center justify-between"
                        aria-label="Select server type"
                      >
                        <Select.Value placeholder="Type…" />
                        <Select.Icon>
                          <ChevronDown className="h-3.5 w-3.5 text-[oklch(1_0_0/0.4)]" />
                        </Select.Icon>
                      </Select.Trigger>
                      <Select.Portal>
                        <Select.Content className="z-[200] max-h-48 overflow-y-auto rounded-lg border border-[oklch(1_0_0/0.1)] bg-[oklch(0.2_0_0)] shadow-xl">
                          <Select.Viewport className="p-1">
                            {catalog.server_types.map((st) => (
                              <SelectItem key={st.id} value={st.id}>
                                {st.name}
                                {st.cores != null &&
                                  st.memory_gb != null &&
                                  ` (${st.cores}vCPU / ${st.memory_gb}GB)`}
                              </SelectItem>
                            ))}
                          </Select.Viewport>
                        </Select.Content>
                      </Select.Portal>
                    </Select.Root>
                  ) : (
                    <input
                      value={provisionServerType}
                      onChange={(e) => setProvisionServerType(e.target.value)}
                      className="input"
                      placeholder="e.g. cpx11"
                      aria-label="Server type"
                    />
                  )}
                </div>

                {/* Image */}
                <div>
                  <label className="mb-1.5 block text-[12px] font-medium text-[oklch(1_0_0/0.55)]">
                    Image
                  </label>
                  {catalog && catalog.images.length > 0 ? (
                    <Select.Root
                      value={provisionImage}
                      onValueChange={setProvisionImage}
                    >
                      <Select.Trigger
                        className="select flex items-center justify-between"
                        aria-label="Select image"
                      >
                        <Select.Value placeholder="Image…" />
                        <Select.Icon>
                          <ChevronDown className="h-3.5 w-3.5 text-[oklch(1_0_0/0.4)]" />
                        </Select.Icon>
                      </Select.Trigger>
                      <Select.Portal>
                        <Select.Content className="z-[200] max-h-48 overflow-y-auto rounded-lg border border-[oklch(1_0_0/0.1)] bg-[oklch(0.2_0_0)] shadow-xl">
                          <Select.Viewport className="p-1">
                            {catalog.images.map((img) => (
                              <SelectItem key={img.id} value={img.id}>
                                {img.name}
                              </SelectItem>
                            ))}
                          </Select.Viewport>
                        </Select.Content>
                      </Select.Portal>
                    </Select.Root>
                  ) : (
                    <input
                      value={provisionImage}
                      onChange={(e) => setProvisionImage(e.target.value)}
                      className="input"
                      placeholder="e.g. ubuntu-24.04"
                      aria-label="Image"
                    />
                  )}
                </div>
              </div>

              <div className="flex justify-end gap-2 border-t border-[oklch(1_0_0/0.07)] pt-4">
                <Dialog.Close asChild>
                  <button type="button" className="btn btn-ghost btn-sm">
                    Cancel
                  </button>
                </Dialog.Close>
                <button
                  type="submit"
                  disabled={
                    isProvisioning ||
                    !provisionName.trim() ||
                    !provisionServerType ||
                    !provisionImage ||
                    !provisionLocation
                  }
                  className="btn btn-primary btn-sm"
                >
                  {isProvisioning ? "Provisioning…" : "Provision"}
                </button>
              </div>
            </form>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Delete confirm */}
      <DeleteConfirmDialog
        open={!!deleteTarget}
        resourceName={deleteTarget?.name ?? ""}
        onConfirm={() => void handleDelete()}
        onCancel={() => setDeleteTarget(null)}
        deleting={isDeleting}
      />
    </div>
  );
}
