"use client";

import React from "react";
import { usePathname } from "next/navigation";
import { Eye, EyeOff, KeyRound } from "lucide-react";
import { useAdminToken } from "../app/admin/token-store";

const TITLES: Record<string, string> = {
  "/admin/deployments": "Deployments",
  "/admin/applications": "Applications",
  "/admin/enrollment-tokens": "Enrollment Tokens",
  "/admin/metrics": "Metrics",
  "/admin/access": "Access",
  "/admin/update-forge": "Update Forge",
};

function titleFor(pathname: string): string {
  if (TITLES[pathname]) return TITLES[pathname]!;
  // Longest matching prefix wins (handles nested routes like /applications/[id]).
  let best = "";
  let bestTitle = "Admin";
  for (const [href, label] of Object.entries(TITLES)) {
    if (pathname.startsWith(href + "/") && href.length > best.length) {
      best = href;
      bestTitle = label;
    }
  }
  return bestTitle;
}

export function AdminTopBar() {
  const pathname = usePathname() ?? "";
  const [adminToken, setAdminToken] = useAdminToken();
  const [show, setShow] = React.useState(false);

  const title = titleFor(pathname);
  const isDetail =
    pathname.startsWith("/admin/applications/") &&
    pathname !== "/admin/applications";

  return (
    <header className="sticky top-0 z-40 flex h-14 items-center justify-between gap-4 border-b border-border bg-[oklch(0.145_0_0/0.85)] px-6 backdrop-blur">
      {/* Breadcrumb / page title */}
      <div className="flex min-w-0 items-center gap-2 text-sm">
        <span className="truncate font-semibold tracking-tight">{title}</span>
        {isDetail && (
          <>
            <span className="text-muted-foreground/50">/</span>
            <span className="truncate text-muted-foreground">Detail</span>
          </>
        )}
      </div>

      {/* Admin token control — set once, shared across all admin pages */}
      <div className="flex items-center gap-2">
        <div className="relative">
          <KeyRound className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type={show ? "text" : "password"}
            value={adminToken}
            onChange={(e) => setAdminToken(e.target.value.trim())}
            placeholder="Admin token"
            aria-label="Admin token"
            spellCheck={false}
            autoComplete="off"
            className="h-9 w-56 rounded-lg border border-input bg-[oklch(1_0_0/0.03)] pl-8 pr-9 font-mono text-xs text-foreground placeholder:text-muted-foreground/60 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-ring"
          />
          <button
            type="button"
            onClick={() => setShow((v) => !v)}
            aria-label={show ? "Hide admin token" : "Show admin token"}
            className="absolute right-1.5 top-1/2 grid h-6 w-6 -translate-y-1/2 place-items-center rounded text-muted-foreground transition-colors hover:bg-[oklch(1_0_0/0.06)] hover:text-foreground"
          >
            {show ? (
              <EyeOff className="h-3.5 w-3.5" />
            ) : (
              <Eye className="h-3.5 w-3.5" />
            )}
          </button>
        </div>
        <span
          className={`status-dot ${adminToken.length >= 12 ? "status-dot-healthy pulse-dot text-[var(--color-success)]" : "status-dot-pending"}`}
          title={adminToken.length >= 12 ? "Token set" : "No token set"}
        />
      </div>
    </header>
  );
}
