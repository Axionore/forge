"use client";

import React from "react";
import { usePathname } from "next/navigation";
import { Eye, EyeOff, KeyRound, ChevronRight } from "lucide-react";
import { useAdminToken } from "../app/admin/token-store";

const ROUTE_LABELS: Record<string, string> = {
  "/admin/deployments": "Deployments",
  "/admin/applications": "Applications",
  "/admin/enrollment-tokens": "Enrollment Tokens",
  "/admin/metrics": "Metrics",
  "/admin/access": "Access",
  "/admin/update-forge": "Update Forge",
};

/** Returns [{ label, href }] breadcrumb segments for the current path. */
function buildCrumbs(pathname: string): { label: string; href?: string }[] {
  // Exact match
  if (ROUTE_LABELS[pathname]) {
    return [{ label: "Forge" }, { label: ROUTE_LABELS[pathname]! }];
  }

  // /admin/applications/[id]
  if (
    pathname.startsWith("/admin/applications/") &&
    pathname !== "/admin/applications"
  ) {
    return [
      { label: "Forge" },
      { label: "Applications", href: "/admin/applications" },
      { label: "Detail" },
    ];
  }

  return [{ label: "Forge" }, { label: "Admin" }];
}

export function AdminTopBar() {
  const pathname = usePathname() ?? "";
  const [adminToken, setAdminToken] = useAdminToken();
  const [show, setShow] = React.useState(false);

  const crumbs = buildCrumbs(pathname);

  return (
    <header className="sticky top-0 z-40 flex h-[3.25rem] items-center justify-between gap-4 border-b border-[oklch(1_0_0/0.07)] bg-[oklch(0.145_0_0/0.92)] px-5 backdrop-blur-sm">
      {/* Breadcrumb */}
      <nav
        className="flex min-w-0 items-center gap-1 text-sm"
        aria-label="Breadcrumb"
      >
        {crumbs.map((crumb, i) => {
          const isLast = i === crumbs.length - 1;
          return (
            <React.Fragment key={i}>
              {i > 0 && (
                <ChevronRight
                  className="h-3.5 w-3.5 shrink-0 text-[oklch(1_0_0/0.22)]"
                  strokeWidth={1.75}
                />
              )}
              {crumb.href ? (
                <a
                  href={crumb.href}
                  className="truncate text-[oklch(1_0_0/0.45)] transition-colors hover:text-[oklch(1_0_0/0.75)]"
                >
                  {crumb.label}
                </a>
              ) : isLast ? (
                <span className="truncate font-medium text-[oklch(0.97_0_0)]">
                  {crumb.label}
                </span>
              ) : (
                <span className="truncate text-[oklch(1_0_0/0.4)]">
                  {crumb.label}
                </span>
              )}
            </React.Fragment>
          );
        })}
      </nav>

      {/* Admin token control */}
      <div className="flex shrink-0 items-center gap-2">
        <div className="relative">
          <KeyRound className="pointer-events-none absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-[oklch(1_0_0/0.3)]" />
          <input
            type={show ? "text" : "password"}
            value={adminToken}
            onChange={(e) => setAdminToken(e.target.value.trim())}
            placeholder="Admin token"
            aria-label="Admin token"
            spellCheck={false}
            autoComplete="off"
            className="h-8 w-52 rounded-md border border-[oklch(1_0_0/0.1)] bg-[oklch(1_0_0/0.03)] pl-7 pr-8 font-mono text-[11px] text-[oklch(0.97_0_0)] placeholder:text-[oklch(1_0_0/0.28)] focus:border-transparent focus:outline-none focus:ring-2 focus:ring-[oklch(1_0_0/0.25)]"
          />
          <button
            type="button"
            onClick={() => setShow((v) => !v)}
            aria-label={show ? "Hide admin token" : "Show admin token"}
            className="absolute right-1.5 top-1/2 grid h-5 w-5 -translate-y-1/2 place-items-center rounded text-[oklch(1_0_0/0.3)] transition-colors hover:text-[oklch(1_0_0/0.65)]"
          >
            {show ? (
              <EyeOff className="h-3 w-3" />
            ) : (
              <Eye className="h-3 w-3" />
            )}
          </button>
        </div>
        <span
          className={`status-dot ${
            adminToken.length >= 12
              ? "status-dot-healthy pulse-dot text-[var(--color-success)]"
              : "status-dot-pending"
          }`}
          title={adminToken.length >= 12 ? "Token set" : "No token set"}
        />
      </div>
    </header>
  );
}
