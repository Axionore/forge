"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Rocket,
  Boxes,
  KeyRound,
  Activity,
  ShieldCheck,
  RefreshCw,
  BookOpen,
  ExternalLink,
  PanelLeftClose,
  PanelLeft,
  type LucideIcon,
} from "lucide-react";

type NavItem = {
  href: string;
  label: string;
  icon: LucideIcon;
};

type NavGroup = {
  label: string;
  items: NavItem[];
};

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Deploy",
    items: [
      { href: "/admin/deployments", label: "Deployments", icon: Rocket },
      { href: "/admin/applications", label: "Applications", icon: Boxes },
    ],
  },
  {
    label: "Operate",
    items: [
      { href: "/admin/metrics", label: "Metrics", icon: Activity },
      {
        href: "/admin/update-forge",
        label: "Update Forge",
        icon: RefreshCw,
      },
    ],
  },
  {
    label: "Administer",
    items: [
      {
        href: "/admin/enrollment-tokens",
        label: "Enrollment Tokens",
        icon: KeyRound,
      },
      { href: "/admin/access", label: "Access", icon: ShieldCheck },
    ],
  },
];

const COLLAPSE_KEY = "forge_sidebar_collapsed";
const VERSION = "v0.1.0";

function isActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(href + "/");
}

/**
 * Collapsed flag backed by localStorage via an external store, so the initial
 * client value is read without a setState-in-effect (avoids cascading renders),
 * while SSR renders the expanded default and hydration stays consistent.
 */
let collapsedSnapshot = false;
let collapsedHydrated = false;
const collapseListeners = new Set<() => void>();

function readCollapsed(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

function subscribeCollapsed(listener: () => void): () => void {
  if (!collapsedHydrated && typeof window !== "undefined") {
    collapsedHydrated = true;
    collapsedSnapshot = readCollapsed();
  }
  collapseListeners.add(listener);
  return () => {
    collapseListeners.delete(listener);
  };
}

function setCollapsedStore(next: boolean): void {
  collapsedSnapshot = next;
  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
    } catch {
      // ignore
    }
  }
  for (const listener of collapseListeners) listener();
}

export function Sidebar() {
  const pathname = usePathname() ?? "";
  const collapsed = React.useSyncExternalStore(
    subscribeCollapsed,
    () => collapsedSnapshot,
    () => false,
  );

  const toggle = React.useCallback(() => {
    setCollapsedStore(!collapsedSnapshot);
  }, []);

  return (
    <aside
      data-collapsed={collapsed}
      className={`group/sidebar sticky top-0 flex h-screen shrink-0 flex-col border-r border-border bg-[oklch(0.165_0_0)] transition-[width] duration-200 ${
        collapsed ? "w-[4.25rem]" : "w-60"
      }`}
    >
      {/* Brand */}
      <div className="flex h-14 items-center gap-2.5 px-4">
        <Link
          href="/admin/deployments"
          className="flex min-w-0 items-center gap-2.5"
        >
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-[oklch(0.74_0.16_58)] shadow-[0_0_0_1px_oklch(1_0_0/0.08)]">
            <span className="h-2.5 w-2.5 rounded-[3px] bg-black/80" />
          </span>
          {!collapsed && (
            <span className="flex min-w-0 flex-col leading-none">
              <span className="truncate text-sm font-semibold tracking-tight">
                Forge
              </span>
              <span className="mt-0.5 truncate text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Control Plane
              </span>
            </span>
          )}
        </Link>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2.5 py-2">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4 last:mb-0">
            {!collapsed && (
              <div className="px-2.5 pb-1.5 pt-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/70">
                {group.label}
              </div>
            )}
            <ul className="flex flex-col gap-0.5">
              {group.items.map((item) => {
                const active = isActive(pathname, item.href);
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      title={collapsed ? item.label : undefined}
                      aria-current={active ? "page" : undefined}
                      className={`flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm transition-colors ${
                        collapsed ? "justify-center" : ""
                      } ${
                        active
                          ? "bg-[oklch(1_0_0/0.08)] font-medium text-foreground"
                          : "text-muted-foreground hover:bg-[oklch(1_0_0/0.04)] hover:text-foreground"
                      }`}
                    >
                      <Icon
                        className="h-4 w-4 shrink-0"
                        strokeWidth={active ? 2.25 : 2}
                      />
                      {!collapsed && (
                        <span className="truncate">{item.label}</span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-2.5 py-2.5">
        <ul className="flex flex-col gap-0.5">
          <li>
            <a
              href="https://github.com/forge"
              target="_blank"
              rel="noreferrer noopener"
              title={collapsed ? "GitHub" : undefined}
              className={`flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm text-muted-foreground transition-colors hover:bg-[oklch(1_0_0/0.04)] hover:text-foreground ${
                collapsed ? "justify-center" : ""
              }`}
            >
              <ExternalLink className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="truncate">GitHub</span>}
            </a>
          </li>
          <li>
            <a
              href="https://github.com/forge#readme"
              target="_blank"
              rel="noreferrer noopener"
              title={collapsed ? "Docs" : undefined}
              className={`flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm text-muted-foreground transition-colors hover:bg-[oklch(1_0_0/0.04)] hover:text-foreground ${
                collapsed ? "justify-center" : ""
              }`}
            >
              <BookOpen className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="truncate">Docs</span>}
            </a>
          </li>
        </ul>

        <div
          className={`mt-1.5 flex items-center ${
            collapsed ? "justify-center" : "justify-between px-2.5"
          }`}
        >
          {!collapsed && (
            <span className="text-[10px] font-medium tabular-nums text-muted-foreground/60">
              {VERSION}
            </span>
          )}
          <button
            type="button"
            onClick={toggle}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="grid h-7 w-7 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-[oklch(1_0_0/0.05)] hover:text-foreground"
          >
            {collapsed ? (
              <PanelLeft className="h-4 w-4" />
            ) : (
              <PanelLeftClose className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>
    </aside>
  );
}
