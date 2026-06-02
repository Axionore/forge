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
      className={`group/sidebar sticky top-0 flex h-screen shrink-0 flex-col border-r border-[oklch(1_0_0/0.07)] bg-[oklch(0.155_0_0)] transition-[width] duration-200 ${
        collapsed ? "w-[3.75rem]" : "w-56"
      }`}
    >
      {/* Brand */}
      <div
        className={`flex h-[3.25rem] items-center border-b border-[oklch(1_0_0/0.07)] ${collapsed ? "justify-center px-0" : "gap-2.5 px-4"}`}
      >
        <Link
          href="/admin/deployments"
          className="flex min-w-0 items-center gap-2.5"
        >
          {/* Neutral mark — no amber */}
          <span className="grid h-6 w-6 shrink-0 place-items-center rounded-[5px] bg-[oklch(0.97_0_0)] shadow-[0_0_0_1px_oklch(1_0_0/0.1)]">
            <svg
              width="14"
              height="14"
              viewBox="0 0 14 14"
              fill="none"
              aria-hidden
            >
              <rect x="2" y="2" width="4" height="4" rx="1" fill="#0a0a0a" />
              <rect
                x="8"
                y="2"
                width="4"
                height="4"
                rx="1"
                fill="#0a0a0a"
                opacity="0.5"
              />
              <rect
                x="2"
                y="8"
                width="4"
                height="4"
                rx="1"
                fill="#0a0a0a"
                opacity="0.5"
              />
              <rect
                x="8"
                y="8"
                width="4"
                height="4"
                rx="1"
                fill="#0a0a0a"
                opacity="0.25"
              />
            </svg>
          </span>
          {!collapsed && (
            <span className="flex min-w-0 flex-col leading-none">
              <span className="truncate text-[13px] font-semibold tracking-tight text-[oklch(0.97_0_0)]">
                Forge
              </span>
              <span className="mt-0.5 truncate text-[9px] font-medium uppercase tracking-[0.14em] text-[oklch(1_0_0/0.38)]">
                {VERSION}
              </span>
            </span>
          )}
        </Link>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4 last:mb-0">
            {!collapsed && (
              <div className="section-label mb-1.5 px-2.5">{group.label}</div>
            )}
            <ul className="flex flex-col gap-px">
              {group.items.map((item) => {
                const active = isActive(pathname, item.href);
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      title={collapsed ? item.label : undefined}
                      aria-current={active ? "page" : undefined}
                      className={`relative flex h-8 items-center rounded-md text-[13px] transition-colors ${
                        collapsed ? "justify-center px-0" : "gap-2.5 px-2.5"
                      } ${
                        active
                          ? "bg-[oklch(1_0_0/0.09)] font-medium text-[oklch(0.97_0_0)]"
                          : "font-normal text-[oklch(1_0_0/0.5)] hover:bg-[oklch(1_0_0/0.04)] hover:text-[oklch(1_0_0/0.78)]"
                      }`}
                    >
                      {active && (
                        <span
                          className="absolute inset-y-1 left-0 w-0.5 rounded-full bg-[oklch(0.97_0_0)]"
                          aria-hidden
                        />
                      )}
                      <Icon
                        className="h-[15px] w-[15px] shrink-0"
                        strokeWidth={active ? 2 : 1.75}
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
      <div className="border-t border-[oklch(1_0_0/0.07)] px-2 py-2">
        <ul className="flex flex-col gap-px">
          <li>
            <a
              href="https://github.com/forge"
              target="_blank"
              rel="noreferrer noopener"
              title={collapsed ? "GitHub" : undefined}
              className={`flex h-8 items-center rounded-md text-[13px] text-[oklch(1_0_0/0.38)] transition-colors hover:bg-[oklch(1_0_0/0.04)] hover:text-[oklch(1_0_0/0.65)] ${
                collapsed ? "justify-center px-0" : "gap-2.5 px-2.5"
              }`}
            >
              <ExternalLink className="h-[14px] w-[14px] shrink-0" />
              {!collapsed && <span className="truncate">GitHub</span>}
            </a>
          </li>
          <li>
            <a
              href="https://github.com/forge#readme"
              target="_blank"
              rel="noreferrer noopener"
              title={collapsed ? "Docs" : undefined}
              className={`flex h-8 items-center rounded-md text-[13px] text-[oklch(1_0_0/0.38)] transition-colors hover:bg-[oklch(1_0_0/0.04)] hover:text-[oklch(1_0_0/0.65)] ${
                collapsed ? "justify-center px-0" : "gap-2.5 px-2.5"
              }`}
            >
              <BookOpen className="h-[14px] w-[14px] shrink-0" />
              {!collapsed && <span className="truncate">Docs</span>}
            </a>
          </li>
        </ul>

        <div
          className={`mt-1 flex items-center ${
            collapsed ? "justify-center" : "justify-end px-1"
          }`}
        >
          <button
            type="button"
            onClick={toggle}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="grid h-6 w-6 place-items-center rounded text-[oklch(1_0_0/0.32)] transition-colors hover:bg-[oklch(1_0_0/0.05)] hover:text-[oklch(1_0_0/0.65)]"
          >
            {collapsed ? (
              <PanelLeft className="h-[13px] w-[13px]" />
            ) : (
              <PanelLeftClose className="h-[13px] w-[13px]" />
            )}
          </button>
        </div>
      </div>
    </aside>
  );
}
