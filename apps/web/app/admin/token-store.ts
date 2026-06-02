"use client";

import React from "react";

/**
 * Shared admin-token store for the /admin app shell.
 *
 * The token is set once (in the shell top bar) and read by every admin page.
 * It is persisted to localStorage so it survives client-side navigation
 * between admin routes within a session. Pages consume it through
 * `useAdminToken()`, which returns the same `[value, setValue]` shape they
 * previously used with `React.useState("")`, so their data-fetching logic is
 * unchanged.
 */

const STORAGE_KEY = "forge_admin_token";

let currentToken = "";
const listeners = new Set<() => void>();

function readInitial(): string {
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

let hydrated = false;

function ensureHydrated(): void {
  if (hydrated || typeof window === "undefined") return;
  hydrated = true;
  currentToken = readInitial();
}

export function setAdminToken(next: string): void {
  ensureHydrated();
  if (next === currentToken) return;
  currentToken = next;
  if (typeof window !== "undefined") {
    try {
      if (next) {
        window.localStorage.setItem(STORAGE_KEY, next);
      } else {
        window.localStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // localStorage may be unavailable (private mode); keep in-memory value.
    }
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  ensureHydrated();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function getSnapshot(): string {
  ensureHydrated();
  return currentToken;
}

function getServerSnapshot(): string {
  return "";
}

/**
 * React hook returning `[adminToken, setAdminToken]`.
 * Drop-in replacement for `React.useState("")` in admin pages.
 */
export function useAdminToken(): [string, (next: string) => void] {
  const token = React.useSyncExternalStore(
    subscribe,
    getSnapshot,
    getServerSnapshot,
  );
  return [token, setAdminToken];
}
