"use client";

import React from "react";
import {
  CheckCircle2,
  XCircle,
  FileText,
  Rocket,
  Activity,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

export interface JobResultRow {
  id: string;
  job_type: string;
  success: boolean;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  details: Record<string, unknown> | null;
  received_at: string;
}

interface StatusTimelineProps {
  results: JobResultRow[];
  max?: number;
}

function getEventIcon(jobType: string, success: boolean) {
  const cls = success ? "text-emerald-500" : "text-red-500";
  const lower = jobType.toLowerCase();
  if (lower.includes("deploy"))
    return <Rocket className={`w-3.5 h-3.5 ${cls}`} />;
  if (lower.includes("log"))
    return <FileText className={`w-3.5 h-3.5 ${cls}`} />;
  if (lower.includes("health"))
    return <Activity className={`w-3.5 h-3.5 ${cls}`} />;
  if (!success) return <XCircle className={`w-3.5 h-3.5 ${cls}`} />;
  return <CheckCircle2 className={`w-3.5 h-3.5 ${cls}`} />;
}

function summarize(result: JobResultRow): string {
  if (result.error)
    return result.error.length > 120
      ? result.error.slice(0, 117) + "…"
      : result.error;
  const d = result.details as Record<string, unknown> | null;
  if (d) {
    if (typeof d["containers_checked"] === "number")
      return `${d["containers_checked"]} containers checked`;
    if (typeof d["replicas"] === "number") return `replicas: ${d["replicas"]}`;
    if (typeof d["traffic_percent"] === "number")
      return `traffic: ${d["traffic_percent"]}%`;
    if (typeof d["phase"] === "string") return `phase: ${d["phase"]}`;
  }
  return result.success ? "completed successfully" : "completed with issues";
}

export function StatusTimeline({ results, max = 12 }: StatusTimelineProps) {
  const [expanded, setExpanded] = React.useState<Record<string, boolean>>({});

  if (!results || results.length === 0) {
    return (
      <div className="text-xs text-[var(--color-muted-foreground)] py-3 border border-dashed border-[var(--color-card-border)] rounded-2xl px-4">
        No execution events yet. Trigger a deploy or Stream Logs to see the real
        timeline from JobResults.
      </div>
    );
  }

  const sortedAsc = [...results]
    .sort(
      (a, b) =>
        new Date(a.received_at).getTime() - new Date(b.received_at).getTime(),
    )
    .slice(-max);

  const toggle = (id: string) =>
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="space-y-2.5">
      {sortedAsc.map((r, idx) => {
        const isLast = idx === sortedAsc.length - 1;
        const time = new Date(r.received_at).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
        const isExpanded = !!expanded[r.id];

        return (
          <div key={r.id} className="flex gap-3 group">
            {/* Time column */}
            <div className="w-[72px] shrink-0 pt-1 text-right">
              <div className="font-mono text-[10px] tabular-nums text-[var(--color-muted-foreground)]">
                {time}
              </div>
            </div>

            {/* Dot + connector */}
            <div className="relative flex flex-col items-center pt-1">
              <div
                className={`w-5 h-5 rounded-full flex items-center justify-center border ${r.success ? "bg-[var(--color-success)]/120/10 border-emerald-500/40" : "bg-[var(--color-destructive)]/100/10 border-red-500/40"}`}
              >
                {getEventIcon(r.job_type, r.success)}
              </div>
              {!isLast && (
                <div className="w-px flex-1 bg-[var(--color-card-border)] my-0.5 group-last:hidden" />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0 pb-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[10px] px-2 py-0.5 rounded-md bg-[var(--color-muted)]/70 border border-[var(--color-card-border)] text-[var(--color-foreground)]">
                  {r.job_type}
                </span>
                <span
                  className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${r.success ? "text-emerald-600 bg-[var(--color-success)]/120/10" : "text-[var(--color-destructive)] bg-[var(--color-destructive)]/100/10"}`}
                >
                  {r.success ? "SUCCESS" : "FAILED"}
                </span>
                <button
                  onClick={() => toggle(r.id)}
                  className="ml-auto text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)] opacity-60 group-hover:opacity-100 transition"
                  aria-label="Toggle details"
                >
                  {isExpanded ? (
                    <ChevronUp className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>

              <div className="text-xs text-[var(--color-foreground)] mt-0.5 leading-snug">
                {summarize(r)}
              </div>

              {isExpanded && (
                <div className="mt-2 rounded-xl border border-[var(--color-card-border)] bg-black/60 p-3 text-[10px] font-mono overflow-auto max-h-48">
                  <div className="text-[var(--color-muted-foreground)] mb-1">
                    raw details
                  </div>
                  <pre className="whitespace-pre-wrap break-all text-[var(--color-foreground)]/90">
                    {JSON.stringify(r.details ?? {}, null, 2)}
                  </pre>
                  {r.error && (
                    <div className="mt-2 text-red-400">error: {r.error}</div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}
      {results.length > max && (
        <div className="text-[10px] text-[var(--color-muted-foreground)] pl-[92px]">
          Showing last {max} of {results.length} events
        </div>
      )}
    </div>
  );
}
