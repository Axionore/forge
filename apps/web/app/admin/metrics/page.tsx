"use client";

import React from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Brush,
} from "recharts";
import ReactECharts from "echarts-for-react";
import { RefreshCw } from "lucide-react";
import { useAdminToken } from "../token-store";

const API_BASE = "http://localhost:3000";

export default function MetricsDashboard() {
  const [adminToken] = useAdminToken();
  const [metrics, setMetrics] = React.useState<any[]>([]);
  const [rolloutData, setRolloutData] = React.useState<any[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [selectedMetric, setSelectedMetric] = React.useState("cpu");

  const headers = React.useMemo(() => {
    const h = new Headers({ "Content-Type": "application/json" });
    if (adminToken) h.set("X-Admin-Token", adminToken);
    return h;
  }, [adminToken]);

  const loadMetrics = async () => {
    if (!adminToken) return;
    setIsLoading(true);
    try {
      const res = await fetch(
        `${API_BASE}/admin/applications/system/metrics?metric=${selectedMetric}&limit=50`,
        { headers },
      );
      const data = await res.json();
      setMetrics(
        data.map((d: any) => ({
          time: new Date(d.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          }),
          value: d.value,
          ...d.labels,
        })),
      );

      // Rollout progress (ECharts)
      const rolloutRes = await fetch(
        `${API_BASE}/admin/applications/system/metrics?metric=rollout_progress&limit=30`,
        { headers },
      );
      const rollout = await rolloutRes.json();
      setRolloutData(
        rollout.map((d: any, i: number) => ({
          name: new Date(d.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          }),
          value: Math.round(d.value * 100) || 40 + i * 2,
        })),
      );
    } catch (e) {
      // demo data
      setMetrics(
        Array.from({ length: 20 }, (_, i) => ({
          time: `${10 + Math.floor(i / 2)}:${(i % 2) * 30}`,
          value: 40 + Math.random() * 50,
        })),
      );
      setRolloutData(
        Array.from({ length: 12 }, (_, i) => ({
          name: `${i}:00`,
          value: 50 + i * 4,
        })),
      );
    } finally {
      setIsLoading(false);
    }
  };

  React.useEffect(() => {
    if (adminToken) loadMetrics();
  }, [adminToken, selectedMetric]);

  const echartsOption = {
    tooltip: { trigger: "axis" },
    xAxis: { type: "category", data: rolloutData.map((d) => d.name) },
    yAxis: { type: "value", min: 0, max: 100 },
    dataZoom: [
      { type: "inside", start: 0, end: 100 },
      { type: "slider", start: 0, end: 100 },
    ],
    series: [
      {
        data: rolloutData.map((d) => d.value),
        type: "line",
        smooth: true,
        areaStyle: {},
        color: "#3b82f6",
      },
    ],
  };

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <div className="flex items-end justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Persistent Metrics
          </h1>
          <p className="mt-1 text-sm text-[var(--color-muted-foreground)]">
            Time-series from heartbeats, HealthChecks, and rollout engine
          </p>
        </div>
        <button
          onClick={loadMetrics}
          disabled={isLoading}
          className="btn btn-ghost"
        >
          <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recharts line */}
        <div className="rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-6">
          <div className="flex justify-between items-center mb-4">
            <div className="font-medium">Metric: {selectedMetric}</div>
            <select
              value={selectedMetric}
              onChange={(e) => setSelectedMetric(e.target.value)}
              className="text-sm border rounded-xl px-3 py-1"
            >
              <option value="cpu">CPU %</option>
              <option value="memory">Memory %</option>
              <option value="rollout_progress">Rollout Progress</option>
            </select>
          </div>
          <div className="h-80">
            <ResponsiveContainer>
              <LineChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={false}
                />
                <Brush dataKey="time" height={30} stroke="#3b82f6" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ECharts area for rollout */}
        <div className="rounded-3xl border border-[var(--color-card-border)] bg-[var(--color-card)] p-6">
          <div className="font-medium mb-4">Rollout Progress (ECharts)</div>
          <ReactECharts option={echartsOption} style={{ height: 320 }} />
        </div>
      </div>

      <div className="mt-6 text-xs text-[var(--color-muted-foreground)]">
        Data is persisted in the <code>deployment_metrics</code> table and
        ingested on every heartbeat and strategy step. Query more via the
        time-series API.
      </div>
    </div>
  );
}
