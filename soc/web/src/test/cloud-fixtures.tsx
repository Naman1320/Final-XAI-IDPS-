import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { ApiError } from "../api/client";
import CloudModule from "../pages/cloud";

export const MOCK = { data_source: "mock", data_source_label: "Mock data: no live cloud connected" };
export const NOTE = "applied to the persisted mock inventory only; nothing in any real cloud was changed";
export const ALL_PERMS = ["cloud.view", "cloud.instances.write", "cloud.storage.write", "cloud.network.write", "cloud.alerts.manage"];

const check = (name: string, value: number, d: number, c: number) => ({ name, status: value >= c ? "critical" : value >= d ? "degraded" : "healthy", value, threshold: { degraded: d, critical: c } });
const health = (cpu: number) => ({
  status: cpu >= 80 ? "degraded" : "healthy",
  checks: [{ name: "instance_state", status: "healthy", value: "running", threshold: null }, check("cpu_pct", cpu, 80, 95), check("memory_pct", 40, 85, 95), check("disk_pct", 30, 80, 90)],
});

export const mkInstance = (o: Record<string, unknown> = {}) => ({
  id: "i-aaaa1111", name: "web-1", instance_type: "t3.small", state: "running", az: "eu-west-1a", vpc_id: "vpc-1", subnet_id: "subnet-1",
  private_ip: "10.0.1.10", public_ip: "203.0.113.20", os: "Ubuntu 22.04", vcpus: 2, memory_gb: 2, disk_gb: 20, tags: { env: "demo" },
  security_group_ids: ["sg-1"], launched_at: "2026-11-01T10:00:00Z", updated_at: "2026-11-02T10:00:00Z", health: health(35), metrics_source: "mock", ...o,
});

export interface Db {
  instances: ReturnType<typeof mkInstance>[];
  volumes: Record<string, unknown>[];
  buckets: Record<string, unknown>[];
  groups: Record<string, unknown>[];
  alerts: Record<string, unknown>[];
  source: { data_source: string; data_source_label: string };
  /** Handlers that replace the default for "METHOD /path-prefix". */
  override: Record<string, (path: string, init: { method?: string; json?: any }) => unknown>;
}

export function freshDb(): Db {
  return {
    instances: [
      mkInstance(),
      mkInstance({ id: "i-bbbb2222", name: "db-1", state: "stopped", az: "eu-west-1b", instance_type: "m5.large", public_ip: null, health: { status: "unknown", checks: [{ name: "instance_state", status: "unknown", value: "stopped", threshold: null }] } }),
      mkInstance({ id: "i-cccc3333", name: "old-1", state: "terminated", public_ip: null }),
    ],
    volumes: [
      { id: "vol-1", name: "data-1", size_gb: 100, type: "gp3", state: "in-use", instance_id: "i-aaaa1111", encrypted: true },
      { id: "vol-2", name: "spare-1", size_gb: 50, type: "gp2", state: "available", instance_id: null, encrypted: false },
    ],
    buckets: [
      { name: "idps-demo-logs", region: "eu-west-1", versioning: true, encrypted: true, public_access_blocked: true, object_count: 12, size_gb: 1.5, created_at: "2026-10-01T00:00:00Z" },
      { name: "idps-demo-empty", region: "eu-west-1", versioning: false, encrypted: true, public_access_blocked: true, object_count: 0, size_gb: 0, created_at: "2026-10-02T00:00:00Z" },
    ],
    groups: [
      { id: "sg-1", name: "web", description: "web tier", vpc_id: "vpc-1", instances_using: 1, open_to_world_admin_ports: false,
        rules: [{ id: 1, direction: "in", protocol: "tcp", port_from: 443, port_to: 443, cidr: "0.0.0.0/0", description: "https" }, { id: 2, direction: "out", protocol: "all", port_from: 0, port_to: 65535, cidr: "0.0.0.0/0", description: "all out" }] },
    ],
    alerts: [
      { id: 1, severity: "critical", rule: "sg_admin_open", resource_type: "security_group", resource_id: "sg-1", message: "Security group web opens SSH to the world", status: "open", created_at: "2026-11-18T10:00:00Z", updated_at: "2026-11-18T10:00:00Z", updated_by: null },
      { id: 2, severity: "warning", rule: "cpu_high", resource_type: "instance", resource_id: "i-aaaa1111", message: "CPU utilisation is high on web-1", status: "acknowledged", created_at: "2026-11-17T10:00:00Z", updated_at: "2026-11-17T11:00:00Z", updated_by: "ann" },
    ],
    source: MOCK,
    override: {},
  };
}

const paged = <T,>(db: Db, all: T[], u: URL) => {
  const limit = Number(u.searchParams.get("limit") ?? 50), offset = Number(u.searchParams.get("offset") ?? 0);
  return { ...db.source, items: all.slice(offset, offset + limit), total: all.length, limit, offset };
};

const series = (n: number, v: number) => Array.from({ length: n }, (_, i) => (i === 0 ? null : v + (i % 5)));
const stamps = (n: number) => Array.from({ length: n }, (_, i) => new Date(Date.UTC(2026, 10, 19, 10, i)).toISOString());

/** A small in-memory /cloud backend. */
export function cloudApiFake(db: Db) {
  return async (path: string, init: { method?: string; json?: any } = {}): Promise<unknown> => {
    const method = init.method ?? "GET";
    for (const [key, fn] of Object.entries(db.override)) {
      const [m, prefix] = key.split(" ");
      if (m === method && path.startsWith(prefix)) return fn(path, init);
    }
    const u = new URL(path, "http://x");
    const p = u.pathname;
    const s = db.source;
    const get = (k: string) => u.searchParams.get(k);
    if (method === "GET") {
      if (p === "/cloud/overview") return {
        ...s, region: "eu-west-1", instances: { total: 2, by_state: { running: 1, stopped: 1, pending: 0, terminated: 1 }, by_type: { "t3.small": 1 } },
        totals: { vcpus_running: 2, memory_gb_running: 2, instance_disk_gb: 40, volumes: 2, volume_gb: 150, volumes_in_use: 1, buckets: 2, bucket_objects: 12, bucket_gb: 1.5, vpcs: 1, subnets: 2, security_groups: 1 },
        health: { healthy: 1, degraded: 0, critical: 0, unknown: 1 }, alerts: { open: 1, acknowledged: 1, critical_open: 1 },
        cost: { available: s.data_source === "mock", currency: "USD", month: "2026-11", month_to_date: 123.45, last_month_total: 400, last_month_same_period: 200, change_vs_same_period_pct: -38.3, forecast_month_total: 220.5, forecast_method: "linear" },
        metrics_source: "mock",
      };
      if (p === "/cloud/metrics/summary") return {
        ...s, fleet: { running_instances: 1, avg_cpu_pct: 35.2, max_cpu_pct: 35.2, avg_memory_pct: 40.1, avg_net_in_mbps: 1.5, avg_net_out_mbps: 0.5 },
        storage: { instance_disk_gb: 40, instance_disk_used_gb: 12, instance_disk_used_pct: 30, volumes_gb: 150, volumes_in_use_gb: 100, volumes_in_use_pct: 66.7, buckets_gb: 1.5 },
        busiest: [{ id: "i-aaaa1111", name: "web-1", cpu_pct: 35.2 }], cpu_trend_24h: { step_seconds: 900, timestamps: stamps(6), avg_cpu_pct: [10, 20, 30, 40, 35, 30] },
        metrics_source: "mock", metrics_label: "Mock metrics: generated deterministically",
      };
      if (p === "/cloud/instances") {
        let rows = db.instances.slice();
        if (get("q")) rows = rows.filter((i) => i.name.includes(get("q")!));
        if (get("state")) rows = rows.filter((i) => i.state === get("state"));
        if (get("az")) rows = rows.filter((i) => i.az === get("az"));
        if (get("type")) rows = rows.filter((i) => i.instance_type === get("type"));
        return paged(db, rows, u);
      }
      const im = /^\/cloud\/instances\/([^/]+)\/metrics$/.exec(p);
      if (im) return { ...s, instance_id: im[1], state: "running", range: get("range"), step_seconds: 60, timestamps: stamps(12), series: { cpu_pct: series(12, 20), memory_pct: series(12, 40), disk_pct: series(12, 30), net_in_mbps: series(12, 1), net_out_mbps: series(12, 0.5) }, current: {}, metrics_source: "mock", metrics_label: "Mock metrics: not measured" };
      const i1 = /^\/cloud\/instances\/([^/]+)$/.exec(p);
      if (i1) { const i = db.instances.find((x) => x.id === decodeURIComponent(i1[1])); if (!i) throw new ApiError(404, "instance not found"); return { ...s, ...i }; }
      if (p === "/cloud/volumes") return paged(db, db.volumes.filter((v) => (!get("state") || v.state === get("state")) && (!get("q") || String(v.name).includes(get("q")!))), u);
      if (p === "/cloud/buckets") return paged(db, db.buckets, u);
      if (p === "/cloud/network/vpcs") return paged(db, [{ id: "vpc-1", name: "main", cidr: "10.0.0.0/16", subnet_count: 2, instance_count: 2 }], u);
      if (p === "/cloud/network/subnets") return paged(db, [
        { id: "subnet-1", vpc_id: "vpc-1", name: "pub-a", cidr: "10.0.1.0/24", az: "eu-west-1a", public: true },
        { id: "subnet-2", vpc_id: "vpc-1", name: "priv-b", cidr: "10.0.2.0/24", az: "eu-west-1b", public: false }], u);
      if (p === "/cloud/network/security-groups") return paged(db, db.groups, u);
      if (p === "/cloud/alerts") return paged(db, db.alerts.filter((a) => (!get("status") || a.status === get("status")) && (!get("severity") || a.severity === get("severity"))), u);
      if (p === "/cloud/notifications") return { ...s, items: db.alerts.filter((a) => a.status !== "resolved"), total: 2, open: 1, acknowledged: 1 };
      if (p === "/cloud/activity") return paged(db, [
        { id: 1, at: "2026-11-19T09:00:00Z", actor: "demo-admin", action: "instance.stop", resource_type: "instance", resource_id: "i-bbbb2222", details: { data_source: "mock", from: "running" } },
        { id: 2, at: "2026-11-18T09:00:00Z", actor: "system", action: "alert.create", resource_type: "alert", resource_id: "1", details: {} }]
        .filter((a) => !get("actor") || a.actor === get("actor")), u);
      if (p === "/cloud/cost") {
        const days = Number(String(get("range") ?? "30d").slice(0, -1));
        return {
          ...s, range: get("range"), available: s.data_source === "mock", currency: "USD", first_day: "2026-11-01", last_day: "2026-11-19", total: days * 10,
          by_service: { compute: days * 6, storage: days * 2, network: days, other: days }, by_day: Array.from({ length: days }, (_, i) => ({ day: new Date(Date.UTC(2026, 7, 1 + i)).toISOString().slice(0, 10), total: 10, services: { compute: 6, storage: 2, network: 1, other: 1 } })),
          forecast: { month: "2026-11", month_to_date: 123.45, days_elapsed: 19, days_in_month: 30, projected_month_total: 220.5, method: "linear" },
          top_drivers: [{ instance_id: "i-aaaa1111", name: "web-1", instance_type: "t3.small", running_hours: 100, hourly_usd: 0.0208, estimated_usd: 2.08 }],
          by_instance_type: [{ instance_type: "t3.small", instances: 1, running_hours: 100, estimated_usd: 2.08 }], cost_note: "Mock cost: estimate, not a bill.",
        };
      }
    }
    // changes
    const out = { ...s, note: NOTE };
    const ia = /^\/cloud\/instances\/([^/]+)\/(start|stop|reboot)$/.exec(p);
    if (method === "POST" && ia) {
      const i = db.instances.find((x) => x.id === ia[1])!;
      const allowed = { start: ["stopped"], stop: ["running"], reboot: ["running"] }[ia[2] as "start"];
      if (!allowed.includes(i.state)) throw new ApiError(409, `cannot ${ia[2]} an instance that is ${i.state} (allowed from: ${allowed.join(", ")})`);
      i.state = (ia[2] === "start" ? "pending" : ia[2] === "stop" ? "stopped" : i.state) as typeof i.state;
      return { ...out, ...i };
    }
    if (method === "DELETE" && /^\/cloud\/instances\/[^/]+$/.test(p)) {
      const i = db.instances.find((x) => x.id === p.split("/")[3])!;
      if (i.state === "terminated") throw new ApiError(409, "cannot terminate an instance that is terminated (allowed from: running, stopped)");
      i.state = "terminated";
      return { ...out, ...i };
    }
    if (method === "POST" && p === "/cloud/instances") {
      const i = mkInstance({ id: "i-new00001", name: init.json.name, state: "pending", instance_type: init.json.instance_type });
      db.instances.push(i);
      return { ...out, ...i };
    }
    const al = /^\/cloud\/alerts\/(\d+)\/(acknowledge|resolve)$/.exec(p);
    if (method === "POST" && al) {
      const a = db.alerts.find((x) => x.id === Number(al[1]))!;
      if (al[2] === "acknowledge" && a.status !== "open") throw new ApiError(409, `cannot acknowledge an alert that is ${a.status}`);
      a.status = al[2] === "acknowledge" ? "acknowledged" : "resolved";
      return { ...s, ...a };
    }
    if (method === "POST" && p === "/cloud/alerts/evaluate") return { ...s, checked_at: "2026-11-19T10:00:00Z", findings: 3, created: [{}, {}], escalated: [], already_open: 1 };
    throw new Error(`unexpected ${method} ${path}`);
  };
}

export const calls = (api: { mock: { calls: unknown[][] } }, method: string, prefix = "") =>
  api.mock.calls.filter(([p, o]) => ((o as { method?: string } | undefined)?.method ?? "GET") === method && String(p).startsWith(prefix));

export function renderCloud(at = "/cloud"): ReturnType<typeof render> {
  const el: ReactElement = (
    <MemoryRouter initialEntries={[at]}>
      <Routes><Route path="/cloud/*" element={<CloudModule />} /></Routes>
    </MemoryRouter>
  );
  return render(el);
}
