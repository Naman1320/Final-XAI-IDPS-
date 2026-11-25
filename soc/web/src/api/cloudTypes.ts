// Shapes of the /cloud API (soc/api/cloud). Every inventory, metric, cost and alert response says
// where it came from in data_source / data_source_label; the dashboard shows that label.

export interface Sourced {
  data_source: string;
  data_source_label: string;
  note?: string | null;
}

export interface Paged<T> extends Sourced {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export type InstanceState = "running" | "stopped" | "pending" | "terminated";
export type HealthStatus = "healthy" | "degraded" | "critical" | "unknown";

export interface HealthCheck {
  name: string;
  status: string;
  value: number | string;
  threshold: { degraded: number; critical: number } | null;
}

export interface Health {
  status: HealthStatus;
  checks: HealthCheck[];
}

export interface Instance {
  id: string;
  name: string;
  instance_type: string;
  state: InstanceState;
  az: string;
  vpc_id: string;
  subnet_id: string;
  private_ip: string;
  public_ip: string | null;
  os: string;
  vcpus: number;
  memory_gb: number;
  disk_gb: number;
  tags: Record<string, string>;
  security_group_ids: string[];
  launched_at: string;
  updated_at: string;
  health: Health;
  metrics_source?: string;
}
export type InstanceOut = Sourced & Instance;

export interface InstanceCreate {
  name: string;
  instance_type: string;
  subnet_id: string;
  security_group_ids: string[];
  az?: string;
  os?: string;
  disk_gb?: number;
  tags?: Record<string, string>;
}

export type MetricRange = "1h" | "24h" | "7d";
export const SERIES_KEYS = ["cpu_pct", "memory_pct", "disk_pct", "net_in_mbps", "net_out_mbps"] as const;
export type SeriesKey = (typeof SERIES_KEYS)[number];

export interface InstanceMetrics extends Sourced {
  instance_id: string;
  state: string;
  range: MetricRange;
  step_seconds: number;
  timestamps: string[];
  series: Record<SeriesKey, (number | null)[]>;
  current: Record<string, number>;
  metrics_source: string;
  metrics_label: string;
}

export interface Volume {
  id: string;
  name: string;
  size_gb: number;
  type: string;
  state: "available" | "in-use";
  instance_id: string | null;
  encrypted: boolean;
}
export type VolumeOut = Sourced & Volume;

export interface Bucket {
  name: string;
  region: string;
  versioning: boolean;
  encrypted: boolean;
  public_access_blocked: boolean;
  object_count: number;
  size_gb: number;
  created_at: string;
}
export type BucketOut = Sourced & Bucket;

export interface Vpc { id: string; name: string; cidr: string; subnet_count: number; instance_count: number }
export interface Subnet { id: string; vpc_id: string; name: string; cidr: string; az: string; public: boolean }
export interface SgRule {
  id: number;
  direction: "in" | "out" | string;
  protocol: string;
  port_from: number;
  port_to: number;
  cidr: string;
  description: string;
}
export interface SecurityGroup {
  id: string;
  name: string;
  description: string;
  vpc_id: string;
  rules: SgRule[];
  instances_using: number;
  open_to_world_admin_ports: boolean;
}
export type SecurityGroupOut = Sourced & SecurityGroup;

export interface RuleCreate {
  direction: "in" | "out";
  protocol: "tcp" | "udp" | "icmp" | "all";
  port_from?: number;
  port_to?: number;
  cidr: string;
  description?: string;
  confirm_open_to_world?: boolean;
}

export interface CloudOverview extends Sourced {
  region: string;
  instances: { total: number; by_state: Record<string, number>; by_type: Record<string, number> };
  totals: Record<string, number>;
  health: Record<string, number>;
  alerts: { open: number; acknowledged: number; critical_open: number };
  cost: {
    available: boolean;
    currency: string;
    month: string;
    month_to_date: number;
    last_month_total: number;
    last_month_same_period: number;
    change_vs_same_period_pct: number | null;
    forecast_month_total: number;
    forecast_method: string;
  };
  metrics_source: string;
}

export interface FleetMetrics extends Sourced {
  fleet: {
    running_instances: number;
    avg_cpu_pct: number;
    max_cpu_pct: number;
    avg_memory_pct: number;
    avg_net_in_mbps: number;
    avg_net_out_mbps: number;
  };
  storage: {
    instance_disk_gb: number;
    instance_disk_used_gb: number;
    instance_disk_used_pct: number;
    volumes_gb: number;
    volumes_in_use_gb: number;
    volumes_in_use_pct: number;
    buckets_gb: number;
  };
  busiest: { id: string; name: string; cpu_pct: number }[];
  cpu_trend_24h: { step_seconds: number; timestamps: string[]; avg_cpu_pct: number[] };
  metrics_source: string;
  metrics_label: string;
}

export type CostRange = "7d" | "30d" | "90d";
export interface CostOut extends Sourced {
  range: CostRange;
  available: boolean;
  currency: string;
  first_day: string;
  last_day: string;
  total: number;
  by_service: Record<string, number>;
  by_day: { day: string; total: number; services: Record<string, number> }[];
  forecast: {
    month: string;
    month_to_date: number;
    days_elapsed: number;
    days_in_month: number;
    projected_month_total: number;
    method: string;
  };
  top_drivers: {
    instance_id: string;
    name: string;
    instance_type: string;
    running_hours: number;
    hourly_usd: number;
    estimated_usd: number;
  }[];
  by_instance_type: { instance_type: string; instances: number; running_hours: number; estimated_usd: number }[];
  cost_note: string;
}

export type AlertSeverity = "info" | "warning" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";
export interface CloudAlert {
  id: number;
  severity: AlertSeverity | string;
  rule: string;
  resource_type: string;
  resource_id: string;
  message: string;
  status: AlertStatus | string;
  created_at: string;
  updated_at: string;
  updated_by: string | null;
}
export type CloudAlertOut = Sourced & CloudAlert;
export interface Notifications extends Sourced {
  items: CloudAlert[];
  total: number;
  open: number;
  acknowledged: number;
}
export interface EvaluateResult extends Sourced {
  checked_at: string;
  findings: number;
  created: CloudAlert[];
  escalated: CloudAlert[];
  already_open: number;
}

export interface Activity {
  id: number;
  at: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
}
