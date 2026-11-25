// Shapes returned by the SOC API (see soc/api/routes/*.py and docs/soc.md).

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "acknowledged" | "confirmed" | "false_positive" | "resolved";
export type ActionKind = "block_ip" | "unblock_ip";
export type ActionStatus = "pending" | "confirmed" | "rejected" | "executed" | "failed";
export type CaseStatus = "open" | "investigating" | "closed";
export type Role = "analyst" | "admin";
/** Who raised an alert: the model, or a Suricata rule running next to it on the sensor. */
export type AlertSource = "ml" | "rule";

export const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
export const ALERT_STATUSES: AlertStatus[] = ["new", "acknowledged", "confirmed", "false_positive", "resolved"];
/** Classes an analyst can name as an alert's real class (idps/features/labels.py CIC_CLASSES). */
export const ATTACK_CLASSES = [
  "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
  "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
  "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS",
] as const;
export const CASE_STATUSES: CaseStatus[] = ["open", "investigating", "closed"];

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface Alert {
  id: number;
  sensor_id: number;
  received_at: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  start_ms: number;
  end_ms: number;
  predicted_class: string;
  confidence: number;
  anomaly_score: number | null;
  severity: Severity;
  status: AlertStatus;
  case_id: number | null;
  /** Missing from older SOCs: treat as "ml". */
  source?: AlertSource;
  /** The Suricata rule that fired; null for model alerts. */
  rule?: RuleInfo | null;
}

export interface RuleInfo {
  sid: number;
  rev: number | null;
  signature: string;
  category: string | null;
  /** Suricata's severity: 1 is the most severe. */
  severity: number;
  /** Matches folded into this alert (same rule, source, target and port within the window). */
  count: number;
}

export interface FeatureContribution {
  feature: string;
  value: number | null;
  contribution: number | null;
}

export interface Explanation {
  method?: string;
  predicted_class?: string;
  confidence?: number;
  base_value?: number | null;
  output_space?: string;
  top_features?: FeatureContribution[];
}

export interface AlertDetail extends Alert {
  explanation: Explanation;
  /** Model that scored the flow; null from older sensors. */
  model_sha256?: string | null;
  model_version?: string | null;
  /** Analyst's correction of the class (confirmed alerts only). */
  true_class?: string | null;
  /** The sensor sent the flow's feature values, so the alert can become a training row. */
  has_features?: boolean;
}

export interface Block {
  id: number;
  sensor_id: number;
  ip: string;
  reason: string;
  source: "auto" | "analyst";
  alert_id: number | null;
  blocked_at: string;
  expires_at: string | null;
  unblocked_at: string | null;
  active: boolean;
}

export interface Action {
  id: number;
  kind: ActionKind;
  params: Record<string, unknown>;
  reason: string;
  proposed_by: string;
  proposed_by_user_id: number | null;
  sensor_id: number;
  status: ActionStatus;
  created_at: string;
  decided_by_id: number | null;
  decided_at: string | null;
  result: Record<string, unknown> | null;
  completed_at: string | null;
}

export interface CaseSummary {
  id: number;
  title: string;
  status: CaseStatus;
  created_by_id: number | null;
  created_at: string;
  updated_at: string;
  alert_count: number;
}

export interface Note {
  id: number;
  case_id: number;
  author_id: number | null;
  author: string | null;
  text: string;
  created_at: string;
}

export interface CaseDetail extends CaseSummary {
  notes: Note[];
  alerts: Alert[];
}

export interface MetricsSummary {
  hours: number;
  since: string;
  bucket_seconds: number;
  alerts_total: number;
  alerts_per_bucket: { start: string; count: number }[];
  by_class: Record<string, number>;
  by_severity: Record<string, number>;
  /** Missing from older SOCs. */
  by_source?: Record<AlertSource, number>;
  top_sources: { ip: string; count: number }[];
  triaged: number;
  false_positives: number;
  false_positive_rate: number | null;
  detection_latency: { p50_ms: number | null; p95_ms: number | null; samples: number };
  active_blocks: number;
  /** Dry-run block decisions in the window. */
  would_blocks?: number;
  /** Last 7 UTC days, oldest first, non-zero pairs only. Outliers are in `anomaly_per_day`. */
  by_class_per_day?: { day: string; class: string; count: number }[];
  /** Isolation Forest outliers per day, last 7 UTC days, non-zero only. */
  anomaly_per_day?: { day: string; count: number }[];
}

export interface AdminUser {
  id: number;
  username: string;
  role: Role;
  disabled: boolean;
  created_at: string;
  /** Missing from older SOCs. */
  mfa_enabled?: boolean;
  /** Signed in with single sign-on at least once (linked to a provider account). */
  sso_linked?: boolean;
}

export interface Sensor {
  id: number;
  name: string;
  revoked: boolean;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor_type: string;
  actor_name: string;
  action: string;
  target: string;
  details: Record<string, unknown>;
}

// --- Phase 3: sensor status, would-block events, class by day ---------------------------

export interface SensorPolicy {
  confidence_threshold: number;
  min_flows: number;
  window_seconds: number;
  min_alert_confidence: number;
  block_ttl_seconds: number;
  unblock_grace_seconds: number;
  max_analyst_blocks: number;
}

export interface SensorReport {
  dry_run: boolean;
  blocking_enabled: boolean;
  interface: string | null;
  mode: "live" | "replay";
  /** sha256 and version are missing or null from older sensors. */
  model: { name: string; checksum_ok: boolean; sha256?: string | null; version?: string | null;
    /** Key id of the verified model signature; missing when the sensor does not check them. */
    signed_by?: string | null };
  /** Suricata next to the model; missing or null from sensors that don't send it. */
  rules?: RulesStatus | null;
  /** Live traffic against the model's training data; missing or null from older sensors. */
  drift?: Drift | null;
  /** null for analysts: only admins see the policy and allowlists. */
  policy: SensorPolicy | null;
  allowlist: string[] | null;
  /** Full allowlist size; the list itself is capped at 100. Missing from older sensors. */
  allowlist_total?: number;
  outbox_pending: number;
  /** The model's explanation-faithfulness test (offline deletion test); missing from older sensors. */
  faithfulness?: Faithfulness | null;
  shap_p95_ms: number | null;
  heartbeat: { enabled: boolean; ok: boolean };
  counters: { flows: number; alerts: number; blocked: number; would_block: number };
  sensor_version: string | null;
  sent_at: string | null;
}

export interface RulesStatus {
  enabled: boolean;
  eve_path: string | null;
  alerts_sent: number;
  dropped_engine: number;
  dropped_info: number;
  deduped: number;
  dropped_invalid: number;
  last_event_at: string | null;
  error: string | null;
  include_info: boolean;
  dedupe_seconds: number;
  /** How many rules may block on their own. */
  block_sids: number;
  /** Rule alerts over the per-minute limit (not queued); missing from older sensors. */
  rate_limited?: number;
  /** Hits of rules allowed to block that were kept from the response engine. */
  block_skipped?: number;
  max_per_minute?: number;
}

export type IntegrationChannel = "webhook" | "slack" | "email" | "syslog";

/** GET /admin/integrations: secrets are never sent, only a hint of the target. */
export interface IntegrationStatus {
  channel: IntegrationChannel;
  configured: boolean;
  enabled: boolean;
  min_severity: Severity;
  include_rules: boolean;
  target_hint: string | null;
  last_success_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  queued: number;
  sent: number;
  failed: number;
  dropped: number;
  rate_limited: number;
  deduped: number;
}

export interface IntegrationsResponse {
  channels: IntegrationStatus[];
  abuseipdb: { configured: boolean; cache_hours: number };
}

export interface IntegrationTestResult {
  channel: IntegrationChannel;
  ok: boolean;
  error: string | null;
  duration_ms: number;
  tested_at: string;
}

/** GET /alerts/{id}/reputation (AbuseIPDB, looked up only on request). */
export interface Reputation {
  ip: string;
  available: boolean;
  reason: string | null;
  abuse_confidence: number | null;
  total_reports: number | null;
  country: string | null;
  isp: string | null;
  usage_type: string | null;
  last_reported_at: string | null;
  checked_at: string | null;
  cached: boolean;
}

export type DriftLevel = "ok" | "watch" | "drift" | "unknown";

export interface Drift {
  level: DriftLevel;
  /** Flows in the rolling window. */
  window: number | null;
  /** Largest population stability index over the features; null while warming up or without a reference. */
  psi_max: number | null;
  top: { feature: string; psi: number }[];
  reference_sha256: string | null;
  /** Set when level is "unknown". */
  reason: string | null;
}

export interface ModelVersion {
  sha256: string;
  version: string | null;
  name: string;
  first_seen: string;
  last_seen: string;
  running_now: number;
  sensors: { sensor_id: number; name: string; first_seen: string; last_seen: string; running_now: boolean; online: boolean }[];
}

export interface FaithfulnessMethod {
  mean_drop: number;
  /** null when removing random features changed nothing; negative when worse than random. */
  ratio_to_random: number | null;
  label_flip_rate: number;
  share_flows_beating_random: number;
}

export interface Faithfulness {
  model: string;
  model_matches: boolean;
  /** "digest": compared by model file checksum; "name": only the algorithm name (older reports). */
  model_check?: "digest" | "name" | null;
  flows: number;
  top_k: number;
  random_mean_drop: number;
  methods: { shap?: FaithfulnessMethod; lime?: FaithfulnessMethod };
}

export interface SensorState {
  sensor_id: number;
  name: string;
  revoked: boolean;
  last_seen_at: string | null;
  online: boolean;
  status: SensorReport | null;
}

export interface SensorsStatus {
  /** null for analysts (redacted). */
  soc_allowlist: string[] | null;
  redacted?: boolean;
  sensors: SensorState[];
}

export interface WouldBlock {
  id: number;
  sensor_id: number;
  ip: string;
  reason: string;
  source: "auto" | "analyst";
  alert_id: number | null;
  at: string;
  ttl_seconds: number | null;
}

// --- Live map: extra fields and messages on /ws/alerts ------------------------------------

export interface GeoLocation {
  lat: number;
  lon: number;
  country: string | null;
  city: string | null;
  /** "demo": a made-up location for a private (lab) address, never a real one. */
  source: "geoip" | "demo";
}

/** An alert as the live feed sends it: the stored alert plus its source's map location. */
export interface LiveAlert extends Alert {
  src_geo?: GeoLocation | null;
}

export interface LiveBlockEvent {
  type: "block";
  event: "blocked" | "unblocked" | "would_block";
  sensor_id: number;
  ip: string;
  source: "auto" | "analyst";
  at: string;
  expires_at: string | null;
  ttl_seconds: number | null;
  reason: string;
  geo: GeoLocation | null;
}

// GET /admin/retention (admin only): the data retention policy (0 = keep forever) and the last run.
export interface RetentionPolicy {
  alert_retention_days: number;
  alert_retention_keep_labelled: boolean;
  audit_retention_days: number;
  assistant_retention_days: number;
  closed_case_retention_days: number;
  would_block_retention_days: number;
}

export interface RetentionRun {
  at: string;
  // rows deleted per table (alerts, case_notes, cases, audit_log, assistant_conversations, would_blocks)
  counts: Record<string, number>;
  error: string | null;
  duration_seconds: number | null;
}

export interface RetentionStatus {
  policy: RetentionPolicy;
  last_run: RetentionRun | null;
}

// --- Step 13: weekly report and privacy (soc/api/reports.py, soc/api/privacy.py) -------------

export interface ReportWeek {
  /** ISO week, e.g. "2026-W46". */
  week: string;
  start: string;
  end: string;
  alerts: number;
  /** An email was attempted for this week. */
  run: boolean;
  emailed: boolean;
  emailed_at: string | null;
  recipients_count: number;
  error: string | null;
}

export interface ReportWeeks {
  default_week: string;
  email_enabled: boolean;
  email_configured: boolean;
  weeks: ReportWeek[];
}

export interface ReportEmailResult {
  week: string;
  /** How many recipients (never the addresses). */
  recipients: number;
  emailed_at: string;
  size_bytes: number;
}

export interface ErasePreview {
  ip: string;
  subject_fp: string;
  /** Rows or fields per table, every key always present. */
  counts: Record<string, number>;
  total: number;
  /** Found but not rewritten (account and sensor names): an admin changes them by hand. */
  manual_review: Record<string, number>;
  warnings: string[];
  /** Active blocks of the address: erasing needs `force` then (the sensor's rule stays). */
  active_blocks: number;
}

export interface EraseResult extends ErasePreview {
  record_id: number;
  erased_at: string;
}

export interface ErasureRecord {
  id: number;
  at: string;
  requested_by: string;
  reason: string;
  subject_fp: string;
  counts: Record<string, number>;
}

export interface AccessEntry {
  id: number;
  at: string;
  user_id: number | null;
  username: string;
  action: string;
  target_type: string | null;
  target: string | null;
  /** Fingerprint of the address read (never the address); null when none was involved. */
  subject_fp: string | null;
}

export interface PrivacyNotice {
  controller: { name: string | null; contact_email: string | null; grievance_officer: string | null };
  data_categories: { category: string; description: string }[];
  purposes: string[];
  rights: { right: string; description: string }[];
  retention: Record<string, number | boolean | string | null>;
  recipients: { name: string; description: string }[];
  how_to_exercise: string;
  note: string;
}

// --- Live demo (soc/api/routes/demo.py) ---------------------------------------------------

export type DemoStepStatus = "pending" | "running" | "done" | "failed" | "skipped";
export type DemoRunStatus = "queued" | "running" | "done" | "failed" | "cancelled" | "expired";

export interface DemoStep {
  key: string;
  label: string;
  status: DemoStepStatus;
  started_at: string | null;
  ended_at: string | null;
  /** Plain text from the runner, at most 200 characters. */
  note: string;
}

export interface DemoRun {
  id: string;
  status: DemoRunStatus;
  requested_by: string;
  requested_at: string;
  finished_at: string | null;
  steps: DemoStep[];
}

export interface DemoState {
  /** Demo mode is on in the SOC (IDPS_SOC_DEMO_TOKEN is set). */
  enabled: boolean;
  /** The host-side demo runner polled in the last 30 s. */
  runner_online: boolean;
  /** The current run, or the last one; null when there has been none since the SOC started. */
  run: DemoRun | null;
}
