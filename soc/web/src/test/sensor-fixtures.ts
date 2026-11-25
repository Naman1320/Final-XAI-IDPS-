/** Builders for the GET /sensors/status shapes (see SensorsStatus in api/types.ts). */
export const policy = (o: Record<string, unknown> = {}) => ({
  confidence_threshold: 0.9, min_flows: 5, window_seconds: 60, min_alert_confidence: 0.6,
  block_ttl_seconds: 900, unblock_grace_seconds: 3600, max_analyst_blocks: 50, ...o,
});
export const report = (o: Record<string, unknown> = {}) => ({
  dry_run: false, blocking_enabled: true, interface: "eth0", mode: "live",
  model: { name: "rf-v3", checksum_ok: true }, policy: policy(), allowlist: ["10.0.0.254"],
  outbox_pending: 0, shap_p95_ms: 12.345, heartbeat: { enabled: true, ok: true },
  counters: { flows: 1, alerts: 1, blocked: 0, would_block: 0 }, sensor_version: "1.0", sent_at: null, ...o,
});
export const sensorState = (o: Record<string, unknown> = {}) => ({
  sensor_id: 1, name: "gw", revoked: false, last_seen_at: new Date(Date.now() - 5000).toISOString(),
  online: true, status: report(), ...o,
});
export const sensorsStatus = (sensors: unknown[] = [], soc_allowlist: string[] = []) => ({ soc_allowlist, sensors });
