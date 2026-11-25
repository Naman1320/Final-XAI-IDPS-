import { api, query } from "./client";
import type {
  Activity, Bucket, BucketOut, CloudAlert, CloudAlertOut, CloudOverview, CostOut, CostRange, EvaluateResult,
  FleetMetrics, Instance, InstanceCreate, InstanceMetrics, InstanceOut, MetricRange, Notifications, Paged,
  RuleCreate, SecurityGroup, SecurityGroupOut, Subnet, Volume, VolumeOut, Vpc,
} from "./cloudTypes";

/** Typed calls to /cloud (the SOC API; the client adds the /api prefix and the token). Path pieces
 *  that come from data are encoded. */
const e = encodeURIComponent;
type Params = Record<string, string | number | boolean | undefined | null>;

export const cloudApi = {
  overview: () => api<CloudOverview>("/cloud/overview"),
  fleetMetrics: () => api<FleetMetrics>("/cloud/metrics/summary"),
  cost: (range: CostRange) => api<CostOut>(`/cloud/cost${query({ range })}`),

  instances: (p: Params = {}) => api<Paged<Instance>>(`/cloud/instances${query(p)}`),
  instance: (id: string) => api<InstanceOut>(`/cloud/instances/${e(id)}`),
  instanceMetrics: (id: string, range: MetricRange) =>
    api<InstanceMetrics>(`/cloud/instances/${e(id)}/metrics${query({ range })}`),
  createInstance: (json: InstanceCreate) => api<InstanceOut>("/cloud/instances", { method: "POST", json }),
  updateInstance: (id: string, json: { name?: string; tags?: Record<string, string> }) =>
    api<InstanceOut>(`/cloud/instances/${e(id)}`, { method: "PATCH", json }),
  instanceAction: (id: string, verb: "start" | "stop" | "reboot") =>
    api<InstanceOut>(`/cloud/instances/${e(id)}/${verb}`, { method: "POST" }),
  terminateInstance: (id: string) => api<InstanceOut>(`/cloud/instances/${e(id)}`, { method: "DELETE" }),

  volumes: (p: Params = {}) => api<Paged<Volume>>(`/cloud/volumes${query(p)}`),
  createVolume: (json: { name: string; size_gb: number; type: string; encrypted: boolean }) =>
    api<VolumeOut>("/cloud/volumes", { method: "POST", json }),
  resizeVolume: (id: string, size_gb: number) =>
    api<VolumeOut>(`/cloud/volumes/${e(id)}`, { method: "PATCH", json: { size_gb } }),
  attachVolume: (id: string, instance_id: string) =>
    api<VolumeOut>(`/cloud/volumes/${e(id)}/attach`, { method: "POST", json: { instance_id } }),
  detachVolume: (id: string) => api<VolumeOut>(`/cloud/volumes/${e(id)}/detach`, { method: "POST" }),
  deleteVolume: (id: string) => api<VolumeOut>(`/cloud/volumes/${e(id)}`, { method: "DELETE" }),

  buckets: (p: Params = {}) => api<Paged<Bucket>>(`/cloud/buckets${query(p)}`),
  createBucket: (json: { name: string; versioning: boolean; encrypted: boolean; public_access_blocked: boolean }) =>
    api<BucketOut>("/cloud/buckets", { method: "POST", json }),
  updateBucket: (name: string, json: Partial<Pick<Bucket, "versioning" | "encrypted" | "public_access_blocked">>) =>
    api<BucketOut>(`/cloud/buckets/${e(name)}`, { method: "PATCH", json }),
  deleteBucket: (name: string, force: boolean) =>
    api<BucketOut>(`/cloud/buckets/${e(name)}${query({ force: force ? "true" : undefined })}`, { method: "DELETE" }),

  vpcs: (p: Params = {}) => api<Paged<Vpc>>(`/cloud/network/vpcs${query(p)}`),
  subnets: (p: Params = {}) => api<Paged<Subnet>>(`/cloud/network/subnets${query(p)}`),
  securityGroups: (p: Params = {}) => api<Paged<SecurityGroup>>(`/cloud/network/security-groups${query(p)}`),
  createSecurityGroup: (json: { name: string; description: string; vpc_id: string }) =>
    api<SecurityGroupOut>("/cloud/network/security-groups", { method: "POST", json }),
  deleteSecurityGroup: (id: string) =>
    api<SecurityGroupOut>(`/cloud/network/security-groups/${e(id)}`, { method: "DELETE" }),
  addRule: (id: string, json: RuleCreate) =>
    api<SecurityGroupOut>(`/cloud/network/security-groups/${e(id)}/rules`, { method: "POST", json }),
  deleteRule: (id: string, ruleId: number) =>
    api<SecurityGroupOut>(`/cloud/network/security-groups/${e(id)}/rules/${ruleId}`, { method: "DELETE" }),

  alerts: (p: Params = {}) => api<Paged<CloudAlert>>(`/cloud/alerts${query(p)}`),
  evaluateAlerts: () => api<EvaluateResult>("/cloud/alerts/evaluate", { method: "POST" }),
  alertAction: (id: number, verb: "acknowledge" | "resolve") =>
    api<CloudAlertOut>(`/cloud/alerts/${id}/${verb}`, { method: "POST" }),
  deleteAlert: (id: number) => api<CloudAlertOut>(`/cloud/alerts/${id}`, { method: "DELETE" }),
  notifications: (limit = 5) => api<Notifications>(`/cloud/notifications${query({ limit })}`),

  activity: (p: Params = {}) => api<Paged<Activity>>(`/cloud/activity${query(p)}`),
};
