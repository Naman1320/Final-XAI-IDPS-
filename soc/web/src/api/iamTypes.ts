// Shapes of the /iam API (soc/api/iam/*.py). Read-only mirrors: the backend is the source of truth.

export type LegacyRole = "analyst" | "admin";

export interface IamPage<T> {
  items: T[];
  next_cursor: number | null;
}

export interface Ref {
  id: number;
  name: string;
}

export interface PermissionInfo {
  name: string;
  description: string;
}

export interface PermissionGroup {
  key: string;
  title: string;
  permissions: PermissionInfo[];
}

export interface Catalog {
  groups: PermissionGroup[];
}

export interface IamUser {
  id: number;
  username: string;
  role: LegacyRole;
  disabled: boolean;
  created_at: string;
  mfa_enabled: boolean;
  last_login: string | null;
  roles: Ref[];
  groups: Ref[];
}

export interface IamUserDetail extends IamUser {
  mfa_required: boolean;
  sso_linked: boolean;
}

export interface PolicyRef {
  id: number;
  name: string;
  effect: Effect;
}

export interface EffectivePermissions {
  user_id: number;
  username: string;
  legacy_role: LegacyRole;
  all_access: boolean;
  permissions: string[];
  denied: string[];
  roles: Ref[];
  groups: Ref[];
  policies: PolicyRef[];
}

export interface IamRole {
  id: number;
  name: string;
  description: string;
  system: boolean;
  permissions: string[];
  user_count: number;
  group_count: number;
  created_at: string;
  updated_at: string;
}

export interface IamGroup {
  id: number;
  name: string;
  description: string;
  created_at: string;
  member_count: number;
  role_count: number;
}

export interface IamGroupDetail extends IamGroup {
  members: Ref[];
  roles: Ref[];
}

export type Effect = "allow" | "deny";
export type SubjectType = "user" | "group" | "role";

export interface Attachment {
  subject_type: SubjectType;
  subject_id: number;
  subject_name?: string | null;
}

export interface IamPolicy {
  id: number;
  name: string;
  description: string;
  effect: Effect;
  permissions: string[];
  resources: string[];
  disabled: boolean;
  created_at: string;
  attachment_count: number;
}

export interface IamPolicyDetail extends IamPolicy {
  attachments: Attachment[];
}

export interface LoginRecord {
  id: number;
  at: string;
  user_id: number | null;
  username: string;
  success: boolean;
  reason: string;
  ip: string;
  user_agent: string;
  mfa_used: boolean;
}

export interface IamAuditEntry {
  id: number;
  at: string;
  actor_type: string;
  actor_name: string;
  action: string;
  target: string;
  details: Record<string, unknown>;
}

export interface UserCreateBody {
  username: string;
  password: string;
  role: LegacyRole;
  role_ids: number[];
  group_ids: number[];
}

export interface UserUpdateBody {
  role?: LegacyRole;
  role_ids?: number[];
  group_ids?: number[];
  disabled?: boolean;
}

export interface PolicyBody {
  name: string;
  description: string;
  effect: Effect;
  permissions: string[];
  resources: string[];
  disabled: boolean;
}
