// Calls to the /iam API through the shared client (so a 401 still sends the user to sign-in).
import { api, query } from "./client";
import type {
  Attachment, Catalog, EffectivePermissions, IamAuditEntry, IamGroup, IamGroupDetail, IamPage, IamPolicy,
  IamPolicyDetail, IamRole, IamUser, IamUserDetail, LoginRecord, PolicyBody, UserCreateBody, UserUpdateBody,
} from "./iamTypes";

export const PAGE_SIZE = 25;
type Params = Record<string, string | number | boolean | undefined | null>;

/** GET every page of a list (newest first) into one array, for pickers and counts. Stops after `maxPages`. */
export async function fetchAll<T>(path: string, params: Params = {}, maxPages = 10): Promise<{ items: T[]; more: boolean }> {
  const items: T[] = [];
  let cursor: number | null | undefined;
  for (let i = 0; i < maxPages; i++) {
    const page = await api<IamPage<T>>(`${path}${query({ ...params, limit: 500, cursor })}`);
    items.push(...page.items);
    if (page.next_cursor == null) return { items, more: false };
    cursor = page.next_cursor;
  }
  return { items, more: true };
}

export const iam = {
  catalog: () => api<Catalog>("/iam/permissions"),

  users: (p: Params) => api<IamPage<IamUser>>(`/iam/users${query(p)}`),
  user: (id: number) => api<IamUserDetail>(`/iam/users/${id}`),
  effective: (id: number) => api<EffectivePermissions>(`/iam/users/${id}/effective-permissions`),
  createUser: (body: UserCreateBody) => api<IamUserDetail>("/iam/users", { method: "POST", json: body }),
  updateUser: (id: number, body: UserUpdateBody) => api<IamUserDetail>(`/iam/users/${id}`, { method: "PATCH", json: body }),
  setActive: (id: number, active: boolean) =>
    api<IamUserDetail>(`/iam/users/${id}/${active ? "activate" : "deactivate"}`, { method: "POST" }),
  deleteUser: (id: number) => api<null>(`/iam/users/${id}`, { method: "DELETE" }),

  roles: (p: Params) => api<IamPage<IamRole>>(`/iam/roles${query(p)}`),
  createRole: (body: { name: string; description: string; permissions: string[] }) =>
    api<IamRole>("/iam/roles", { method: "POST", json: body }),
  updateRole: (id: number, body: Partial<{ name: string; description: string; permissions: string[] }>) =>
    api<IamRole>(`/iam/roles/${id}`, { method: "PATCH", json: body }),
  deleteRole: (id: number) => api<null>(`/iam/roles/${id}`, { method: "DELETE" }),

  groups: (p: Params) => api<IamPage<IamGroup>>(`/iam/groups${query(p)}`),
  group: (id: number) => api<IamGroupDetail>(`/iam/groups/${id}`),
  createGroup: (body: { name: string; description: string }) =>
    api<IamGroupDetail>("/iam/groups", { method: "POST", json: body }),
  updateGroup: (id: number, body: Partial<{ name: string; description: string }>) =>
    api<IamGroupDetail>(`/iam/groups/${id}`, { method: "PATCH", json: body }),
  deleteGroup: (id: number) => api<null>(`/iam/groups/${id}`, { method: "DELETE" }),
  setMembers: (id: number, user_ids: number[]) =>
    api<IamGroupDetail>(`/iam/groups/${id}/members`, { method: "PUT", json: { user_ids } }),
  setGroupRoles: (id: number, role_ids: number[]) =>
    api<IamGroupDetail>(`/iam/groups/${id}/roles`, { method: "PUT", json: { role_ids } }),

  policies: (p: Params) => api<IamPage<IamPolicy>>(`/iam/policies${query(p)}`),
  policy: (id: number) => api<IamPolicyDetail>(`/iam/policies/${id}`),
  createPolicy: (body: PolicyBody) => api<IamPolicyDetail>("/iam/policies", { method: "POST", json: body }),
  updatePolicy: (id: number, body: Partial<PolicyBody>) =>
    api<IamPolicyDetail>(`/iam/policies/${id}`, { method: "PATCH", json: body }),
  deletePolicy: (id: number) => api<null>(`/iam/policies/${id}`, { method: "DELETE" }),
  setAttachments: (id: number, attachments: Pick<Attachment, "subject_type" | "subject_id">[]) =>
    api<IamPolicyDetail>(`/iam/policies/${id}/attachments`, { method: "PUT", json: { attachments } }),

  logins: (p: Params) => api<IamPage<LoginRecord>>(`/iam/logins${query(p)}`),
  audit: (p: Params & { action?: string }) => api<IamPage<IamAuditEntry>>(`/iam/audit${query(p)}`),
};
