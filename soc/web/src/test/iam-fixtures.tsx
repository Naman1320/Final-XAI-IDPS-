// An in-memory stand-in for the /iam API, used by the iam*.test.tsx files through a mocked `api`.
import { ApiError } from "../api/client";

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const CATALOG = {
  groups: [
    { key: "cloud", title: "Cloud", permissions: [
      { name: "cloud.view", description: "View cloud" }, { name: "cloud.instances.write", description: "Change instances" } ] },
    { key: "users", title: "Users", permissions: [
      { name: "iam.users.view", description: "View users" }, { name: "iam.users.write", description: "Change users" },
      { name: "iam.users.delete", description: "Delete users" } ] },
    { key: "roles", title: "Roles", permissions: [
      { name: "iam.roles.view", description: "View roles" }, { name: "iam.roles.write", description: "Change roles" } ] },
    { key: "groups", title: "Groups", permissions: [
      { name: "iam.groups.view", description: "View groups" }, { name: "iam.groups.write", description: "Change groups" } ] },
    { key: "policies", title: "Policies", permissions: [
      { name: "iam.policies.view", description: "View policies" }, { name: "iam.policies.write", description: "Change policies" } ] },
    { key: "monitoring", title: "Monitoring", permissions: [
      { name: "iam.audit.view", description: "View audit" }, { name: "iam.logins.view", description: "View logins" } ] },
  ],
};
export const ALL_PERMS = CATALOG.groups.flatMap((g) => g.permissions.map((p) => p.name));

export const user = (o: Row = {}): Row => ({
  id: 2, username: "alice", role: "analyst", disabled: false, created_at: "2026-01-05T10:00:00Z", mfa_enabled: false,
  last_login: "2026-11-01T08:00:00Z", roles: [], groups: [], ...o,
});
export const role = (o: Row = {}): Row => ({
  id: 10, name: "viewer", description: "", system: false, permissions: ["cloud.view"], created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z", ...o,
});
export const group = (o: Row = {}): Row => ({ id: 20, name: "ops", description: "", created_at: "2026-01-01T00:00:00Z", members: [], roles: [], ...o });
export const policy = (o: Row = {}): Row => ({
  id: 30, name: "no-delete", description: "", effect: "deny", permissions: ["cloud.instances.write"], resources: ["*"],
  disabled: false, created_at: "2026-01-01T00:00:00Z", attachments: [], ...o,
});
export const login = (o: Row = {}): Row => ({
  id: 1, at: "2026-11-01T08:00:00Z", user_id: 2, username: "alice", success: true, reason: "ok", ip: "10.0.0.5",
  user_agent: "Firefox", mfa_used: false, ...o,
});
export const entry = (o: Row = {}): Row => ({
  id: 1, at: "2026-11-01T09:00:00Z", actor_type: "user", actor_name: "root", action: "iam_user_create", target: "user:alice",
  details: { id: 2 }, ...o,
});

export interface World {
  users: Row[]; roles: Row[]; groups: Row[]; policies: Row[]; logins: Row[]; audit: Row[];
  effective: Record<number, Row>;
  failures: { method: string; path: RegExp; status: number; message: string }[];
}

export function newWorld(): World {
  return {
    users: [user({ id: 1, username: "root", role: "admin", mfa_enabled: true }), user(), user({ id: 3, username: "bob", disabled: true })],
    roles: [role({ id: 1, name: "admin", system: true, permissions: ALL_PERMS }), role({ id: 2, name: "analyst", system: true }), role()],
    groups: [group()], policies: [policy()], logins: [login()], audit: [entry()], effective: {}, failures: [],
  };
}

function paged(items: Row[], p: URLSearchParams) {
  const sorted = [...items].sort((a, b) => b.id - a.id);
  const cursor = p.get("cursor");
  const limit = Number(p.get("limit") ?? 100);
  const rest = cursor ? sorted.filter((i) => i.id < Number(cursor)) : sorted;
  const page = rest.slice(0, limit);
  return { items: page, next_cursor: rest.length > limit ? page[page.length - 1].id : null };
}

const ref = (rows: Row[], ids: number[], key = "name") => rows.filter((r) => ids.includes(r.id)).map((r) => ({ id: r.id, name: r[key] }));

export function makeApi(w: World) {
  const withRefs = (u: Row) => ({
    ...u, mfa_required: u.role === "admin", sso_linked: false,
    roles: u.roleIds ? ref(w.roles, u.roleIds) : u.roles, groups: u.groupIds ? ref(w.groups, u.groupIds) : u.groups,
  });
  const roleOut = (r: Row) => ({
    ...r, user_count: w.users.filter((u) => (u.roleIds ?? []).includes(r.id) || u.roles.some((x: Row) => x.id === r.id)).length,
    group_count: w.groups.filter((g) => g.roles.some((x: Row) => x.id === r.id)).length,
  });
  const groupOut = (g: Row) => ({ ...g, member_count: g.members.length, role_count: g.roles.length });
  const policyOut = (p: Row, detail = false) => {
    const { attachments, ...rest } = p;
    return detail ? { ...rest, attachment_count: attachments.length, attachments } : { ...rest, attachment_count: attachments.length };
  };
  const nameOf = (type: string, id: number) =>
    (type === "user" ? w.users.find((u) => u.id === id)?.username : (type === "group" ? w.groups : w.roles).find((r) => r.id === id)?.name) ?? null;
  const nextId = (rows: Row[]) => Math.max(0, ...rows.map((r) => r.id)) + 1;

  return async (path: string, opts: { method?: string; json?: any } = {}): Promise<unknown> => { // eslint-disable-line @typescript-eslint/no-explicit-any
    const method = opts.method ?? "GET";
    const url = new URL(path, "http://x");
    const p = url.searchParams;
    const body = opts.json ?? {};
    const route = url.pathname;
    await Promise.resolve();
    const fail = w.failures.find((f) => f.method === method && f.path.test(route));
    if (fail) throw new ApiError(fail.status, fail.message);
    let m: RegExpExecArray | null;

    if (method === "GET" && route === "/iam/permissions") return CATALOG;
    // users
    if (route === "/iam/users" && method === "GET") {
      let items = w.users.filter((u) => (!p.get("q") || u.username.includes(p.get("q")!))
        && (!p.get("status") || u.disabled === (p.get("status") === "disabled")) && (!p.get("role") || u.role === p.get("role"))
        && (!p.get("group_id") || u.groups.some((g: Row) => g.id === Number(p.get("group_id"))))
        && (!p.get("role_id") || u.roles.some((r: Row) => r.id === Number(p.get("role_id")))));
      items = items.map(withRefs);
      return paged(items, p);
    }
    if (route === "/iam/users" && method === "POST") {
      if (w.users.some((u) => u.username === body.username)) throw new ApiError(409, `user '${body.username}' already exists`);
      const u = user({ id: nextId(w.users), username: body.username, role: body.role, roles: ref(w.roles, body.role_ids), groups: ref(w.groups, body.group_ids), last_login: null });
      w.users.push(u);
      return withRefs(u);
    }
    if ((m = /^\/iam\/users\/(\d+)\/effective-permissions$/.exec(route))) {
      const id = Number(m[1]);
      return w.effective[id] ?? { user_id: id, username: "x", legacy_role: "analyst", all_access: false, permissions: ["cloud.view"], denied: [], roles: [], groups: [], policies: [] };
    }
    if ((m = /^\/iam\/users\/(\d+)\/(activate|deactivate)$/.exec(route))) {
      const u = w.users.find((x) => x.id === Number(m![1]))!;
      u.disabled = m[2] === "deactivate";
      return withRefs(u);
    }
    if ((m = /^\/iam\/users\/(\d+)$/.exec(route))) {
      const u = w.users.find((x) => x.id === Number(m![1]));
      if (!u) throw new ApiError(404, "user not found");
      if (method === "GET") return withRefs(u);
      if (method === "PATCH") {
        if (body.role) u.role = body.role;
        if (body.role_ids) u.roles = ref(w.roles, body.role_ids);
        if (body.group_ids) u.groups = ref(w.groups, body.group_ids);
        return withRefs(u);
      }
      if (method === "DELETE") { w.users = w.users.filter((x) => x !== u); return null; }
    }
    // roles
    if (route === "/iam/roles" && method === "GET") {
      const items = w.roles.filter((r) => (!p.get("q") || r.name.includes(p.get("q")!)) && (!p.get("system") || r.system === (p.get("system") === "true")));
      return paged(items.map(roleOut), p);
    }
    if (route === "/iam/roles" && method === "POST") {
      if (w.roles.some((r) => r.name.toLowerCase() === body.name.toLowerCase())) throw new ApiError(409, `the name '${body.name}' is already used`);
      const r = role({ id: nextId(w.roles), ...body });
      w.roles.push(r);
      return roleOut(r);
    }
    if ((m = /^\/iam\/roles\/(\d+)$/.exec(route))) {
      const r = w.roles.find((x) => x.id === Number(m![1]))!;
      if (r.system) throw new ApiError(409, "system roles cannot be changed or deleted");
      if (method === "PATCH") { Object.assign(r, body); return roleOut(r); }
      if (method === "DELETE") { w.roles = w.roles.filter((x) => x !== r); return null; }
    }
    // groups
    if (route === "/iam/groups" && method === "GET") {
      return paged(w.groups.filter((g) => !p.get("q") || g.name.includes(p.get("q")!)).map(groupOut), p);
    }
    if (route === "/iam/groups" && method === "POST") {
      const g = group({ id: nextId(w.groups), ...body });
      w.groups.push(g);
      return groupOut(g);
    }
    if ((m = /^\/iam\/groups\/(\d+)(?:\/(members|roles))?$/.exec(route))) {
      const g = w.groups.find((x) => x.id === Number(m![1]))!;
      if (m[2] === "members") { g.members = ref(w.users, body.user_ids, "username"); return groupOut(g); }
      if (m[2] === "roles") { g.roles = ref(w.roles, body.role_ids); return groupOut(g); }
      if (method === "GET") return groupOut(g);
      if (method === "PATCH") { Object.assign(g, body); return groupOut(g); }
      if (method === "DELETE") { w.groups = w.groups.filter((x) => x !== g); return null; }
    }
    // policies
    if (route === "/iam/policies" && method === "GET") {
      const items = w.policies.filter((x) => (!p.get("q") || x.name.includes(p.get("q")!)) && (!p.get("effect") || x.effect === p.get("effect"))
        && (!p.get("disabled") || x.disabled === (p.get("disabled") === "true")));
      return paged(items.map((x) => policyOut(x)), p);
    }
    if (route === "/iam/policies" && method === "POST") {
      const x = policy({ id: nextId(w.policies), attachments: [], ...body });
      w.policies.push(x);
      return policyOut(x, true);
    }
    if ((m = /^\/iam\/policies\/(\d+)(\/attachments)?$/.exec(route))) {
      const x = w.policies.find((q) => q.id === Number(m![1]))!;
      if (m[2]) {
        x.attachments = body.attachments.map((a: Row) => ({ ...a, subject_name: nameOf(a.subject_type, a.subject_id) }));
        return policyOut(x, true);
      }
      if (method === "GET") return policyOut(x, true);
      if (method === "PATCH") { Object.assign(x, body); return policyOut(x, true); }
      if (method === "DELETE") { w.policies = w.policies.filter((q) => q !== x); return null; }
    }
    // monitoring
    if (route === "/iam/logins") {
      const t = (s: string) => Date.parse(s);
      const items = w.logins.filter((l) => (!p.get("user_id") || l.user_id === Number(p.get("user_id"))) && (!p.get("username") || l.username === p.get("username"))
        && (!p.get("success") || l.success === (p.get("success") === "true")) && (!p.get("reason") || l.reason === p.get("reason"))
        && (!p.get("since") || t(l.at) >= t(p.get("since")!)) && (!p.get("until") || t(l.at) <= t(p.get("until")!)));
      return paged(items, p);
    }
    if (route === "/iam/audit") {
      const items = w.audit.filter((e) => (!p.get("actor") || e.actor_name === p.get("actor")) && (!p.getAll("action").length || p.getAll("action").includes(e.action))
        && (!p.get("target") || e.target === p.get("target")));
      return paged(items, p);
    }
    throw new ApiError(404, `unmocked ${method} ${path}`);
  };
}

export const ADMIN_PERMS = ALL_PERMS;

import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import IamModule from "../pages/iam";

export const meWith = (permissions: string[] | undefined, o: Row = {}) => ({ id: 1, username: "root", role: "admin", permissions, ...o });

export function renderIam(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path="/iam/*" element={<IamModule />} /></Routes>
    </MemoryRouter>,
  );
}

export const calls = (api: { mock: { calls: unknown[][] } }, method: string, prefix = "") =>
  api.mock.calls.filter(([p, o]) => ((o as Row | undefined)?.method ?? "GET") === method && String(p).startsWith(prefix));
