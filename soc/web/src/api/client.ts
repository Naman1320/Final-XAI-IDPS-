// Small fetch wrapper for the SOC API.
//
// The access token lives in memory, with a copy in sessionStorage so a page refresh keeps
// you logged in; it is gone when the tab closes. It is never put in a URL or a cookie.
// The dashboard never renders API data as HTML (no dangerouslySetInnerHTML), which is what
// keeps a token in storage safe from injected markup in alert fields.

import { workspace } from "../workspace";

const BASE = workspace.api;
const STORAGE_KEY = workspace.storageKey("idps-soc-token");

let token: string | null = null;
try {
  token = sessionStorage.getItem(STORAGE_KEY);
} catch {
  token = null;
}

type Listener = () => void;
const listeners = new Set<Listener>();

export function getToken(): string | null {
  return token;
}

export function setToken(value: string | null): void {
  token = value;
  try {
    if (value) sessionStorage.setItem(STORAGE_KEY, value);
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable: keep the in-memory copy only */
  }
  listeners.forEach((fn) => fn());
}

export function onTokenChange(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public code?: string) {
    super(message);
  }
}

function detailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (d && typeof d === "object" && "message" in d && typeof d.message === "string") return d.message;
    if (Array.isArray(d)) {
      return d
        .map((e) => (e && typeof e === "object" && "msg" in e ? String(e.msg) : String(e)))
        .join("; ");
    }
  }
  return fallback;
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  const res = await fetch(BASE + path, { ...init, headers, body });
  if (res.status === 401 && token) setToken(null); // expired or revoked: back to login
  const text = await res.text();
  const data = text ? safeJson(text) : null;
  if (!res.ok) throw new ApiError(res.status, detailMessage(data, `${res.status} ${res.statusText}`),
    (data as { detail?: { code?: string } } | null)?.detail?.code);
  if (path.startsWith("/iam/") && init.method && init.method !== "GET") {
    window.dispatchEvent(new Event("idps-iam-changed"));
  }
  return data as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${BASE}${path}`;
}

/** POST and read a streamed NDJSON reply line by line (the assistant's chat endpoint). */
export async function streamNdjson(path: string, json: unknown, onEvent: (e: Record<string, unknown>) => void,
  signal?: AbortSignal): Promise<void> {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(BASE + path, { method: "POST", headers, body: JSON.stringify(json), signal });
  if (res.status === 401 && token) setToken(null);
  if (!res.ok || !res.body) {
    const text = await res.text();
    throw new ApiError(res.status, detailMessage(text ? safeJson(text) : null, `${res.status} ${res.statusText}`));
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const emitLine = (line: string) => {
    if (!line.trim()) return;
    const event = safeJson(line.trim());
    if (event && typeof event === "object") onEvent(event as Record<string, unknown>);
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      emitLine(buffer.slice(0, nl));
      buffer = buffer.slice(nl + 1);
    }
  }
  buffer += decoder.decode(); // flush a multi-byte character split across chunks
  emitLine(buffer); // a last line without a trailing newline
}

/** GET a file the API serves (e.g. the weekly PDF) with the access token, and hand it to the
 *  browser as a download. A plain link can't send the token. */
export async function download(path: string, fallbackName: string): Promise<void> {
  const headers = new Headers();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(BASE + path, { headers });
  if (res.status === 401 && token) setToken(null);
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, detailMessage(text ? safeJson(text) : null, `${res.status} ${res.statusText}`));
  }
  if (!(res.headers.get("Content-Type") ?? "").startsWith("application/pdf")) {
    throw new ApiError(res.status, "the SOC did not send a PDF"); // e.g. a proxy's HTML page
  }
  const blob = await res.blob();
  const named = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? "";
  const name = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.pdf$/.test(named) ? named : fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
