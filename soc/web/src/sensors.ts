import { useEffect, useState } from "react";
import { api } from "./api/client";
import type { SensorState, SensorsStatus } from "./api/types";

/** GET /sensors/status shared by everything on screen (the top-bar mode badge and the page),
 *  fetched when the first subscriber mounts and every 30 s while any is mounted. */

const EVERY_MS = 30_000;

export interface SensorsSnapshot { data: SensorsStatus | null; error: string | null }

const listeners = new Set<(s: SensorsSnapshot) => void>();
let snapshot: SensorsSnapshot = { data: null, error: null };
let timer: ReturnType<typeof setInterval> | undefined;
let seq = 0;

function publish(next: SensorsSnapshot) {
  snapshot = next;
  listeners.forEach((fn) => fn(next));
}

export async function reloadSensors(): Promise<void> {
  const mine = ++seq;
  try {
    const data = await api<SensorsStatus>("/sensors/status");
    if (mine === seq) publish({ data, error: null });
  } catch (err) {
    // Keep the last good data: one failed poll shouldn't blank the badge and cards.
    if (mine === seq) publish({ data: snapshot.data, error: err instanceof Error ? err.message : String(err) });
  }
}

export function useSensors(): SensorsSnapshot {
  const [state, setState] = useState(snapshot);
  useEffect(() => {
    listeners.add(setState);
    setState(snapshot);
    if (listeners.size === 1) {
      void reloadSensors();
      timer = setInterval(() => void reloadSensors(), EVERY_MS);
    }
    return () => {
      listeners.delete(setState);
      if (listeners.size === 0) {
        if (timer) clearInterval(timer);
        timer = undefined;
        seq++; // ignore a response that lands after everyone left
        snapshot = { data: null, error: null }; // the next user (maybe after a logout) refetches
      }
    };
  }, []);
  return state;
}

/** Sensors that are online and have reported a status. */
export function reporting(data: SensorsStatus | null): (SensorState & { status: NonNullable<SensorState["status"]> })[] {
  return (data?.sensors ?? []).filter((s): s is SensorState & { status: NonNullable<SensorState["status"]> } =>
    s.online && !s.revoked && s.status !== null);
}

export type BlockingMode = "on" | "dry-run" | "mixed" | "unknown";

/** Whether the online sensors really block, only log (dry-run), or differ. */
export function blockingMode(data: SensorsStatus | null): BlockingMode {
  const live = reporting(data);
  if (live.length === 0) return "unknown";
  const on = live.filter((s) => s.status.blocking_enabled && !s.status.dry_run).length;
  if (on === live.length) return "on";
  if (on === 0) return "dry-run";
  return "mixed";
}
