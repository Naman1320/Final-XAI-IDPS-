import { useCallback, useEffect, useMemo, useState } from "react";
import { api, query } from "./api/client";
import type { Block, LiveBlockEvent, Page, WouldBlock } from "./api/types";
import { useNow } from "./components/common";
import { useLiveBlocks } from "./live";

/** What the sensors are doing about each address, for the maps: "blocked" (an active block on
 *  some sensor) or "would" (a dry-run sensor would have blocked it). Loaded from the API, kept
 *  current by the live feed, and refreshed every 30 s as a fallback. Matched by address only:
 *  the maps show hosts, not sensors. */
export type BlockMark = "blocked" | "would";

interface Entry { mark: BlockMark; until: number | null }

const WOULD_DEFAULT_MS = 3600_000; // a dry-run decision without a block time counts for 1 h
const REFRESH_MS = 30_000;

function wouldUntil(at: string, ttl: number | null): number | null {
  const t = Date.parse(at);
  return Number.isNaN(t) ? null : t + (ttl != null ? ttl * 1000 : WOULD_DEFAULT_MS);
}

function blockUntil(expiresAt: string | null): number | null {
  if (!expiresAt) return null;
  const t = Date.parse(expiresAt);
  return Number.isNaN(t) ? null : t;
}

/** Fold one live event into the map (returns a new map). Exported for tests. */
export function applyBlockEvent(prev: Map<string, Entry>, e: LiveBlockEvent): Map<string, Entry> {
  const next = new Map(prev);
  const cur = next.get(e.ip);
  if (e.event === "blocked") {
    next.set(e.ip, { mark: "blocked", until: blockUntil(e.expires_at) });
  } else if (e.event === "unblocked") {
    if (cur?.mark === "blocked") next.delete(e.ip);
  } else if (cur?.mark !== "blocked") {
    next.set(e.ip, { mark: "would", until: wouldUntil(e.at, e.ttl_seconds) });
  }
  return next;
}

export function useBlockMarks(): Map<string, BlockMark> {
  const [entries, setEntries] = useState<Map<string, Entry>>(new Map());
  const now = useNow(5000);

  const load = useCallback(async () => {
    try {
      const [blocks, would] = await Promise.all([
        api<Page<Block>>(`/blocks${query({ active: true, limit: 200 })}`),
        api<Page<WouldBlock>>(`/blocks/would${query({ since_hours: 24, limit: 200 })}`),
      ]);
      const m = new Map<string, Entry>();
      for (const w of would.items) {
        const until = wouldUntil(w.at, w.ttl_seconds);
        const cur = m.get(w.ip);
        if (!cur || (until ?? Infinity) > (cur.until ?? Infinity)) m.set(w.ip, { mark: "would", until });
      }
      for (const b of blocks.items) if (b.active) m.set(b.ip, { mark: "blocked", until: blockUntil(b.expires_at) });
      setEntries(m);
    } catch {
      /* keep what we have; the next refresh tries again */
    }
  }, []);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  useLiveBlocks(useCallback((e: LiveBlockEvent) => setEntries((prev) => applyBlockEvent(prev, e)), []));

  return useMemo(() => {
    const out = new Map<string, BlockMark>();
    for (const [ip, e] of entries) if (e.until === null || e.until > now) out.set(ip, e.mark);
    return out;
  }, [entries, now]);
}

/** Whether the viewer asked for less motion (follows the system setting while mounted). */
export function useReducedMotion(): boolean {
  const query = "(prefers-reduced-motion: reduce)";
  const [reduce, setReduce] = useState(() => typeof window !== "undefined" && !!window.matchMedia?.(query).matches);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    const update = () => setReduce(mq.matches);
    mq.addEventListener?.("change", update);
    return () => mq.removeEventListener?.("change", update);
  }, []);
  return reduce;
}
