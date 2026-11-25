import { useCallback, useEffect, useRef } from "react";
import type { Alert } from "./api/types";
import { useLiveAlerts, useLiveBlocks } from "./live";

const MAX_WAIT_MS = 5000;

/** Call `reload` shortly after new alerts arrive (debounced, at most 5 s late), and every `everyMs` as a fallback.
 *  Returns whether the live feed is connected. */
export function useLiveRefresh(reload: () => void, onAlert?: (a: Alert) => void, everyMs = 30_000): boolean {
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  const alertRef = useRef(onAlert);
  alertRef.current = onAlert;

  const firstAt = useRef(0); // when the oldest not-yet-reloaded event arrived
  const schedule = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    const now = Date.now();
    if (!firstAt.current) firstAt.current = now;
    // Wait for a quiet 1.5 s, but never more than MAX_WAIT_MS, so a steady stream of
    // alerts (an attack in progress) still refreshes the page.
    const wait = Math.max(0, Math.min(1500, firstAt.current + MAX_WAIT_MS - now));
    timer.current = setTimeout(() => {
      timer.current = undefined;
      firstAt.current = 0;
      reloadRef.current();
    }, wait);
  }, []);
  const live = useLiveAlerts(useCallback((a: Alert) => {
    alertRef.current?.(a);
    schedule();
  }, [schedule]));
  // A block, unblock or dry-run decision changes what the page shows too.
  useLiveBlocks(schedule);

  useEffect(() => {
    const id = setInterval(() => reloadRef.current(), everyMs);
    return () => {
      clearInterval(id);
      if (timer.current) clearTimeout(timer.current);
    };
  }, [everyMs]);

  return live;
}
