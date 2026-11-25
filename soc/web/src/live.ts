import { useEffect, useRef, useState } from "react";
import { getToken, onTokenChange, setToken, wsUrl } from "./api/client";
import type { Alert, LiveBlockEvent } from "./api/types";

/** One /ws/alerts connection shared by every subscriber (the top bar's Live badge and the page),
 *  so a page never opens a second socket. Opened by the first subscriber, closed with the last.
 *  The token goes in the first message (never the URL). Reconnects with back-off. If the server
 *  rejects the token (4401) the session is over: the token is cleared, which signs the user out.
 *  A token change (logout, another login) closes the socket and reconnects with the new token. */
type AlertListener = (a: Alert) => void;
type BlockListener = (b: LiveBlockEvent) => void;
type StateListener = (connected: boolean) => void;

const alertListeners = new Set<AlertListener>();
const blockListeners = new Set<BlockListener>();
const stateListeners = new Set<StateListener>();
let ws: WebSocket | null = null;
let timer: ReturnType<typeof setTimeout> | undefined;
let retry = 1000;
let connected = false;
let refused = false; // 4401: don't retry until the token changes or everyone unsubscribes
let readyAt = 0;
const STABLE_MS = 10_000; // back-off resets only after a connection has lasted this long

function setConnected(value: boolean) {
  if (connected === value) return;
  connected = value;
  stateListeners.forEach((fn) => fn(value));
}

function active(): boolean {
  return alertListeners.size + blockListeners.size + stateListeners.size > 0;
}

function connect() {
  timer = undefined;
  const token = getToken();
  if (!token || refused || !active()) return;
  const socket = new WebSocket(wsUrl("/ws/alerts"));
  ws = socket;
  socket.onopen = () => socket.send(JSON.stringify({ token }));
  socket.onmessage = (ev) => {
    let msg: unknown;
    try {
      msg = JSON.parse(String(ev.data));
    } catch {
      return;
    }
    if (msg && typeof msg === "object" && "type" in msg && (msg as { type: string }).type === "ready") {
      setConnected(true);
      readyAt = Date.now();
      return;
    }
    if (msg && typeof msg === "object" && (msg as { type?: unknown }).type === "block") {
      for (const fn of [...blockListeners]) {
        try {
          fn(msg as LiveBlockEvent);
        } catch (err) {
          console.error("live block listener failed", err);
        }
      }
      return;
    }
    if (msg && typeof msg === "object" && "id" in msg) {
      for (const fn of [...alertListeners]) {
        try {
          fn(msg as Alert);
        } catch (err) {
          console.error("live alert listener failed", err); // one bad listener must not starve the rest
        }
      }
    }
  };
  socket.onclose = (ev) => {
    if (ws !== socket) return; // an older socket closing after a reconnect
    ws = null;
    setConnected(false);
    if (ev.code === 4401) {
      refused = true;
      setToken(null); // same as an HTTP 401: back to the login page
      return;
    }
    if (!active()) return;
    if (readyAt && Date.now() - readyAt >= STABLE_MS) retry = 1000;
    readyAt = 0;
    timer = setTimeout(connect, retry);
    retry = Math.min(retry * 2, 30_000);
  };
}

function ensureOpen() {
  if (!ws && !timer) connect();
}

function maybeClose() {
  if (active()) return;
  closeNow();
  retry = 1000;
  refused = false;
}

function closeNow() {
  if (timer) clearTimeout(timer);
  timer = undefined;
  const socket = ws;
  ws = null;
  readyAt = 0;
  setConnected(false);
  socket?.close();
}

// A different token means a different user (or none): never keep a socket opened for the old one.
let lastToken = getToken();
onTokenChange(() => {
  const token = getToken();
  if (token === lastToken) return;
  lastToken = token;
  closeNow();
  retry = 1000;
  refused = false;
  if (token && active()) connect();
});

/** Whether the shared live feed is connected (opens it while mounted). */
export function useLiveStatus(): boolean {
  const [state, setState] = useState(connected);
  useEffect(() => {
    stateListeners.add(setState);
    setState(connected);
    ensureOpen();
    return () => {
      stateListeners.delete(setState);
      maybeClose();
    };
  }, []);
  return state;
}

/** Call `onAlert` for every live alert. Returns whether the feed is connected. */
export function useLiveAlerts(onAlert: AlertListener): boolean {
  const handler = useRef(onAlert);
  handler.current = onAlert;
  const state = useLiveStatus();
  useEffect(() => {
    const fn: AlertListener = (a) => handler.current(a);
    alertListeners.add(fn);
    ensureOpen();
    return () => {
      alertListeners.delete(fn);
      maybeClose();
    };
  }, []);
  return state;
}

/** Call `onBlock` for every block, unblock and dry-run decision a sensor reports. */
export function useLiveBlocks(onBlock: BlockListener): boolean {
  const handler = useRef(onBlock);
  handler.current = onBlock;
  const state = useLiveStatus();
  useEffect(() => {
    const fn: BlockListener = (b) => handler.current(b);
    blockListeners.add(fn);
    ensureOpen();
    return () => {
      blockListeners.delete(fn);
      maybeClose();
    };
  }, []);
  return state;
}
