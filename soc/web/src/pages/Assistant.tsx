import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, streamNdjson } from "../api/client";
import { ErrorText, PageHead, Pill, useLoad } from "../components/common";
import { dateTime } from "../format";

interface Status { enabled: boolean; model: string | null; reason: string | null }
interface ConversationSummary { id: number; title: string; user_turns: number; updated_at: string }
interface StoredMessage { role: "user" | "assistant"; text: string; tools: string[] }
interface Conversation extends ConversationSummary { messages: StoredMessage[] }

interface Bubble {
  role: "user" | "assistant";
  text: string;
  tools: { name: string; ok?: boolean }[];
  actions: { id: number; ip: string }[];
  error?: string;
}

const TOOL_LABELS: Record<string, string> = {
  search_alerts: "searched alerts", get_alert: "read the alert", top_attackers: "looked up top attackers",
  list_blocks: "listed blocks", get_case: "read the case", metrics_summary: "read the metrics",
  get_playbook: "read the playbook", propose_block: "proposed a block",
};

/** Playbooks the assistant can read (docs/playbooks), by the class name its tool accepts. */
const PLAYBOOKS: { label: string; cls: string }[] = [
  { label: "port scan", cls: "PortScan" }, { label: "brute force", cls: "brute force" },
  { label: "DoS", cls: "DoS" }, { label: "web attack", cls: "Web Attack" }, { label: "bot", cls: "Bot" },
  { label: "infiltration", cls: "Infiltration" }, { label: "Heartbleed", cls: "Heartbleed" },
];

const SUGGESTIONS = [
  "Who were the top attackers in the last 24 hours?",
  "Summarise today's critical and high alerts.",
  "What's our false-positive rate this week?",
];

/** Show the assistant's text with alert/action ids turned into links. Never renders HTML. */
function Linked({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  const re = /(alert|action|case) #(\d{1,12})/gi;
  let last = 0;
  for (const m of text.matchAll(re)) {
    const i = m.index ?? 0;
    parts.push(text.slice(last, i));
    const kind = m[1].toLowerCase();
    const to = kind === "alert" ? `/alerts/${m[2]}` : kind === "case" ? `/cases/${m[2]}` : "/response";
    parts.push(<Link key={i} to={to}>{m[0]}</Link>);
    last = i + m[0].length;
  }
  parts.push(text.slice(last));
  return <>{parts}</>;
}

export default function Assistant() {
  const [params, setParams] = useSearchParams();
  const { data: status } = useLoad(() => api<Status>("/assistant/status"), []);
  const { data: history, reload: reloadHistory } = useLoad(
    () => api<ConversationSummary[]>("/assistant/conversations"), []);
  const [conversationId, setConversationId] = useState<number | null>(null);
  const [bubbles, setBubbles] = useState<Bubble[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  // Loading a past conversation counts as busy: a message sent meanwhile would mix with it.
  const [loading, setLoading] = useState(false);
  // What screen readers hear: the start and end of a reply, not every streamed chunk.
  const [announce, setAnnounce] = useState("");

  // "Explain this alert" from an alert page: /assistant?alert=12
  useEffect(() => {
    const alertId = params.get("alert");
    if (alertId && /^\d{1,12}$/.test(alertId) && status?.enabled) {
      setParams({}, { replace: true });
      void send(`Explain alert #${alertId}: why was it raised (by the model or a Suricata rule), is it likely a real attack, and what should I do?`, null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.enabled]);

  useEffect(() => () => { abort.current?.abort(); }, []);

  async function open(id: number) {
    if (busy || loading) return;
    let conv: Conversation;
    setLoading(true);
    try {
      conv = await api<Conversation>(`/assistant/conversations/${id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    } finally {
      setLoading(false);
    }
    setConversationId(conv.id);
    setBubbles(conv.messages.map((m) => ({ role: m.role, text: m.text, actions: [],
      tools: m.tools.map((name) => ({ name, ok: true })) })));
    setError(null);
  }

  function newChat() {
    if (busy || loading) return;
    setConversationId(null);
    setBubbles([]);
    setError(null);
  }

  function update(fn: (b: Bubble) => Bubble) {
    setBubbles((bs) => [...bs.slice(0, -1), fn(bs[bs.length - 1])]);
  }

  async function send(message: string, convId: number | null = conversationId) {
    const text = message.trim();
    if (!text || busy || loading) return;
    setBusy(true);
    setAnnounce("The assistant is replying…");
    setError(null);
    setInput("");
    setBubbles((bs) => [...bs, { role: "user", text, tools: [], actions: [] },
      { role: "assistant", text: "", tools: [], actions: [] }]);
    abort.current = new AbortController();
    try {
      await streamNdjson("/assistant/chat", { message: text, ...(convId ? { conversation_id: convId } : {}) }, (e) => {
        switch (e.type) {
          case "conversation":
            setConversationId(Number(e.conversation_id));
            break;
          case "text":
            update((b) => ({ ...b, text: b.text + String(e.text ?? "") }));
            break;
          case "tool":
            update((b) => ({ ...b, tools: [...b.tools, { name: String(e.name) }] }));
            break;
          case "tool_result":
            update((b) => {
              const tools = [...b.tools];
              const i = tools.map((t) => t.name).lastIndexOf(String(e.name));
              if (i >= 0) tools[i] = { ...tools[i], ok: Boolean(e.ok) };
              return { ...b, tools };
            });
            break;
          case "action_proposed":
            update((b) => ({ ...b, actions: [...b.actions, { id: Number(e.action_id), ip: String(e.ip) }] }));
            break;
          case "error":
            update((b) => ({ ...b, error: String(e.message ?? "error") }));
            break;
        }
      }, abort.current.signal);
    } catch (err) {
      if (!(err instanceof DOMException && err.name === "AbortError")) {
        setError(err instanceof ApiError ? err.message : "Can't reach the SOC API");
        // keep a partial reply (and any proposal notice); drop only an empty bubble
        setBubbles((bs) => {
          const last = bs[bs.length - 1];
          return last && !last.text && last.actions.length === 0 ? bs.slice(0, -1) : bs;
        });
      }
    } finally {
      setBusy(false);
      setAnnounce("Reply finished.");
      void reloadHistory();
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void send(input);
  }

  const off = !!status && !status.enabled;

  return (
    <>
      <PageHead title="SOC assistant">
        {status && (status.enabled
          ? <Pill tone="ok" round dot>On{status.model ? ` · ${status.model}` : ""}</Pill>
          : <Pill tone="neutral" round dot>Switched off</Pill>)}
      </PageHead>
      <div className="grid cols-chat">

        {off ? (
          <section className="card" aria-labelledby="assistant-off">
            <h2 id="assistant-off">The assistant is switched off</h2>
            <p>{status!.reason}</p>
            <p className="muted" style={{ margin: 0 }}>
              Everything else in the SOC works without it. See docs/soc.md to turn it on. Past conversations
              on the left can still be read.
            </p>
            {bubbles.length > 0 && <ChatLog bubbles={bubbles} busy={false} />}
          </section>
        ) : (
        <section className="card chat" aria-labelledby="chat-title">
          <h2 id="chat-title" className="sr-only">Conversation</h2>
          <div className="sr-only" role="status" aria-live="polite">{announce}</div>
          {bubbles.length === 0 ? (
              <div className="muted">
                <p>Ask about alerts, attackers, blocks, cases or metrics, or open an alert and choose
                  “Explain this alert”. The assistant reads SOC data through fixed tools. It can only
                  <b> propose</b> a block: you confirm it in the action queue on the Response page.</p>
                <div className="row-actions">
                  {SUGGESTIONS.map((s) => <button key={s} onClick={() => void send(s)} disabled={busy}>{s}</button>)}
                </div>
              </div>
          ) : <ChatLog bubbles={bubbles} busy={busy} />}
          <ErrorText error={error} />
          <form className="chat-input" onSubmit={submit}>
            <label className="field" style={{ flex: 1 }}>Ask about alerts, blocks or cases
              <textarea value={input} maxLength={4000} rows={2}
                placeholder="e.g. Which hosts were scanned in the last hour?"
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(input); } }} />
            </label>
            {busy
              ? <button type="button" onClick={() => abort.current?.abort()}>Stop</button>
              : <button className="primary" disabled={!input.trim() || loading}>Send</button>}
          </form>
          <p className="muted small-text" style={{ margin: "8px 0 0" }}>
            The assistant reads SOC data through {Object.keys(TOOL_LABELS).length} fixed tools and can only propose a
            block; an analyst confirms it. Answers can be wrong: check the data before acting.
          </p>
        </section>
        )}
        <aside className="card stack chat-side" aria-label="Conversations and playbooks" style={{ gap: 10 }}>
          <h2 className="sr-only">Conversations</h2>
          {off
            ? <button onClick={newChat} disabled={bubbles.length === 0 || loading}>Close conversation</button>
            : <button className="primary" onClick={newChat} disabled={busy || loading}>New conversation</button>}
          <ul className="conv-list">
            {(history ?? []).map((c) => (
              <li key={c.id}>
                <button className={`conv${c.id === conversationId ? " active" : ""}`}
                  aria-current={c.id === conversationId ? "true" : undefined}
                  onClick={() => void open(c.id)} disabled={busy || loading}>
                  <b className="conv-title">{c.title || `Conversation #${c.id}`}</b>
                  <span className="muted small-text">
                    {dateTime(c.updated_at)} · {c.user_turns} question{c.user_turns === 1 ? "" : "s"}
                  </span>
                </button>
              </li>
            ))}
          </ul>
          {history?.length === 0 && <p className="muted" style={{ margin: 0 }}>No conversations yet.</p>}
          <div className="playbooks">
            <h2 style={{ margin: "0 0 6px", fontSize: 15 }}>Playbooks</h2>
            <div className="row-actions" style={{ gap: 6 }}>
              {PLAYBOOKS.map((p) => (
                <button key={p.cls} type="button" className="small" disabled={busy || loading || off}
                  onClick={() => void send(`Summarise the playbook for "${p.cls}": how to confirm it and what to do.`)}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        </aside>
      </div>
    </>
  );
}

/** The conversation's messages: tool chips, text with links, proposal cards. Never renders HTML. */
function ChatLog({ bubbles, busy }: { bubbles: Bubble[]; busy: boolean }) {
  // The log scrolls itself: keep the newest message in view as replies stream in.
  const log = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = log.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [bubbles]);
  return (
    <div className="chat-log" ref={log} aria-busy={busy}>
      {bubbles.map((b, i) => (
        <div key={i} className={`bubble ${b.role}`}>
          {b.tools.length > 0 && (
            <div className="chat-tools" aria-label="Tools used">
              {b.tools.map((t, j) => (
                <span key={j} className={`chip${t.ok === false ? " bad" : ""}`}>
                  <span aria-hidden="true">{t.ok === undefined ? "…" : t.ok ? "✓" : "✗"} </span>
                  {t.ok === false && <span className="sr-only">failed: </span>}
                  {Object.hasOwn(TOOL_LABELS, t.name) ? TOOL_LABELS[t.name] : t.name}
                </span>
              ))}
            </div>
          )}
          <div className="bubble-text">
            {b.text ? <Linked text={b.text} /> : (busy && i === bubbles.length - 1 ? <span className="muted">Thinking…</span> : null)}
          </div>
          {b.actions.map((a) => (
            <div key={a.id} className="proposal">
              <span className="eyebrow">Proposed action · needs an analyst</span>
              <span style={{ fontWeight: 600 }}>Block <span className="mono">{a.ip}</span> (action #{a.id})</span>
              <span className="small-text">Nothing happens until an analyst confirms it.</span>
              <Link className="button-link" style={{ alignSelf: "flex-start" }} to="/response">Review in queue</Link>
            </div>
          ))}
          {b.error && <div className="error">{b.error}</div>}
        </div>
      ))}
    </div>
  );
}
