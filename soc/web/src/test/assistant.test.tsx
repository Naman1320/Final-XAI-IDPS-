import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import Assistant from "../pages/Assistant";

const h = vi.hoisted(() => ({ api: vi.fn(), stream: vi.fn() }));
vi.mock("../api/client", async (orig) => ({
  ...(await orig<typeof import("../api/client")>()), api: h.api, streamNdjson: h.stream,
}));

type Ev = Record<string, unknown>;
let status: Record<string, unknown>;
let history: Record<string, unknown>[];
let convs: Record<string, Record<string, unknown>>;
let ctl: { emit: (e: Ev) => void; end: () => void; fail: (e: unknown) => void; signal?: AbortSignal };

const calls = (prefix: string) => h.api.mock.calls.filter(([p]) => String(p) === prefix);
const summary = (o: Record<string, unknown> = {}) => ({
  id: 1, title: "Scan chat", user_turns: 2, updated_at: "2026-01-05T10:00:00Z", ...o,
});

/** A stream the test drives by hand. */
function controlled() {
  h.stream.mockImplementation((_p: string, _j: unknown, onEvent: (e: Ev) => void, signal?: AbortSignal) =>
    new Promise<void>((res, rej) => {
      ctl = { emit: (e) => act(() => onEvent(e)), end: () => act(() => res()), fail: (e) => act(() => rej(e)), signal };
      signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
    }));
}
/** A stream that plays the events and ends. */
function scripted(events: Ev[]) {
  h.stream.mockImplementation(async (_p: string, _j: unknown, onEvent: (e: Ev) => void) => {
    for (const e of events) onEvent(e);
  });
}

beforeEach(() => {
  status = { enabled: true, model: "claude-x", reason: null };
  history = [];
  convs = {};
  h.api.mockReset();
  h.stream.mockReset();
  h.api.mockImplementation(async (path: string) => {
    if (path === "/assistant/status") return status;
    if (path === "/assistant/conversations") return history;
    const m = /^\/assistant\/conversations\/(\d+)$/.exec(path);
    if (m) return convs[m[1]];
    throw new Error(`unexpected ${path}`);
  });
  scripted([]);
});

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname + l.search}</div>; }
const show = (url = "/assistant") => render(<MemoryRouter initialEntries={[url]}><Assistant /><Loc /></MemoryRouter>);
const box = () => screen.getByLabelText("Ask about alerts, blocks or cases");
const ask = (text: string) => {
  fireEvent.change(box(), { target: { value: text } });
  fireEvent.keyDown(box(), { key: "Enter" });
};
const ready = () => screen.findByText(/^On/);
const sentMessages = () => h.stream.mock.calls.map(([, j]) => (j as { message: string }).message);

describe("header and status", () => {
  it("shows the heading and the On pill with the model", async () => {
    show();
    expect(screen.getByRole("heading", { level: 1, name: "SOC assistant" })).toBeInTheDocument();
    expect(await screen.findByText("On · claude-x")).toBeInTheDocument();
  });
  it("shows Switched off when disabled", async () => {
    status = { enabled: false, model: null, reason: "No API key" };
    show();
    expect(await screen.findByText("Switched off")).toBeInTheDocument();
  });
});

describe("switched off", () => {
  beforeEach(() => {
    status = { enabled: false, model: null, reason: "No API key is configured" };
    history = [summary()];
    convs["1"] = { ...summary(), messages: [
      { role: "user", text: "old question", tools: [] },
      { role: "assistant", text: "old answer", tools: ["top_attackers"] },
    ] };
  });
  it("explains why, disables the buttons and offers no input", async () => {
    show();
    const sec = (await screen.findByRole("heading", { name: "The assistant is switched off" })).closest("section")!;
    expect(within(sec).getByText("No API key is configured")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close conversation" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "New conversation" })).toBeNull();
    for (const n of ["port scan", "brute force", "DoS", "web attack", "bot", "infiltration", "Heartbleed"]) {
      expect(screen.getByRole("button", { name: n })).toBeDisabled();
    }
    expect(screen.queryByLabelText("Ask about alerts, blocks or cases")).toBeNull();
  });
  it("past conversations can still be read", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: /Scan chat/ }));
    expect(await screen.findByText("old answer")).toBeInTheDocument();
    expect(screen.getByText("old question")).toBeInTheDocument();
    expect(screen.getByText("looked up top attackers")).toBeInTheDocument();
    expect(screen.queryByLabelText("Ask about alerts, blocks or cases")).toBeNull();
    expect(h.api.mock.calls.some(([p]) => p === "/assistant/conversations/1")).toBe(true);
  });
  it("Close conversation clears the opened log back to the off message", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: /Scan chat/ }));
    await screen.findByText("old answer");
    const close = screen.getByRole("button", { name: "Close conversation" });
    expect(close).toBeEnabled();
    fireEvent.click(close);
    expect(screen.queryByText("old answer")).toBeNull();
    expect(screen.getByRole("heading", { name: "The assistant is switched off" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close conversation" })).toBeDisabled();
  });
  it("does not send an ?alert= request", async () => {
    show("/assistant?alert=12");
    await screen.findByText("Switched off");
    await act(async () => {});
    expect(h.stream).not.toHaveBeenCalled();
  });
});

describe("conversation list", () => {
  it("shows title or fallback, date, and singular/plural questions", async () => {
    history = [summary({ id: 1, title: "Scan chat", user_turns: 2 }), summary({ id: 2, title: "", user_turns: 1 })];
    show();
    expect(await screen.findByText("Scan chat")).toBeInTheDocument();
    expect(screen.getByText("Conversation #2")).toBeInTheDocument();
    expect(screen.getByText(/· 2 questions$/)).toBeInTheDocument();
    expect(screen.getByText(/· 1 question$/)).toBeInTheDocument();
    expect(screen.getAllByText(/2026/).length).toBe(2);
  });
  it("says so when empty", async () => {
    show();
    expect(await screen.findByText("No conversations yet.")).toBeInTheDocument();
  });
  it("opens a conversation, marks it current and shows tool chips", async () => {
    history = [summary(), summary({ id: 2, title: "Other" })];
    convs["1"] = { ...summary(), messages: [
      { role: "user", text: "hi", tools: [] },
      { role: "assistant", text: "hello there", tools: ["search_alerts", "mystery_tool"] },
    ] };
    show();
    const item = (await screen.findByRole("button", { name: /Scan chat/ }));
    expect(item).not.toHaveAttribute("aria-current");
    fireEvent.click(item);
    expect(await screen.findByText("hello there")).toBeInTheDocument();
    expect(h.api.mock.calls.some(([p]) => p === "/assistant/conversations/1")).toBe(true);
    expect(item).toHaveAttribute("aria-current", "true");
    expect(item).toHaveClass("active");
    expect(screen.getByRole("button", { name: /Other/ })).not.toHaveAttribute("aria-current");
    const chip = screen.getByText("searched alerts");
    expect(chip.textContent).toContain("✓");
    expect(screen.getByText("mystery_tool")).toBeInTheDocument();
  });
  it("shows a load error", async () => {
    history = [summary()];
    h.api.mockImplementation(async (p: string) => {
      if (p === "/assistant/status") return status;
      if (p === "/assistant/conversations") return history;
      throw new Error("cannot open");
    });
    show();
    fireEvent.click(await screen.findByRole("button", { name: /Scan chat/ }));
    expect(await screen.findByText("cannot open")).toBeInTheDocument();
  });
  it("New conversation clears the log", async () => {
    scripted([{ type: "text", text: "an answer" }]);
    show();
    await ready();
    ask("q");
    await screen.findByText("an answer");
    // The text shows up while the reply is still "busy"; New conversation is disabled until the
    // stream's finally block has run, so wait for it (clicking earlier is ignored, which made
    // this test fail now and then).
    const btn = screen.getByRole("button", { name: "New conversation" });
    await waitFor(() => expect(btn).toBeEnabled());
    fireEvent.click(btn);
    expect(screen.queryByText("an answer")).toBeNull();
  });
  it("New conversation is disabled while a reply streams and clears the log once it ends", async () => {
    controlled();
    show();
    await ready();
    ask("q");
    await waitFor(() => expect(h.stream).toHaveBeenCalledTimes(1));
    ctl.emit({ type: "text", text: "partial" });
    expect(await screen.findByText("partial")).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: "New conversation" });
    expect(btn).toBeDisabled();
    fireEvent.click(btn); // ignored while busy
    expect(screen.getByText("partial")).toBeInTheDocument();
    ctl.end();
    await waitFor(() => expect(btn).toBeEnabled());
    fireEvent.click(btn);
    expect(screen.queryByText("partial")).toBeNull();
  });
});

describe("sending", () => {
  it("has the suggestions and a labelled textarea", async () => {
    show();
    await ready();
    expect(box().tagName).toBe("TEXTAREA");
    expect(screen.getByRole("button", { name: "Who were the top attackers in the last 24 hours?" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send" })).toBeDisabled();
  });
  it("a suggestion sends its text", async () => {
    show();
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Summarise today's critical and high alerts." }));
    await waitFor(() => expect(sentMessages()).toEqual(["Summarise today's critical and high alerts."]));
  });
  it("Enter sends, trimmed and without a conversation id; the box clears", async () => {
    show();
    await ready();
    ask("  what happened?  ");
    await waitFor(() => expect(h.stream).toHaveBeenCalledTimes(1));
    const [path, json] = h.stream.mock.calls[0];
    expect(path).toBe("/assistant/chat");
    expect(json).toEqual({ message: "what happened?" });
    expect(box()).toHaveValue("");
    expect(await screen.findByText("what happened?")).toBeInTheDocument();
  });
  it("Shift+Enter does not send; Enter on blank does not either", async () => {
    show();
    await ready();
    fireEvent.change(box(), { target: { value: "line" } });
    fireEvent.keyDown(box(), { key: "Enter", shiftKey: true });
    expect(h.stream).not.toHaveBeenCalled();
    fireEvent.change(box(), { target: { value: "   " } });
    fireEvent.keyDown(box(), { key: "Enter" });
    expect(h.stream).not.toHaveBeenCalled();
  });
  it("the Send button submits", async () => {
    show();
    await ready();
    fireEvent.change(box(), { target: { value: "via button" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(sentMessages()).toEqual(["via button"]));
  });
  it("while busy Stop replaces Send and aborts; no error is shown", async () => {
    controlled();
    show();
    await ready();
    ask("long one");
    const stop = await screen.findByRole("button", { name: "Stop" });
    expect(screen.queryByRole("button", { name: "Send" })).toBeNull();
    expect(screen.getByRole("button", { name: "New conversation" })).toBeDisabled();
    expect(ctl.signal!.aborted).toBe(false);
    fireEvent.click(stop);
    expect(ctl.signal!.aborted).toBe(true);
    expect(await screen.findByRole("button", { name: "Send" })).toBeInTheDocument();
    expect(screen.queryByText("Can't reach the SOC API")).toBeNull();
  });
  it("shows Thinking… until text arrives", async () => {
    controlled();
    show();
    await ready();
    ask("q");
    expect(await screen.findByText("Thinking…")).toBeInTheDocument();
    ctl.emit({ type: "text", text: "done" });
    expect(screen.queryByText("Thinking…")).toBeNull();
    ctl.end();
  });
  it("reloads the conversation list after a reply and keeps the conversation id for the next question", async () => {
    scripted([{ type: "conversation", conversation_id: 4 }, { type: "text", text: "ok" }]);
    show();
    await ready();
    await waitFor(() => expect(calls("/assistant/conversations").length).toBe(1));
    history = [summary({ id: 4, title: "New one" })];
    ask("first");
    await waitFor(() => expect(calls("/assistant/conversations").length).toBe(2));
    const item = await screen.findByRole("button", { name: /New one/ });
    expect(item).toHaveAttribute("aria-current", "true");
    ask("second");
    await waitFor(() => expect(h.stream).toHaveBeenCalledTimes(2));
    expect(h.stream.mock.calls[1][1]).toEqual({ message: "second", conversation_id: 4 });
  });
});

describe("stream rendering", () => {
  it("tool chips go from … to ✓ or ✗ and unknown names show as is", async () => {
    controlled();
    show();
    await ready();
    ask("q");
    await screen.findByText("Thinking…");
    ctl.emit({ type: "tool", name: "top_attackers" });
    ctl.emit({ type: "tool", name: "weird_tool" });
    const chip = screen.getByText("looked up top attackers");
    expect(chip.textContent).toMatch(/^… /);
    ctl.emit({ type: "tool_result", name: "top_attackers", ok: true });
    expect(chip.textContent).toMatch(/^✓ /);
    expect(chip).not.toHaveClass("bad");
    ctl.emit({ type: "tool_result", name: "weird_tool", ok: false });
    const bad = screen.getByText("weird_tool");
    expect(bad).toHaveClass("bad");
    expect(bad.textContent).toContain("✗");
    expect(within(bad).getByText("failed:")).toHaveClass("sr-only");
    expect(within(chip).queryByText("failed:")).toBeNull();
    ctl.end();
  });

  it("streams text and links alert, case and action ids", async () => {
    controlled();
    show();
    await ready();
    ask("q");
    await screen.findByText("Thinking…");
    ctl.emit({ type: "text", text: "See alert #3 and " });
    ctl.emit({ type: "text", text: "case #2, then Action #5." });
    expect(screen.getByRole("link", { name: "alert #3" })).toHaveAttribute("href", "/alerts/3");
    expect(screen.getByRole("link", { name: "case #2" })).toHaveAttribute("href", "/cases/2");
    expect(screen.getByRole("link", { name: "Action #5" })).toHaveAttribute("href", "/response");
    ctl.end();
  });

  it("renders a proposal card", async () => {
    scripted([{ type: "text", text: "I suggest a block." }, { type: "action_proposed", action_id: 5, ip: "10.0.0.9" }]);
    show();
    await ready();
    ask("q");
    expect(await screen.findByText("Proposed action · needs an analyst")).toBeInTheDocument();
    expect(screen.getByText(/^Block/, { selector: "span" })).toHaveTextContent("Block 10.0.0.9 (action #5)");
    expect(screen.getByRole("link", { name: "Review in queue" })).toHaveAttribute("href", "/response");
    expect(screen.getByText("Nothing happens until an analyst confirms it.")).toBeInTheDocument();
  });

  it("shows an error event", async () => {
    scripted([{ type: "error", message: "model overloaded" }]);
    show();
    await ready();
    ask("q");
    expect(await screen.findByText("model overloaded")).toBeInTheDocument();
  });

  it("a network failure keeps a partial reply", async () => {
    controlled();
    show();
    await ready();
    ask("q");
    await screen.findByText("Thinking…");
    ctl.emit({ type: "text", text: "partial answer" });
    ctl.fail(new Error("boom"));
    expect(await screen.findByText("Can't reach the SOC API")).toBeInTheDocument();
    expect(screen.getByText("partial answer")).toBeInTheDocument();
  });

  it("a failure with nothing received drops the empty bubble", async () => {
    h.stream.mockRejectedValue(new Error("boom"));
    const { container } = show();
    await ready();
    ask("q");
    expect(await screen.findByText("Can't reach the SOC API")).toBeInTheDocument();
    expect(container.querySelectorAll(".bubble.user").length).toBe(1);
    expect(container.querySelectorAll(".bubble.assistant").length).toBe(0);
  });

  it("an API error shows its message", async () => {
    const { ApiError } = await import("../api/client");
    h.stream.mockRejectedValue(new ApiError(429, "slow down"));
    show();
    await ready();
    ask("q");
    expect(await screen.findByText("slow down")).toBeInTheDocument();
  });
});

describe("playbooks", () => {
  it.each([
    ["port scan", "PortScan"], ["brute force", "brute force"], ["DoS", "DoS"], ["web attack", "Web Attack"],
    ["bot", "Bot"], ["infiltration", "Infiltration"], ["Heartbleed", "Heartbleed"],
  ])("%s sends the %s playbook request", async (name, cls) => {
    show();
    await ready();
    fireEvent.click(screen.getByRole("button", { name }));
    await waitFor(() => expect(sentMessages()).toEqual([`Summarise the playbook for "${cls}": how to confirm it and what to do.`]));
  });
});

describe("?alert=", () => {
  it("?alert=12 asks once and clears the query", async () => {
    show("/assistant?alert=12");
    await waitFor(() => expect(h.stream).toHaveBeenCalledTimes(1));
    expect(h.stream.mock.calls[0][1]).toEqual({
      message: "Explain alert #12: why was it raised (by the model or a Suricata rule), is it likely a real attack, and what should I do?",
    });
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/assistant"));
    await act(async () => {});
    expect(h.stream).toHaveBeenCalledTimes(1);
  });
  it.each(["abc", "1x", "", "1234567890123"])("?alert=%j sends nothing", async (v) => {
    show(`/assistant?alert=${v}`);
    await ready();
    await act(async () => {});
    expect(h.stream).not.toHaveBeenCalled();
  });
});

describe("layout and screen-reader output", () => {
  it("the chat section comes before the aside and both are labelled", async () => {
    show();
    await ready();
    const chat = screen.getByRole("region", { name: "Conversation" });
    const aside = screen.getByRole("complementary", { name: "Conversations and playbooks" });
    expect(chat.compareDocumentPosition(aside) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(chat.querySelector("h2.sr-only")).toHaveTextContent("Conversation");
    expect(screen.getAllByRole("heading", { level: 2 }).map((e) => e.textContent))
      .toEqual(["Conversation", "Conversations", "Playbooks"]);
  });
  it("the off message also comes before the aside", async () => {
    status = { enabled: false, model: null, reason: "r" };
    show();
    const off = (await screen.findByRole("heading", { name: "The assistant is switched off" })).closest("section")!;
    const aside = screen.getByRole("complementary", { name: "Conversations and playbooks" });
    expect(off.compareDocumentPosition(aside) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
  it("the log is not a live region; aria-busy follows the reply; a status region announces start and end", async () => {
    controlled();
    const { container } = show();
    await ready();
    const status = screen.getByRole("status");
    expect(status).toBeEmptyDOMElement();
    expect(status).toHaveClass("sr-only");
    ask("q");
    await screen.findByText("Thinking…");
    const log = container.querySelector(".chat-log")!;
    expect(log).not.toHaveAttribute("aria-live");
    expect(log).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent("The assistant is replying…");
    ctl.emit({ type: "text", text: "hello" });
    expect(status).toHaveTextContent("The assistant is replying…");
    ctl.end();
    await waitFor(() => expect(status).toHaveTextContent("Reply finished."));
    expect(container.querySelector(".chat-log")).toHaveAttribute("aria-busy", "false");
  });
});

describe("auto-scroll", () => {
  const sets: { el: HTMLElement; v: number }[] = [];
  beforeEach(() => {
    sets.length = 0;
    Object.defineProperty(HTMLElement.prototype, "scrollHeight", {
      configurable: true, get() { return (this as HTMLElement).classList.contains("chat-log") ? 777 : 0; },
    });
    Object.defineProperty(HTMLElement.prototype, "scrollTop", {
      configurable: true, get() { return sets.filter((x) => x.el === this).at(-1)?.v ?? 0; },
      set(v: number) { sets.push({ el: this as HTMLElement, v }); },
    });
  });
  afterEach(() => {
    delete (HTMLElement.prototype as { scrollHeight?: unknown }).scrollHeight;
    delete (HTMLElement.prototype as { scrollTop?: unknown }).scrollTop;
  });
  it("scrolls the log to the bottom when bubbles change", async () => {
    controlled();
    const { container } = show();
    await ready();
    ask("q");
    await screen.findByText("Thinking…");
    const log = container.querySelector<HTMLElement>(".chat-log")!;
    expect(log.scrollTop).toBe(777);
    const before = sets.length;
    ctl.emit({ type: "text", text: "more" });
    expect(sets.length).toBeGreaterThan(before);
    expect(log.scrollTop).toBe(777);
    ctl.end();
  });
});

describe("loading a conversation", () => {
  it("disables sending and the other buttons until it resolves", async () => {
    history = [summary(), summary({ id: 2, title: "Other" })];
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    convs["1"] = { ...summary(), messages: [{ role: "assistant", text: "loaded text", tools: [] }] };
    h.api.mockImplementation(async (path: string) => {
      if (path === "/assistant/status") return status;
      if (path === "/assistant/conversations") return history;
      if (path === "/assistant/conversations/1") { await gate; return convs["1"]; }
      throw new Error(`unexpected ${path}`);
    });
    show();
    const item = await screen.findByRole("button", { name: /Scan chat/ });
    fireEvent.click(item);
    await waitFor(() => expect(screen.getByRole("button", { name: "New conversation" })).toBeDisabled());
    expect(screen.getByRole("button", { name: /Scan chat/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Other/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: "port scan" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Who were the top attackers in the last 24 hours?" })).toBeEnabled();
    fireEvent.change(box(), { target: { value: "typed meanwhile" } });
    expect(screen.getByRole("button", { name: "Send" })).toBeDisabled();
    fireEvent.keyDown(box(), { key: "Enter" });
    expect(h.stream).not.toHaveBeenCalled();
    release();
    expect(await screen.findByText("loaded text")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New conversation" })).toBeEnabled();
    expect(screen.getByRole("button", { name: /Other/ })).toBeEnabled();
    expect(screen.getByRole("button", { name: "port scan" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Send" })).toBeEnabled();
  });
});

describe("footnote and safety", () => {
  it("mentions 8 fixed tools", async () => {
    show();
    await ready();
    expect(screen.getByText(/reads SOC data through 8 fixed tools/)).toBeInTheDocument();
  });

  it("renders model text, titles, IPs and messages as text, never HTML", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    history = [summary({ title: evil })];
    scripted([
      { type: "text", text: `${evil} alert #3` },
      { type: "action_proposed", action_id: 5, ip: evil },
      { type: "error", message: evil },
    ]);
    const { container } = show();
    await screen.findByText(evil, { selector: "b" });
    ask("q");
    await screen.findByText("Proposed action · needs an analyst");
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(`${evil} alert #3`);
    expect(container.querySelector(".proposal .mono")?.textContent).toBe(evil);
    expect(container.querySelector(".bubble .error")?.textContent).toBe(evil);
  });
});
