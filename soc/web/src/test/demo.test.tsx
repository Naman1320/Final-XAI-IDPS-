import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ApiError } from "../api/client";
import type { DemoRun, DemoState } from "../api/types";
import Demo, { ACTIVE_POLL_MS, elapsed, IDLE_POLL_MS, runBlocker, STEP_HINTS } from "../pages/Demo";
import { workspace } from "../workspace";
import { report, sensorState, sensorsStatus } from "./sensor-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), role: "admin" }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: { id: 1, username: "u", role: h.role }, loading: false, logout: vi.fn() }),
}));

const STEPS = [
  ["portscan", "Port scan (nmap)"], ["ssh_bruteforce", "SSH brute force (hydra)"],
  ["syn_flood", "SYN flood (hping3)"], ["settle", "Wait for flows to end (about 150 s)"],
] as const;

function makeRun(status: DemoRun["status"], stepStatus: DemoRun["steps"][number]["status"][]): DemoRun {
  return {
    id: "6f1c", status, requested_by: "admin", requested_at: "2026-11-18T10:00:00Z", finished_at: null,
    steps: STEPS.map(([key, label], i) => ({
      key, label, status: stepStatus[i] ?? "pending",
      started_at: ["running", "done", "failed"].includes(stepStatus[i] ?? "") ? "2026-11-18T10:00:00Z" : null,
      ended_at: ["done", "failed"].includes(stepStatus[i] ?? "") ? "2026-11-18T10:01:05Z" : null,
      note: stepStatus[i] === "failed" ? "hydra exited 255" : "",
    })),
  };
}

let state: DemoState;
let postImpl: (path: string) => Promise<unknown>;

beforeEach(() => {
  h.role = "admin";
  state = { enabled: true, runner_online: true, run: null };
  postImpl = async () => makeRun("queued", []);
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string }) => {
    if (opts?.method === "POST") return postImpl(path);
    if (path === "/demo") return structuredClone(state);
    throw new Error(`unexpected ${path}`);
  });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

const renderPage = () => render(<MemoryRouter><Demo /></MemoryRouter>);
const runButton = () => screen.getByRole("button", { name: "Run demo" });
const posts = () => h.api.mock.calls.filter(([, o]) => o?.method === "POST").map(([p]) => p);

describe("Live demo page", () => {
  it("shows live sensor activity and the classroom replay route in the lab workspace", async () => {
    const originalLab = workspace.lab;
    workspace.lab = true;
    try {
      h.api.mockImplementation(async (path: string) => {
        if (path === "/demo") return state;
        if (path === "/sensors/status") return sensorsStatus([
          sensorState({ name: "Classroom sensor", status: report({ counters: { flows: 42, alerts: 3, blocked: 0, would_block: 2 } }) }),
          sensorState({ sensor_id: 2, name: "Replay sensor", status: report({ mode: "replay" }) }),
        ]);
        throw new Error("Unexpected route");
      });
      render(<MemoryRouter basename="/lab" initialEntries={["/lab/demo"]}><Demo /></MemoryRouter>);
      expect(await screen.findByRole("rowheader", { name: "Classroom sensor" })).toBeInTheDocument();
      expect(screen.getByRole("cell", { name: "42" })).toBeInTheDocument();
      expect(screen.queryByText("Replay sensor")).toBeNull();
      expect(screen.getByRole("link", { name: "Open C6 replay" })).toHaveAttribute("href", "/lab/c6");
    } finally {
      workspace.lab = originalLab;
    }
  });

  it("enables Run demo for an admin when the runner is online and nothing runs", async () => {
    renderPage();
    await screen.findByText("Runner online");
    expect(runButton()).toBeEnabled();
    expect(screen.getByText("No demo has run since the SOC started.")).toBeInTheDocument();
    fireEvent.click(runButton());
    await waitFor(() => expect(posts()).toEqual(["/admin/demo/run"]));
  });

  it("disables Run demo with the reason when the runner is offline", async () => {
    state.runner_online = false;
    renderPage();
    await screen.findByText("Runner offline");
    expect(runButton()).toBeDisabled();
    expect(runButton()).toHaveAccessibleDescription(/demo runner is offline/);
    expect(screen.getByText("The demo runner is offline.")).toBeInTheDocument();
  });

  it("says plainly when demo mode is off", async () => {
    state = { enabled: false, runner_online: false, run: null };
    renderPage();
    expect(await screen.findByText("Demo mode is off.")).toBeInTheDocument();
    expect(screen.getByText("Demo mode off")).toBeInTheDocument();
    expect(runButton()).toBeDisabled();
    expect(runButton()).toHaveAccessibleDescription(/IDPS_SOC_DEMO_TOKEN/);
  });

  it("disables Run demo while a run is active and offers Cancel", async () => {
    state.run = makeRun("running", ["done", "running"]);
    postImpl = async () => makeRun("cancelled", ["done", "skipped", "skipped", "skipped"]);
    renderPage();
    await screen.findByRole("button", { name: "Cancel run" });
    expect(screen.getByText("Run status:").nextElementSibling).toHaveTextContent("Running");
    expect(runButton()).toBeDisabled();
    expect(runButton()).toHaveAccessibleDescription(/already in progress/);
    fireEvent.click(screen.getByRole("button", { name: "Cancel run" }));
    await waitFor(() => expect(posts()).toEqual(["/admin/demo/cancel"]));
  });

  it("hides the admin buttons from analysts but shows the steps", async () => {
    h.role = "analyst";
    state.run = makeRun("running", ["running"]);
    renderPage();
    await screen.findByText("Port scan (nmap)");
    expect(screen.queryByRole("button", { name: "Run demo" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel run" })).toBeNull();
    expect(screen.getAllByRole("listitem")).toHaveLength(4);
  });

  it("renders every step with a text status chip, timing, note and a what-to-show hint", async () => {
    state.run = { ...makeRun("failed", ["done", "failed", "skipped", "skipped"]), finished_at: "2026-11-18T10:02:00Z" };
    renderPage();
    const items = await screen.findAllByRole("listitem");
    expect(items.map((li) => within(li).getByText(/Pending|Running|Done|Failed|Skipped/, { selector: ".pill" }).textContent?.trim()))
      .toEqual(["✓ Done", "✕ Failed", "– Skipped", "– Skipped"]);
    expect(items[0]).toHaveTextContent("took 1:05");
    expect(items[1]).toHaveTextContent("hydra exited 255");
    expect(items[2]).not.toHaveTextContent("took");
    for (const [i, [key]] of STEPS.entries()) expect(items[i]).toHaveTextContent(STEP_HINTS[key]);
    expect(items[0]).toHaveTextContent(/SHAP explanation/);
    expect(screen.getByText("Run status:").nextElementSibling).toHaveTextContent("Failed");
    expect(screen.getByText(/elapsed 2:00/)).toBeInTheDocument();
  });

  it("marks the running step for assistive technology", async () => {
    state.run = makeRun("running", ["done", "running"]);
    renderPage();
    const items = await screen.findAllByRole("listitem");
    expect(items[1]).toHaveAttribute("aria-current", "step");
    expect(items[0]).not.toHaveAttribute("aria-current");
    expect(items[1]).toHaveTextContent(/running for \d+:\d\d/);
  });

  it("shows the SOC's refusal", async () => {
    postImpl = async () => { throw new ApiError(409, "demo runner is not running"); };
    renderPage();
    await screen.findByText("Runner online");
    fireEvent.click(runButton());
    expect(await screen.findByRole("alert")).toHaveTextContent("demo runner is not running");
  });

  it("keeps Run demo disabled from the click until the reload has finished (no double start)", async () => {
    renderPage();
    await screen.findByText("Runner online");
    let release: () => void = () => {};
    const gate = new Promise<void>((res) => { release = res; });
    const plainGet = h.api.getMockImplementation()!;
    postImpl = async () => {
      // from now on the reload after the POST waits for `gate`
      h.api.mockImplementation(async (path: string, opts?: { method?: string }) => {
        if (opts?.method !== "POST" && path === "/demo") { await gate; return structuredClone(state); }
        return plainGet(path, opts);
      });
      return makeRun("queued", []);
    };
    fireEvent.click(runButton());
    await waitFor(() => expect(posts()).toEqual(["/admin/demo/run"]));
    await waitFor(() => expect(screen.getByRole("button", { name: /Starting/ })).toBeDisabled());
    fireEvent.click(screen.getByRole("button", { name: /Starting/ }));
    expect(posts()).toEqual(["/admin/demo/run"]);
    state.run = makeRun("queued", []);
    release();
    await screen.findByRole("button", { name: "Cancel run" });
    expect(screen.getByRole("button", { name: "Cancel run" })).toBeEnabled();
    expect(posts()).toEqual(["/admin/demo/run"]);
  });

  it("announces only status chips; the per-second timers are outside any live region", async () => {
    state.run = makeRun("running", ["done", "running"]);
    const { container } = renderPage();
    await screen.findAllByRole("listitem");
    const timers = [screen.getByText(/elapsed \d+:\d\d/), screen.getByText(/running for \d+:\d\d/),
      screen.getByText(/took \d+:\d\d/)];
    for (const t of timers) expect(t.closest("[aria-live]")).toBeNull();
    const live = Array.from(container.querySelectorAll("[aria-live]"));
    expect(live).toHaveLength(5); // the run status and the four step chips
    for (const el of live) {
      expect(el.querySelector(".pill")).not.toBeNull();
      expect(el.textContent).not.toMatch(/\d+:\d\d/);
    }
    expect(live[0]).toHaveTextContent("Running");
  });

  it("polls every 2 s while a run is active, every 10 s otherwise", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    state.run = makeRun("running", ["running"]);
    renderPage();
    await screen.findByText("Port scan (nmap)");
    const gets = () => h.api.mock.calls.filter(([p]) => p === "/demo").length;
    const before = gets();
    await act(async () => { await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS * 3); });
    expect(gets() - before).toBeGreaterThanOrEqual(3);

    state.run = makeRun("done", ["done", "done", "done", "done"]);
    await act(async () => { await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS); });
    await screen.findByText("Finished");
    const idle = gets();
    await act(async () => { await vi.advanceTimersByTimeAsync(IDLE_POLL_MS - 500); });
    expect(gets()).toBe(idle);
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(gets()).toBe(idle + 1);
  });
});

describe("demo helpers", () => {
  it("formats elapsed time", () => {
    const now = Date.parse("2026-11-18T11:02:03Z");
    expect(elapsed(null, null, now)).toBe("");
    expect(elapsed("2026-11-18T10:00:00Z", "2026-11-18T10:00:09Z", now)).toBe("0:09");
    expect(elapsed("2026-11-18T10:00:00Z", null, now)).toBe("1:02:03");
  });

  it("explains why a run can't start", () => {
    expect(runBlocker(null)).toMatch(/Loading/);
    expect(runBlocker({ enabled: true, runner_online: true, run: null })).toBeNull();
    expect(runBlocker({ enabled: true, runner_online: true, run: makeRun("done", []) })).toBeNull();
    expect(runBlocker({ enabled: true, runner_online: true, run: makeRun("queued", []) })).toMatch(/in progress/);
  });
});
