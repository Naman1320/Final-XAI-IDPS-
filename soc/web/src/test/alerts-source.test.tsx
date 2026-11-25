import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Alerts from "../pages/Alerts";

const h = vi.hoisted(() => ({ api: vi.fn(), onAlert: null as null | ((a: unknown) => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../live", () => ({
  useLiveStatus: () => false, useLiveBlocks: () => false,
  useLiveAlerts: (cb: (a: unknown) => void) => { h.onAlert = cb; return true; },
}));

const mk = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 1, predicted_class: "PortScan", confidence: 0.9, severity: "high", status: "new",
  src_ip: "10.0.0.1", src_port: 1000, dst_ip: "10.0.0.9", dst_port: 22, protocol: 6,
  received_at: new Date().toISOString(), ...o,
});
let items: unknown[];
beforeEach(() => {
  items = [];
  h.onAlert = null;
  h.api.mockReset();
  h.api.mockImplementation(async () => ({ items, total: items.length, next_cursor: null }));
});
const show = (url = "/alerts") => render(<MemoryRouter initialEntries={[url]}><Alerts /></MemoryRouter>);
const last = () => String(h.api.mock.calls[h.api.mock.calls.length - 1][0]);

describe("Alerts Raised by", () => {
  it("offers model or rule / model / Suricata rule", () => {
    show();
    const sel = screen.getByLabelText("Raised by");
    expect(within(sel).getAllByRole("option").map((o) => [o.getAttribute("value"), o.textContent])).toEqual([
      ["", "model or rule"], ["ml", "model"], ["rule", "Suricata rule"],
    ]);
  });

  it.each([["ml"], ["rule"]])("Apply sends source=%s", async (v) => {
    show();
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    fireEvent.change(screen.getByLabelText("Raised by"), { target: { value: v } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(last()).toContain(`source=${v}`));
  });

  it("sends no source when empty, including after clearing", async () => {
    show("/alerts?source=rule");
    await waitFor(() => expect(last()).toContain("source=rule"));
    fireEvent.change(screen.getByLabelText("Raised by"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(last()).not.toContain("source"));
  });

  it("takes its initial value from ?source=rule and requests with it", async () => {
    show("/alerts?source=rule");
    expect(screen.getByLabelText("Raised by")).toHaveValue("rule");
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    expect(String(h.api.mock.calls[0][0])).toContain("source=rule");
  });

  it("ignores an invalid ?source=", async () => {
    show("/alerts?source=bogus");
    expect(screen.getByLabelText("Raised by")).toHaveValue("");
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    expect(String(h.api.mock.calls[0][0])).not.toContain("source");
  });

  it("filters live alerts by source; a missing source counts as ml", async () => {
    show("/alerts?source=rule");
    await waitFor(() => expect(h.onAlert).not.toBeNull());
    await waitFor(() => expect(screen.queryByText("Loading…")).toBeNull());
    act(() => h.onAlert!(mk({ id: 11, predicted_class: "ViaModel" })));
    act(() => h.onAlert!(mk({ id: 12, predicted_class: "ViaMl", source: "ml" })));
    act(() => h.onAlert!(mk({ id: 13, predicted_class: "ViaRule", source: "rule" })));
    expect(await screen.findByText(/ViaRule/)).toBeInTheDocument();
    expect(screen.queryByText(/ViaModel/)).toBeNull();
    expect(screen.queryByText(/ViaMl/)).toBeNull();
  });

  it("with source=ml, a live alert without source is shown and a rule one is not", async () => {
    show("/alerts?source=ml");
    await waitFor(() => expect(h.onAlert).not.toBeNull());
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    act(() => h.onAlert!(mk({ id: 21, predicted_class: "NoSource" })));
    act(() => h.onAlert!(mk({ id: 22, predicted_class: "IsRule", source: "rule" })));
    expect(await screen.findByText(/NoSource/)).toBeInTheDocument();
    expect(screen.queryByText(/IsRule/)).toBeNull();
  });

  it("shows the rule tag in the class cell only for rule alerts", async () => {
    items = [mk({ id: 1, predicted_class: "Scan", source: "rule" }), mk({ id: 2, predicted_class: "DoS", source: "ml" }), mk({ id: 3, predicted_class: "Bot" })];
    show();
    await screen.findByText(/Scan/);
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText("rule")).toHaveClass("source-tag");
    expect(within(rows[1]).queryByText("rule")).toBeNull();
    expect(within(rows[2]).queryByText("rule")).toBeNull();
  });
});

describe("Alerts confidence cell", () => {
  it("is a dash for rule alerts and a percentage for model alerts", async () => {
    items = [mk({ id: 1, predicted_class: "Scan", source: "rule", confidence: 0.5 }), mk({ id: 2, predicted_class: "DoS", confidence: 0.9 })];
    show();
    await screen.findByText(/Scan/);
    const rows = screen.getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("—")).toBeInTheDocument();
    expect(within(rows[0]).queryByText(/%/)).toBeNull();
    expect(within(rows[1]).getByText(/%/)).toBeInTheDocument();
  });
});
