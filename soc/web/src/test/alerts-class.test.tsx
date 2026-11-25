import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Alerts from "../pages/Alerts";

const h = vi.hoisted(() => ({ api: vi.fn() }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../live", () => ({ useLiveStatus: () => false, useLiveAlerts: () => false, useLiveBlocks: () => false }));

beforeEach(() => {
  h.api.mockReset();
  h.api.mockResolvedValue({ items: [], total: 0, next_cursor: null });
});
const show = (url: string) => render(<MemoryRouter initialEntries={[url]}><Alerts /></MemoryRouter>);

describe("Alerts ?class=", () => {
  it("fills the class filter and requests with it", async () => {
    show("/alerts?class=PortScan");
    expect(screen.getByLabelText("Class")).toHaveValue("PortScan");
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    expect(String(h.api.mock.calls[0][0])).toContain("predicted_class=PortScan");
  });

  it("works together with ?ip=", async () => {
    show("/alerts?class=DoS&ip=1.2.3.4");
    expect(screen.getByLabelText("Class")).toHaveValue("DoS");
    expect(screen.getByLabelText("IP (source or destination)")).toHaveValue("1.2.3.4");
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    const p = String(h.api.mock.calls[0][0]);
    expect(p).toContain("predicted_class=DoS");
    expect(p).toContain("ip=1.2.3.4");
  });

  it("without ?class= the filter is empty and unfiltered", async () => {
    show("/alerts");
    expect(screen.getByLabelText("Class")).toHaveValue("");
    await waitFor(() => expect(h.api).toHaveBeenCalled());
    expect(String(h.api.mock.calls[0][0])).not.toContain("predicted_class");
    fireEvent.change(screen.getByLabelText("Class"), { target: { value: "x" } });
  });
});
