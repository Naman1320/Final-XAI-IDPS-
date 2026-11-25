import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { api } from "../api/client";
import C6 from "../pages/C6";

vi.mock("../api/client", () => ({ api: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("requires an online evidence worker to start a run", async () => {
  vi.mocked(api).mockResolvedValue({ enabled: true, worker_online: false, run: null });
  render(<C6 />);
  await screen.findByText(/C6 worker offline/);
  expect(screen.getByRole("button", { name: "Start C6 replay" })).toBeDisabled();
});

it("renders only received evidence after an admin starts a replay", async () => {
  const idle = { enabled: true, worker_online: true, demo_status: null, run: null };
  const run = { id: "example", status: "running", mode: "replay", started_at: "2026-01-02T10:00:00Z",
    events: [{ stage: "baseline", at: "2026-01-02T10:00:02Z", evidence: "No matching rule" }] };
  vi.mocked(api).mockResolvedValueOnce(idle).mockResolvedValueOnce(run)
    .mockResolvedValue({ ...idle, run });
  render(<C6 />);
  const start = screen.getByRole("button", { name: "Start C6 replay" });
  await waitFor(() => expect(start).toBeEnabled());
  fireEvent.click(start);
  await screen.findByText("No matching rule");
  expect(api).toHaveBeenCalledWith("/admin/c6/run", { method: "POST", json: { mode: "replay" } });
  expect(screen.getByText("2.0 s")).toBeInTheDocument();
  expect(screen.getByText("AWS CLI verification · no evidence")).toBeInTheDocument();
  expect(start).toBeDisabled();
});
