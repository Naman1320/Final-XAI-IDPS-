import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ApiError } from "../api/client";
import { ALL_PERMS, cloudApiFake, freshDb, renderCloud, type Db } from "./cloud-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), perms: undefined as string[] | undefined }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({
    me: { id: 1, username: "u", role: "admin", permissions: h.perms }, loading: false, logout: vi.fn(),
    can: (p: string) => Boolean(h.perms?.includes(p)),
  }),
}));

let db: Db;
beforeEach(() => {
  db = freshDb();
  h.perms = ALL_PERMS;
  h.api.mockReset();
  h.api.mockImplementation(cloudApiFake(db));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

import CloudAlertsBadge from "../components/cloud/CloudAlertsBadge";
import { MemoryRouter } from "react-router-dom";
import { render } from "@testing-library/react";

const disabled = (name: string | RegExp) => expect(screen.getByRole("button", { name })).toBeDisabled();

describe("cloud permissions (UI hints; the backend enforces)", () => {
  it("disables every write button for a user who only holds cloud.view", async () => {
    h.perms = ["cloud.view"];
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    disabled("Create instance");
    expect(screen.getByRole("button", { name: "Create instance" })).toHaveAttribute("title", "Needs the cloud.instances.write permission");
    cleanup();

    renderCloud("/cloud/storage");
    await screen.findByText("data-1");
    disabled("Create volume"); disabled("Create bucket");
    for (const b of screen.getAllByRole("button", { name: "Resize" })) expect(b).toBeDisabled();
    for (const b of screen.getAllByRole("switch")) expect(b).toBeDisabled();
    cleanup();

    renderCloud("/cloud/network");
    await screen.findByText("web", { selector: "td" });
    disabled("Create security group");
    cleanup();

    renderCloud("/cloud/alerts");
    await screen.findByText("CPU utilisation is high on web-1");
    disabled("Run evaluation");
    for (const b of screen.getAllByRole("button", { name: "Acknowledge" })) expect(b).toBeDisabled();
    cleanup();

    renderCloud("/cloud/compute/i-aaaa1111");
    await screen.findByRole("button", { name: "Stop" });
    for (const n of ["Start", "Stop", "Reboot", "Terminate", "Edit name and tags"]) disabled(n);
    // reading still works
    expect(await screen.findByText("CPU utilisation", { selector: "figcaption" })).toBeInTheDocument();
  });

  it("enables only the buttons that match the held permission", async () => {
    h.perms = ["cloud.view", "cloud.alerts.manage"];
    renderCloud("/cloud/alerts");
    await screen.findByText("CPU utilisation is high on web-1");
    expect(screen.getByRole("button", { name: "Run evaluation" })).toBeEnabled();
    cleanup();
    renderCloud("/cloud/storage");
    await screen.findByText("data-1");
    disabled("Create volume");
  });

  it("does not block a user whose permission list is missing (older SOC)", async () => {
    h.perms = undefined;
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    expect(screen.getByRole("button", { name: "Create instance" })).toBeEnabled();
  });

  it("is read-only when the data source is the emulator, whatever the permissions", async () => {
    db.source = { data_source: "emulated-aws", data_source_label: "Emulated AWS (local Moto, read-only)" };
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    await waitFor(() => expect(screen.getByRole("button", { name: "Create instance" })).toBeDisabled());
    expect(screen.getByRole("button", { name: "Create instance" })).toHaveAttribute("title", "Read-only: this data source cannot be changed");
  });

  it("shows the no-permission state on a section whose read is refused", async () => {
    db.override["GET /cloud/alerts"] = () => { throw new ApiError(403, "missing permission cloud.view"); };
    renderCloud("/cloud/alerts");
    expect(await screen.findByRole("heading", { name: "No permission" })).toBeInTheDocument();
    expect(screen.getByText("missing permission cloud.view")).toBeInTheDocument();
  });

  it("shows a backend 403 on a write (a deny policy on one resource) inside the dialog", async () => {
    renderCloud("/cloud/compute/i-aaaa1111");
    fireEvent.click(await screen.findByRole("button", { name: "Reboot" }));
    const dialog = await screen.findByRole("dialog");
    db.override["POST /cloud/instances/i-aaaa1111/reboot"] = () => { throw new ApiError(403, "a policy denies cloud.instances.write on instance:i-aaaa1111"); };
    fireEvent.click(within(dialog).getByRole("button", { name: "Reboot" }));
    expect(await within(dialog).findByText("No permission: a policy denies cloud.instances.write on instance:i-aaaa1111")).toBeInTheDocument();
  });
});

describe("CloudAlertsBadge", () => {
  const renderBadge = () => render(<MemoryRouter><CloudAlertsBadge pollMs={100000} /></MemoryRouter>);

  it("links to the alerts page with the open count and marks critical alerts in text", async () => {
    renderBadge();
    const link = await screen.findByRole("link", { name: /Cloud alerts: 1 open, 1 acknowledged, at least one critical/ });
    expect(link).toHaveAttribute("href", "/cloud/alerts");
    expect(link).toHaveTextContent("Cloud alerts 1");
  });

  it("renders nothing without cloud.view or after an error", async () => {
    h.perms = ["cloud.instances.write"];
    const { container } = renderBadge();
    await new Promise((r) => setTimeout(r, 20));
    expect(container).toBeEmptyDOMElement();
    expect(h.api).not.toHaveBeenCalled();
    cleanup();
    h.perms = ALL_PERMS;
    h.api.mockImplementation(async () => { throw new ApiError(500, "boom"); });
    const again = renderBadge();
    await new Promise((r) => setTimeout(r, 20));
    expect(again.container).toBeEmptyDOMElement();
  });
});
