import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, login, makeApi, meWith, newWorld, renderIam, user, type World } from "./iam-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), me: {} as Record<string, unknown> }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: h.me, loading: false, logout: vi.fn(), can: (p: string) => (h.me.permissions as string[] | undefined)?.includes(p) ?? false }),
}));

let w: World;
beforeEach(() => {
  w = newWorld();
  h.me = meWith(ADMIN_PERMS);
  h.api.mockReset();
  h.api.mockImplementation(makeApi(w));
});

import { act, render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import IamModule from "../pages/iam";
import { ConfirmDialog, Modal, ToastProvider, useToast } from "../components/iam/ui";

const nav = () => within(screen.getByRole("navigation", { name: "Identity and access sections" }));

describe("IAM module navigation", () => {
  it("shows every section to a user who holds every permission", async () => {
    renderIam("/iam");
    await screen.findByRole("heading", { name: "Identity and access" });
    for (const name of ["Overview", "Users", "Roles", "Groups", "Policies", "Login history", "Audit log"]) {
      expect(nav().getByRole("link", { name })).toBeInTheDocument();
    }
    expect(nav().getByRole("link", { name: "Overview" })).toHaveAttribute("href", "/iam");
    expect(nav().getByRole("link", { name: "Users" })).toHaveAttribute("href", "/iam/users");
  });

  it("only shows the sections the user can view", async () => {
    h.me = meWith(["iam.users.view", "iam.audit.view"]);
    renderIam("/iam");
    await screen.findByRole("heading", { name: "Identity and access" });
    expect(nav().getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(nav().getByRole("link", { name: "Audit log" })).toBeInTheDocument();
    for (const name of ["Roles", "Groups", "Policies", "Login history"]) expect(nav().queryByRole("link", { name })).toBeNull();
  });

  it("explains an account with no IAM permissions, and makes no IAM calls", async () => {
    h.me = meWith(["cloud.view"]);
    renderIam("/iam");
    expect(await screen.findByText(/holds no IAM permissions/)).toBeInTheDocument();
    expect(h.api).not.toHaveBeenCalled();
  });

  it("works when the SOC sends no permissions list (everything shown, backend decides)", async () => {
    h.me = meWith(undefined);
    renderIam("/iam");
    await screen.findByRole("heading", { name: "Identity and access" });
    expect(nav().getByRole("link", { name: "Policies" })).toBeInTheDocument();
  });

  it("navigates between sections", async () => {
    renderIam("/iam");
    await screen.findByRole("heading", { name: "Identity and access" });
    fireEvent.click(nav().getByRole("link", { name: "Roles" }));
    expect(await screen.findByRole("heading", { name: "Roles", level: 1 })).toBeInTheDocument();
    fireEvent.click(nav().getByRole("link", { name: "Groups" }));
    expect(await screen.findByRole("heading", { name: "Groups", level: 1 })).toBeInTheDocument();
  });

  it("shows a not-found message for an unknown IAM page", async () => {
    renderIam("/iam/nowhere");
    expect(await screen.findByText("That IAM page does not exist.")).toBeInTheDocument();
  });

  it("builds its links from wherever the app mounts it", async () => {
    render(
      <MemoryRouter initialEntries={["/admin/access/users"]}>
        <Routes><Route path="/admin/access/*" element={<IamModule />} /></Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("link", { name: "alice" })).toHaveAttribute("href", "/admin/access/users/2");
    expect(nav().getByRole("link", { name: "Roles" })).toHaveAttribute("href", "/admin/access/roles");
  });
});

describe("IAM overview", () => {
  it("shows counts, MFA coverage, an admin warning and recent sign-ins", async () => {
    w.users.push(user({ id: 5, username: "carol", mfa_enabled: true }));
    w.users[0] = user({ id: 1, username: "root", role: "admin", mfa_enabled: false });
    w.logins = [login({ id: 1, username: "alice", ip: "10.7.7.7" })];
    renderIam("/iam");
    const glance = within(await screen.findByRole("region", { name: "At a glance" }));
    await waitFor(() => expect(glance.getByText("3 active, 1 deactivated")).toBeInTheDocument());
    expect(glance.getByText("1 of 3")).toBeInTheDocument(); // only carol has MFA among the 3 active
    expect(glance.getByText("33%")).toBeInTheDocument();
    expect(await screen.findByText(/1 active admin account\(s\) have no two-factor/)).toBeInTheDocument();
    expect(await screen.findByText("10.7.7.7")).toBeInTheDocument();
    expect(calls(h.api, "GET", "/iam/logins?limit=8")).toHaveLength(1);
  });

  it("marks a card that the backend refuses instead of failing the page", async () => {
    w.failures.push({ method: "GET", path: /^\/iam\/roles$/, status: 403, message: "missing permission" });
    renderIam("/iam");
    expect(await screen.findByText("No permission")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "All sign-ins" })).toBeInTheDocument();
  });

  it("offers shortcuts only to what the user can open", async () => {
    h.me = meWith(["iam.users.view", "iam.users.write"]);
    renderIam("/iam");
    const shortcuts = within(await screen.findByRole("region", { name: "Shortcuts" }));
    expect(shortcuts.getByRole("link", { name: "Manage users" })).toBeInTheDocument();
    expect(shortcuts.queryByRole("link", { name: "Roles" })).toBeNull();
  });
});

describe("dialog and toast helpers", () => {
  function Harness({ children }: { children: React.ReactNode }) {
    return <ToastProvider>{children}</ToastProvider>;
  }

  it("Modal traps Tab inside, closes on Escape and on the backdrop, and exposes a labelled dialog", () => {
    const onClose = vi.fn();
    render(
      <Modal title="Trap" onClose={onClose}>
        <input aria-label="first" />
        <button>last</button>
      </Modal>,
    );
    const dialog = screen.getByRole("dialog", { name: "Trap" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(screen.getByLabelText("first")).toHaveFocus();
    const last = screen.getByRole("button", { name: "last" });
    last.focus();
    fireEvent.keyDown(last, { key: "Tab" });
    expect(screen.getByRole("button", { name: "Close dialog" })).toHaveFocus(); // wrapped to the first focusable
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.mouseDown(dialog.parentElement!);
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("Modal ignores Escape while busy", () => {
    const onClose = vi.fn();
    render(<Modal title="Busy" onClose={onClose} busy><p>wait</p></Modal>);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
  });

  it("ConfirmDialog without typed text confirms directly and shows errors", async () => {
    const onConfirm = vi.fn().mockRejectedValue(new Error("nope"));
    render(<ConfirmDialog title="Sure?" confirmLabel="Do it" onConfirm={onConfirm} onClose={() => undefined}><p>x</p></ConfirmDialog>);
    fireEvent.click(screen.getByRole("button", { name: "Do it" }));
    expect(await screen.findByText("nope")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Do it" })).toBeEnabled(); // can retry
  });

  it("toasts announce politely and can be dismissed", async () => {
    function Fire() {
      const toast = useToast();
      return <button onClick={() => toast("Saved it.")}>fire</button>;
    }
    render(<Harness><Fire /></Harness>);
    fireEvent.click(screen.getByRole("button", { name: "fire" }));
    const region = screen.getAllByRole("status").find((r) => r.classList.contains("iam-toasts"))!;
    expect(region).toHaveAttribute("aria-live", "polite");
    expect(within(region).getByText("Saved it.")).toBeInTheDocument();
    await act(async () => { fireEvent.click(within(region).getByRole("button", { name: "Dismiss notification" })); });
    expect(within(region).queryByText("Saved it.")).toBeNull();
  });
});
