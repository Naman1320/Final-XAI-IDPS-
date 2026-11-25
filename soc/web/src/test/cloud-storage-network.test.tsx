import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ApiError } from "../api/client";
import { ALL_PERMS, MOCK, calls, cloudApiFake, freshDb, renderCloud, type Db } from "./cloud-fixtures";

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

const sgRow = (name: string) => screen.getByText(name, { selector: "td" }).closest("tr")!;
const rulesPanel = () => screen.getByRole("region", { name: /^Rules of/ });

describe("cloud network", () => {
  const openRules = async () => {
    renderCloud("/cloud/network");
    await screen.findByText("web", { selector: "td" });
    expect(await screen.findByText("pub-a")).toBeInTheDocument();
    expect(screen.getByText("main")).toBeInTheDocument();
    fireEvent.click(within(sgRow("web").closest("tr")!).getByRole("button", { name: /rules of web/i }));
    return screen.findByRole("region", { name: "Rules of web" });
  };

  it("reads VPCs, subnets and the rules of a security group", async () => {
    const panel = await openRules();
    const table = within(within(panel).getByRole("table", { name: "Rules of web" }));
    expect(table.getByText("Inbound")).toBeInTheDocument();
    expect(table.getByText("443")).toBeInTheDocument();
    expect(table.getByText("whole internet")).toBeInTheDocument();
    expect(within(sgRow("web").closest("tr")!).getByText(/not open/)).toBeInTheDocument();
  });

  it("validates a rule (CIDR, ports, protocol) before sending anything", async () => {
    const panel = await openRules();
    const form = within(within(panel).getByRole("form", { name: /Add a rule/ }));
    fireEvent.click(form.getByRole("button", { name: "Add rule" }));
    expect(form.getByText(/Enter a whole number/)).toBeInTheDocument();
    expect(form.getByText(/Enter a CIDR range/)).toBeInTheDocument();

    fireEvent.change(form.getByLabelText(/^Port from/), { target: { value: "70000" } });
    fireEvent.change(form.getByLabelText(/^CIDR/), { target: { value: "10.0.0.0/33" } });
    fireEvent.click(form.getByRole("button", { name: "Add rule" }));
    expect(form.getByText("Between 0 and 65535.")).toBeInTheDocument();
    expect(form.getByText("An IPv4 prefix is 0 to 32.")).toBeInTheDocument();

    fireEvent.change(form.getByLabelText(/^Port from/), { target: { value: "500" } });
    fireEvent.change(form.getByLabelText(/^Port to/), { target: { value: "400" } });
    fireEvent.change(form.getByLabelText(/^CIDR/), { target: { value: "300.1.1.1/24" } });
    expect(form.getByText("The first port must not be above the last port.")).toBeInTheDocument();
    expect(form.getByText("Each part of the address is 0 to 255.")).toBeInTheDocument();

    fireEvent.change(form.getByLabelText("Protocol"), { target: { value: "icmp" } });
    expect(form.getByLabelText(/^Port from/)).toBeDisabled();
    expect(form.getByLabelText(/^Port to/)).toBeDisabled();
    expect(calls(h.api, "POST")).toHaveLength(0);
  });

  it("adds a valid rule and shows the toast", async () => {
    const panel = await openRules();
    db.override["POST /cloud/network/security-groups/sg-1/rules"] = (_p, init) => {
      (db.groups[0].rules as unknown[]).push({ id: 9, direction: init.json.direction, protocol: init.json.protocol, port_from: init.json.port_from, port_to: init.json.port_to, cidr: init.json.cidr, description: init.json.description });
      return { ...MOCK, ...db.groups[0] };
    };
    const form = within(within(panel).getByRole("form", { name: /Add a rule/ }));
    fireEvent.change(form.getByLabelText(/^Port from/), { target: { value: "8080" } });
    fireEvent.change(form.getByLabelText(/^CIDR/), { target: { value: "10.1.0.0/16" } });
    fireEvent.click(form.getByRole("button", { name: "Add rule" }));
    await waitFor(() => expect(calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")).toHaveLength(1));
    expect(calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")[0][1]).toMatchObject({
      json: { direction: "in", protocol: "tcp", port_from: 8080, port_to: 8080, cidr: "10.1.0.0/16", description: "" },
    });
    expect(await screen.findByText("Rule added to web.")).toBeInTheDocument();
    expect(await within(rulesPanel()).findByText("10.1.0.0/16")).toBeInTheDocument();
  });

  it("shows the backend's refusal for SSH open to the world and resends only after a confirmation", async () => {
    const panel = await openRules();
    const reason = "this rule opens SSH (22) or RDP (3389) to the whole internet (0.0.0.0/0), where anyone can try to log in. Use a narrower source range, or send confirm_open_to_world=true to accept the risk.";
    db.override["POST /cloud/network/security-groups/sg-1/rules"] = (_p, init) => {
      if (!init.json.confirm_open_to_world) throw new ApiError(422, reason, "confirm_open_to_world");
      return { ...MOCK, ...db.groups[0] };
    };
    const form = within(within(panel).getByRole("form", { name: /Add a rule/ }));
    fireEvent.change(form.getByLabelText(/^Port from/), { target: { value: "22" } });
    fireEvent.change(form.getByLabelText(/^CIDR/), { target: { value: "0.0.0.0/0" } });
    fireEvent.click(form.getByRole("button", { name: "Add rule" }));

    const dialog = await screen.findByRole("dialog", { name: "Open this port to the whole internet?" });
    expect(within(dialog).getByText(reason)).toBeInTheDocument();
    expect(calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")).toHaveLength(1);
    expect((calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")[0][1] as { json: object }).json).not.toHaveProperty("confirm_open_to_world");

    // cancelling sends nothing more
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")).toHaveLength(1);

    fireEvent.click(form.getByRole("button", { name: "Add rule" }));
    const again = await screen.findByRole("dialog");
    fireEvent.click(within(again).getByRole("button", { name: "Add the rule anyway" }));
    await waitFor(() => expect(calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")).toHaveLength(3));
    expect(calls(h.api, "POST", "/cloud/network/security-groups/sg-1/rules")[2][1]).toMatchObject({ json: { cidr: "0.0.0.0/0", port_from: 22, confirm_open_to_world: true } });
    expect(await screen.findByText("Rule added to web.")).toBeInTheDocument();
  });

  it("removes a rule after a confirmation and shows a duplicate-rule 409 as text", async () => {
    const panel = await openRules();
    fireEvent.click(within(panel).getAllByRole("button", { name: "Remove" })[0]);
    const dialog = await screen.findByRole("dialog", { name: "Remove this rule?" });
    db.override["DELETE /cloud/network/security-groups/sg-1/rules/1"] = () => { (db.groups[0].rules as unknown[]).shift(); return { ...MOCK, ...db.groups[0] }; };
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove rule" }));
    expect(await screen.findByText("Rule removed from web.")).toBeInTheDocument();
    expect(calls(h.api, "DELETE", "/cloud/network/security-groups/sg-1/rules/1")).toHaveLength(1);

    db.override["POST /cloud/network/security-groups/sg-1/rules"] = () => { throw new ApiError(409, "that rule already exists"); };
    const form = within(within(rulesPanel()).getByRole("form", { name: /Add a rule/ }));
    fireEvent.change(form.getByLabelText(/^Port from/), { target: { value: "443" } });
    fireEvent.change(form.getByLabelText(/^CIDR/), { target: { value: "10.0.0.0/8" } });
    fireEvent.click(form.getByRole("button", { name: "Add rule" }));
    expect(await screen.findByText("that rule already exists")).toBeInTheDocument();
  });

  it("creates a security group with validation and deletes one, showing the 409 when it is in use", async () => {
    renderCloud("/cloud/network");
    await screen.findByText("web", { selector: "td" });
    fireEvent.click(screen.getByRole("button", { name: "Create security group" }));
    const dialog = await screen.findByRole("dialog", { name: "Create security group" });
    await within(dialog).findByRole("option", { name: /main/ });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "ab" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create security group" }));
    expect(within(dialog).getByText("At least 3 characters.")).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
    db.override["POST /cloud/network/security-groups"] = (_p, init) => ({ ...MOCK, id: "sg-9", rules: [], instances_using: 0, open_to_world_admin_ports: false, vpc_id: init.json.vpc_id, ...init.json });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "db tier" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create security group" }));
    expect(await screen.findByText("Security group db tier (sg-9) created.")).toBeInTheDocument();
    expect(calls(h.api, "POST", "/cloud/network/security-groups")[0][1]).toMatchObject({ json: { name: "db tier", vpc_id: "vpc-1" } });

    db.override["DELETE /cloud/network/security-groups/sg-1"] = () => { throw new ApiError(409, "the security group is used by 1 instance(s); change them first"); };
    fireEvent.click(within(sgRow("web")).getByRole("button", { name: "Delete" }));
    const del = await screen.findByRole("dialog", { name: "Delete this security group?" });
    fireEvent.click(within(del).getByRole("button", { name: "Delete security group" }));
    expect(await within(del).findByText(/used by 1 instance/)).toBeInTheDocument();
  });
});

describe("cloud storage", () => {
  const bucketRow = (name: string) => screen.getByText(name, { selector: "code" }).closest("tr")!;

  it("deletes a bucket that holds objects only after typing its name, with force", async () => {
    renderCloud("/cloud/storage");
    await screen.findByText("idps-demo-logs");
    fireEvent.click(within(bucketRow("idps-demo-logs")).getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete this bucket?" });
    expect(within(dialog).getByText(/12 objects/)).toBeInTheDocument();
    const go = within(dialog).getByRole("button", { name: "Delete bucket and its objects" });
    expect(go).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Type/), { target: { value: "idps-demo-log" } });
    expect(go).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Type/), { target: { value: "idps-demo-logs" } });
    expect(go).toBeEnabled();
    db.override["DELETE /cloud/buckets/idps-demo-logs"] = () => ({ ...MOCK, ...db.buckets[0] });
    fireEvent.click(go);
    await waitFor(() => expect(calls(h.api, "DELETE", "/cloud/buckets/idps-demo-logs?force=true")).toHaveLength(1));
    expect(await screen.findByText("Bucket idps-demo-logs deleted.")).toBeInTheDocument();
  });

  it("deletes an empty bucket without force", async () => {
    renderCloud("/cloud/storage");
    await screen.findByText("idps-demo-empty");
    fireEvent.click(within(bucketRow("idps-demo-empty")).getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog");
    db.override["DELETE /cloud/buckets/idps-demo-empty"] = () => ({ ...MOCK, ...db.buckets[1] });
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete bucket" }));
    await waitFor(() => expect(calls(h.api, "DELETE", "/cloud/buckets/idps-demo-empty")).toHaveLength(1));
    expect(calls(h.api, "DELETE", "/cloud/buckets/idps-demo-empty")[0][0]).toBe("/cloud/buckets/idps-demo-empty");
  });

  it("validates a bucket name, creates it, and toggles flags (turning protection off asks first)", async () => {
    renderCloud("/cloud/storage");
    await screen.findByText("idps-demo-logs");
    fireEvent.click(screen.getByRole("button", { name: "Create bucket" }));
    const dialog = await screen.findByRole("dialog", { name: "Create bucket" });
    fireEvent.change(within(dialog).getByLabelText(/^Bucket name/), { target: { value: "Bad_Name" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create bucket" }));
    expect(within(dialog).getByText(/Lower-case letters, digits, dots or hyphens/)).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText(/^Bucket name/), { target: { value: "192.168.1.1" } });
    expect(within(dialog).getByText("Must not look like an IP address.")).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
    db.override["POST /cloud/buckets"] = (_p, init) => ({ ...MOCK, ...db.buckets[1], ...init.json });
    fireEvent.change(within(dialog).getByLabelText(/^Bucket name/), { target: { value: "my-new-bucket" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create bucket" }));
    expect(await screen.findByText("Bucket my-new-bucket created.")).toBeInTheDocument();
    expect(calls(h.api, "POST", "/cloud/buckets")[0][1]).toMatchObject({ json: { name: "my-new-bucket", versioning: false, encrypted: true, public_access_blocked: true } });

    db.override["PATCH /cloud/buckets/idps-demo-logs"] = (_p, init) => ({ ...MOCK, ...db.buckets[0], ...init.json });
    const row = bucketRow("idps-demo-logs");
    fireEvent.click(within(row).getByRole("switch", { name: "Versioning for idps-demo-logs" }));
    await waitFor(() => expect(calls(h.api, "PATCH", "/cloud/buckets/idps-demo-logs")).toHaveLength(1));
    expect(calls(h.api, "PATCH", "/cloud/buckets/idps-demo-logs")[0][1]).toMatchObject({ json: { versioning: false } });

    fireEvent.click(within(bucketRow("idps-demo-logs")).getByRole("switch", { name: "Block public access for idps-demo-logs" }));
    const risk = await screen.findByRole("dialog", { name: "Turn off block public access?" });
    expect(calls(h.api, "PATCH")).toHaveLength(1);
    fireEvent.click(within(risk).getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(calls(h.api, "PATCH")).toHaveLength(2));
    expect(calls(h.api, "PATCH")[1][1]).toMatchObject({ json: { public_access_blocked: false } });
  });

  it("creates, resizes (grow only), attaches, detaches and deletes volumes", async () => {
    renderCloud("/cloud/storage");
    await screen.findByText("data-1");
    const vrow = (n: string) => screen.getByText(n).closest("tr")!;
    expect(within(vrow("data-1")).getByText("in-use")).toBeInTheDocument();
    expect(within(vrow("spare-1")).getByText("not encrypted")).toBeInTheDocument();

    fireEvent.click(within(vrow("data-1")).getByRole("button", { name: "Resize" }));
    let dialog = await screen.findByRole("dialog", { name: "Resize data-1" });
    fireEvent.change(within(dialog).getByLabelText(/New size/), { target: { value: "80" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Resize" }));
    expect(within(dialog).getByText("A volume can only grow (it is 100 GB).")).toBeInTheDocument();
    db.override["PATCH /cloud/volumes/vol-1"] = (_p, init) => ({ ...MOCK, ...db.volumes[0], size_gb: init.json.size_gb });
    fireEvent.change(within(dialog).getByLabelText(/New size/), { target: { value: "200" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Resize" }));
    expect(await screen.findByText("Volume data-1 is now 200 GB.")).toBeInTheDocument();

    fireEvent.click(within(vrow("spare-1")).getByRole("button", { name: "Attach" }));
    dialog = await screen.findByRole("dialog", { name: "Attach spare-1" });
    await within(dialog).findByRole("option", { name: /web-1/ });
    expect(within(dialog).queryByRole("option", { name: /old-1/ })).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Attach" }));
    expect(within(dialog).getByText("Choose an instance.")).toBeInTheDocument();
    db.override["POST /cloud/volumes/vol-2/attach"] = () => ({ ...MOCK, ...db.volumes[1] });
    fireEvent.change(within(dialog).getByLabelText(/^Instance/), { target: { value: "i-aaaa1111" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Attach" }));
    await waitFor(() => expect(calls(h.api, "POST", "/cloud/volumes/vol-2/attach")).toHaveLength(1));
    expect(calls(h.api, "POST", "/cloud/volumes/vol-2/attach")[0][1]).toMatchObject({ json: { instance_id: "i-aaaa1111" } });

    fireEvent.click(within(vrow("data-1")).getByRole("button", { name: "Delete" }));
    dialog = await screen.findByRole("dialog", { name: "Delete this volume?" });
    db.override["DELETE /cloud/volumes/vol-1"] = () => { throw new ApiError(409, "the volume is attached; detach it before deleting it"); };
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete volume" }));
    expect(await within(dialog).findByText("the volume is attached; detach it before deleting it")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    fireEvent.click(within(vrow("data-1")).getByRole("button", { name: "Detach" }));
    dialog = await screen.findByRole("dialog", { name: "Detach this volume?" });
    db.override["POST /cloud/volumes/vol-1/detach"] = () => ({ ...MOCK, ...db.volumes[0] });
    fireEvent.click(within(dialog).getByRole("button", { name: "Detach" }));
    expect(await screen.findByText("Volume data-1 detached.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Create volume" }));
    dialog = await screen.findByRole("dialog", { name: "Create volume" });
    fireEvent.change(within(dialog).getByLabelText(/^Size/), { target: { value: "0" } });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "scratch" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create volume" }));
    expect(within(dialog).getByText("Between 1 and 16384.")).toBeInTheDocument();
    db.override["POST /cloud/volumes"] = (_p, init) => ({ ...MOCK, id: "vol-9", state: "available", instance_id: null, ...init.json });
    fireEvent.change(within(dialog).getByLabelText(/^Size/), { target: { value: "10" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create volume" }));
    expect(await screen.findByText("Volume scratch (vol-9) created.")).toBeInTheDocument();
  });
});
