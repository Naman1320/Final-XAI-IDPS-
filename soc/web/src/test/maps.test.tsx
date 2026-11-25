import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import Maps, { WINDOWS } from "../pages/Maps";

vi.mock("../pages/WorldMap", () => ({ default: ({ hours }: { hours: number }) => <div>world-map-stub hours={hours}</div> }));
vi.mock("../pages/TopologyMap", () => ({
  default: ({ hours, onShowWorld }: { hours: number; onShowWorld: () => void }) => (
    <div>topology-map-stub hours={hours}<button onClick={onShowWorld}>stub-show-world</button></div>
  ),
}));

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname + l.search}</div>; }
const setup = (url: string) => render(<MemoryRouter initialEntries={[url]}><Maps /><Loc /></MemoryRouter>);
const loc = () => screen.getByTestId("loc").textContent;

describe("Maps toggle", () => {
  it("defaults to topology and 1 h", async () => {
    setup("/maps");
    expect(await screen.findByText("topology-map-stub hours=1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Network topology" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText("Window")).toHaveValue("1");
  });
  it("clicking World attack map sets ?view=world and shows it", async () => {
    setup("/maps");
    fireEvent.click(screen.getByRole("button", { name: "World attack map" }));
    expect(await screen.findByText("world-map-stub hours=1")).toBeInTheDocument();
    expect(loc()).toBe("/maps?view=world");
    expect(screen.getByRole("button", { name: "World attack map" })).toHaveAttribute("aria-pressed", "true");
  });
  it("switching back to topology clears the query", async () => {
    setup("/maps?view=world");
    expect(await screen.findByText(/world-map-stub/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Network topology" }));
    expect(await screen.findByText(/topology-map-stub/)).toBeInTheDocument();
    expect(loc()).toBe("/maps");
  });
  it("the toggle keeps the chosen hours", async () => {
    setup("/maps?hours=6");
    await screen.findByText("topology-map-stub hours=6");
    fireEvent.click(screen.getByRole("button", { name: "World attack map" }));
    expect(await screen.findByText("world-map-stub hours=6")).toBeInTheDocument();
    expect(loc()).toBe("/maps?view=world&hours=6");
    fireEvent.click(screen.getByRole("button", { name: "Network topology" }));
    await screen.findByText("topology-map-stub hours=6");
    expect(loc()).toBe("/maps?hours=6");
  });
});

describe("Maps window", () => {
  it("accepts exactly 1, 6, 24, 72 and 168", () => {
    expect(WINDOWS).toEqual([1, 6, 24, 72, 168]);
  });
  it("labels the options", async () => {
    setup("/maps");
    await screen.findByText(/topology-map-stub/);
    const opts = Array.from((screen.getByLabelText("Window") as HTMLSelectElement).options).map((o) => o.text);
    expect(opts).toEqual(["last 1 h", "last 6 h", "last 24 h", "last 3 days", "last 7 days"]);
  });
  it("changing it writes ?hours, except 1 (the default) which is omitted; 24 is written", async () => {
    setup("/maps");
    await screen.findByText(/topology-map-stub/);
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "72" } });
    expect(await screen.findByText("topology-map-stub hours=72")).toBeInTheDocument();
    expect(loc()).toBe("/maps?hours=72");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "24" } });
    expect(await screen.findByText("topology-map-stub hours=24")).toBeInTheDocument();
    expect(loc()).toBe("/maps?hours=24");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "1" } });
    expect(await screen.findByText("topology-map-stub hours=1")).toBeInTheDocument();
    expect(loc()).toBe("/maps");
  });
  it("the window applies to the world map too", async () => {
    setup("/maps?view=world");
    await screen.findByText("world-map-stub hours=1");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "168" } });
    expect(await screen.findByText("world-map-stub hours=168")).toBeInTheDocument();
    expect(loc()).toBe("/maps?view=world&hours=168");
  });
  it.each(["5", "abc", "0", "-1", "24.5", ""])("?hours=%s falls back to 1", async (v) => {
    setup(`/maps?hours=${v}`);
    expect(await screen.findByText("topology-map-stub hours=1")).toBeInTheDocument();
    expect(screen.getByLabelText("Window")).toHaveValue("1");
  });
  it("?hours=24 is a valid choice", async () => {
    setup("/maps?hours=24");
    expect(await screen.findByText("topology-map-stub hours=24")).toBeInTheDocument();
    expect(screen.getByLabelText("Window")).toHaveValue("24");
  });
  it("passes onShowWorld to the topology map, keeping the hours", async () => {
    setup("/maps?hours=6");
    fireEvent.click(await screen.findByText("stub-show-world"));
    expect(await screen.findByText("world-map-stub hours=6")).toBeInTheDocument();
    expect(loc()).toBe("/maps?view=world&hours=6");
  });
});
