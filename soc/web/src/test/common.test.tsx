import { act, fireEvent, render, screen } from "@testing-library/react";
import { Card, ConfidenceBar, Countdown, PageHead, Pill, Segmented, Timeline } from "../components/common";

describe("Segmented", () => {
  it("presses exactly the chosen button and reports changes", () => {
    const onChange = vi.fn();
    render(<Segmented label="Mode" value="b" onChange={onChange}
      options={[{ value: "a", label: "A" }, { value: "b", label: "B" }, { value: "c", label: "C" }]} />);
    expect(screen.getByRole("group", { name: "Mode" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "B" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "A" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getAllByRole("button").filter((b) => b.getAttribute("aria-pressed") === "true")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "C" }));
    expect(onChange).toHaveBeenCalledWith("c");
  });
});

describe("Pill", () => {
  it("applies tone, round and dot", () => {
    const { container } = render(<Pill tone="ok" round dot>Hi</Pill>);
    const el = container.querySelector(".pill")!;
    expect(el).toHaveClass("ok", "round");
    expect(el.querySelector(".dot")).not.toBeNull();
    expect(el).toHaveTextContent("Hi");
  });
  it("defaults to neutral with no dot", () => {
    const { container } = render(<Pill>x</Pill>);
    expect(container.querySelector(".pill")).toHaveClass("neutral");
    expect(container.querySelector(".dot")).toBeNull();
  });
});

describe("ConfidenceBar", () => {
  const width = (c: HTMLElement) => (c.querySelector(".meter-fill") as HTMLElement).style.width;
  it("shows percentage", () => {
    const { container } = render(<ConfidenceBar value={0.5} digits={0} />);
    expect(container).toHaveTextContent("50%");
    expect(width(container)).toBe("50%");
  });
  it("clamps out-of-range values", () => {
    const hi = render(<ConfidenceBar value={1.7} />);
    expect(hi.container).toHaveTextContent("100.00%");
    expect(width(hi.container)).toBe("100%");
    const lo = render(<ConfidenceBar value={-3} />);
    expect(lo.container).toHaveTextContent("0.00%");
  });
  it.each([[NaN], [null], [undefined], [Infinity]])("renders a dash for %s", (v) => {
    const { container } = render(<ConfidenceBar value={v as number} />);
    expect(container).toHaveTextContent("—");
    expect(container).not.toHaveTextContent("%");
    expect(container.querySelector(".meter-fill")).toBeNull();
  });
  it("still renders a real zero", () => {
    const { container } = render(<ConfidenceBar value={0} />);
    expect(container).toHaveTextContent("0.00%");
  });
});

describe("Countdown", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-01-01T00:00:00Z")); });
  afterEach(() => vi.useRealTimers());
  const iso = (s: number) => new Date(Date.parse("2026-01-01T00:00:00Z") + s * 1000).toISOString();

  it("shows time left and ticks down", () => {
    render(<Countdown start={iso(0)} end={iso(42)} />);
    expect(screen.getByText("0:42 left")).toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(2000); });
    expect(screen.getByText("0:40 left")).toBeInTheDocument();
  });
  it("shows hours format", () => {
    render(<Countdown start={iso(0)} end={iso(3600 + 5 * 60)} />);
    expect(screen.getByText("1:05 h left")).toBeInTheDocument();
  });
  it("says expired at and after the end", () => {
    render(<Countdown start={iso(-10)} end={iso(0)} />);
    expect(screen.getByText("expired")).toBeInTheDocument();
  });
  it("flips to expired as time passes", () => {
    render(<Countdown start={iso(0)} end={iso(3)} />);
    act(() => { vi.advanceTimersByTime(4000); });
    expect(screen.getByText("expired")).toBeInTheDocument();
  });
  it("shows unknown expiry for an unparseable end", () => {
    render(<Countdown start={iso(0)} end="not-a-date" />);
    expect(screen.getByText("unknown expiry")).toBeInTheDocument();
  });
  it("with an invalid start keeps counting and the bar at 0", () => {
    const { container } = render(<Countdown start="garbage" end={iso(42)} />);
    expect(screen.getByText("0:42 left")).toBeInTheDocument();
    expect((container.querySelector(".meter-fill") as HTMLElement).style.width).toBe("0%");
    act(() => { vi.advanceTimersByTime(2000); });
    expect(screen.getByText("0:40 left")).toBeInTheDocument();
  });
  it("caps the bar at 100% when start is still in the future", () => {
    const { container } = render(<Countdown start={iso(10)} end={iso(20)} />);
    expect((container.querySelector(".meter-fill") as HTMLElement).style.width).toBe("100%");
  });
  it("says no expiry for null", () => {
    render(<Countdown start={iso(0)} end={null} />);
    expect(screen.getByText("no expiry")).toBeInTheDocument();
  });
});

describe("Timeline, PageHead, Card", () => {
  it("renders timeline items in order", () => {
    render(<Timeline items={[{ key: "1", at: "10:00", text: "first" }, { key: "2", at: "10:05", text: "second", tone: "danger" }]} />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("10:00 first");
    expect(items[1].querySelector(".tl-dot")).toHaveClass("danger");
  });
  it("PageHead renders heading and controls", () => {
    render(<PageHead title="Maps"><button>Go</button></PageHead>);
    expect(screen.getByRole("heading", { level: 1, name: "Maps" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go" })).toBeInTheDocument();
  });
  it("Card labels itself from a string title, and explicit label wins", () => {
    const a = render(<Card title="Blocks">x</Card>);
    const sec = screen.getByRole("region", { name: "Blocks" });
    expect(sec).not.toHaveAttribute("aria-label");
    expect(sec.getAttribute("aria-labelledby")).toBe(screen.getByRole("heading", { level: 2 }).id);
    a.unmount();
    render(<Card title="T" label="Custom">x</Card>);
    const c = screen.getByRole("region", { name: "Custom" });
    expect(c).not.toHaveAttribute("aria-labelledby");
  });
  it("Card without a title has no name", () => {
    const { container } = render(<Card>x</Card>);
    expect(container.querySelector("section")).not.toHaveAttribute("aria-labelledby");
  });
});
