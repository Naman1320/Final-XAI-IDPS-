import type { Alert, LiveBlockEvent } from "../api/types";
import { trimFeed, type FeedItem } from "../pages/WorldMap";

const alert = (key: number): FeedItem => ({ key, kind: "alert", at: key, alert: { id: key } as Alert, located: true });
const block = (key: number): FeedItem => ({ key, kind: "block", at: key, event: { type: "block", event: "blocked", ip: "10.0.0.1" } as LiveBlockEvent });

describe("trimFeed", () => {
  it("keeps the newest 20 alerts and the newest 5 block events, in order", () => {
    // newest first: a block, then a flood of 100 alerts, then 7 older blocks
    const items = [block(1000), ...Array.from({ length: 100 }, (_, i) => alert(999 - i)),
      ...Array.from({ length: 7 }, (_, i) => block(800 - i))];
    const out = trimFeed(items);
    expect(out.filter((i) => i.kind === "alert")).toHaveLength(20);
    expect(out.filter((i) => i.kind === "block").map((i) => i.key)).toEqual([1000, 800, 799, 798, 797]);
    expect(out.map((i) => i.key)).toEqual([...out.map((i) => i.key)].sort((a, b) => b - a));
  });

  it("a flood of alerts never pushes out a block event", () => {
    let feed: FeedItem[] = [block(1)];
    for (let k = 2; k < 2000; k++) feed = trimFeed([alert(k), ...feed]);
    expect(feed.some((i) => i.kind === "block" && i.key === 1)).toBe(true);
    expect(feed).toHaveLength(21);
  });
});
