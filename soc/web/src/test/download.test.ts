import { ApiError, download, getToken, setToken } from "../api/client";
import { isoWeek, weekRange } from "../pages/Reports";

describe("isoWeek", () => {
  it.each([
    ["2026-01-01", "2026-W01"],
    ["2027-01-01", "2026-W53"],
    ["2024-12-30", "2025-W01"],
    ["2021-01-03", "2020-W53"],
    ["2026-11-16", "2026-W47"],
    ["2026-11-15", "2026-W46"],
  ])("%s -> %s", (d, w) => {
    expect(isoWeek(new Date(`${d}T12:00:00Z`))).toBe(w);
  });
  it("uses UTC, not local time", () => {
    expect(isoWeek(new Date("2026-11-15T23:59:59Z"))).toBe("2026-W46");
    expect(isoWeek(new Date("2026-11-16T00:00:00Z"))).toBe("2026-W47");
  });
});

describe("weekRange", () => {
  it("formats start to the last day (end is exclusive)", () => {
    const fmt = (s: string) => new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", timeZone: "UTC" });
    expect(weekRange("2026-11-09T00:00:00Z", "2026-11-16T00:00:00Z")).toBe(`${fmt("2026-11-09")} – ${fmt("2026-11-15")}`);
  });
  it("crosses a month boundary", () => {
    const r = weekRange("2026-10-26T00:00:00Z", "2026-11-02T00:00:00Z");
    expect(r).toContain("26");
    expect(r).toMatch(/1\b/);
    expect(r).not.toContain("2 ");
  });
});

describe("download()", () => {
  let anchor: HTMLAnchorElement | null;
  let click: ReturnType<typeof vi.spyOn>;
  const fetchMock = vi.fn();
  const create = vi.fn(() => "blob:fake");
  const revoke = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    anchor = null;
    fetchMock.mockReset();
    create.mockClear();
    revoke.mockClear();
    vi.stubGlobal("fetch", fetchMock);
    (URL as any).createObjectURL = create;
    (URL as any).revokeObjectURL = revoke;
    click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { anchor = this; });
    setToken("tok123");
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    setToken(null);
  });

  const pdf = (headers: Record<string, string> = {}) =>
    new Response(new Blob(["%PDF"]), { status: 200, headers: { "Content-Type": "application/pdf", ...headers } });

  it("sends the bearer token and uses the server filename", async () => {
    fetchMock.mockResolvedValue(pdf({ "Content-Disposition": 'attachment; filename="idps-2026-W46.pdf"' }));
    await download("/reports/weekly?week=2026-W46", "fallback.pdf");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/reports/weekly?week=2026-W46");
    expect((init.headers as Headers).get("Authorization")).toBe("Bearer tok123");
    expect(click).toHaveBeenCalledTimes(1);
    expect(anchor!.download).toBe("idps-2026-W46.pdf");
    expect(create).toHaveBeenCalledTimes(1);
    expect(document.querySelector("a[download]")).toBeNull();
  });

  it("falls back to the given name without Content-Disposition", async () => {
    fetchMock.mockResolvedValue(pdf());
    await download("/x", "fallback.pdf");
    expect(anchor!.download).toBe("fallback.pdf");
  });

  it("uses the fallback name for a hostile filename", async () => {
    fetchMock.mockResolvedValue(pdf({ "Content-Disposition": 'attachment; filename="../../x\\"; y.pdf"' }));
    await download("/x", "fallback.pdf");
    expect(anchor!.download).toBe("fallback.pdf");
  });

  it("uses the fallback name for path separators, spaces or a non-PDF name", async () => {
    for (const name of ["../a b/c.pdf", "..", ".hidden.pdf", "report.html"]) {
      fetchMock.mockResolvedValue(pdf({ "Content-Disposition": `attachment; filename=${name}` }));
      await download("/x", "fallback.pdf");
      expect(anchor!.download).toBe("fallback.pdf");
    }
  });

  it("refuses an answer that is not a PDF (e.g. a proxy's HTML page)", async () => {
    fetchMock.mockResolvedValue(new Response("<html>", { status: 200, headers: { "Content-Type": "text/html" } }));
    await expect(download("/x", "f.pdf")).rejects.toThrow("did not send a PDF");
    expect(anchor).toBeNull();
  });

  it("revokes the object URL later", async () => {
    fetchMock.mockResolvedValue(pdf());
    await download("/x", "f.pdf");
    expect(revoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(10_000);
    expect(revoke).toHaveBeenCalledWith("blob:fake");
  });

  it("throws ApiError with the server detail on 4xx", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: "No such week" }), { status: 404 }));
    const err = await download("/x", "f.pdf").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(404);
    expect(err.message).toBe("No such week");
    expect(click).not.toHaveBeenCalled();
    expect(getToken()).toBe("tok123");
  });

  it("clears the token on 401", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: "Token expired" }), { status: 401 }));
    await expect(download("/x", "f.pdf")).rejects.toMatchObject({ status: 401, message: "Token expired" });
    expect(getToken()).toBeNull();
  });
});
