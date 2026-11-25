import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import AlertDetail, { isReservedIp, timeline } from "../pages/AlertDetail";
import { sensorsStatus } from "./sensor-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn() }));
vi.mock("../useLiveRefresh", () => ({ useLiveRefresh: () => true }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));

const T = 1_700_000_000_000;
const rule = (o: Record<string, unknown> = {}) => ({
  sid: 2024897, rev: 5, signature: "ET SCAN Nmap", category: "Attempted Information Leak", severity: 2, count: 1, ...o,
});
const mk = (o: Record<string, unknown> = {}) => ({
  id: 7, sensor_id: 3, received_at: new Date(T + 60_000).toISOString(), src_ip: "10.0.0.1", src_port: 1234,
  dst_ip: "10.0.0.2", dst_port: 80, protocol: 6, start_ms: T, end_ms: T + 1000, predicted_class: "PortScan",
  confidence: 0.95, anomaly_score: null, severity: "high", status: "new", case_id: null,
  explanation: { method: "shap", predicted_class: "PortScan", top_features: [{ feature: "syn_count", value: 4, contribution: 1.2 }] },
  ...o,
});
const ruleAlert = (r: Record<string, unknown> = {}, o: Record<string, unknown> = {}) => mk({
  source: "rule", rule: rule(r), explanation: null, top_features: [], model_version: null, model_sha256: null, ...o,
});

let alert: unknown;
beforeEach(() => {
  h.api.mockReset();
  h.api.mockImplementation(async (path: string) => {
    if (path === "/sensors/status") return sensorsStatus();
    if (path.startsWith("/blocks") || path.startsWith("/cases")) return { items: [], total: 0 };
    if (path === "/alerts/7") return alert;
    throw new Error(`unexpected ${path}`);
  });
});
const show = async () => {
  render(<MemoryRouter initialEntries={["/alerts/7"]}><Routes><Route path="/alerts/:id" element={<AlertDetail />} /></Routes></MemoryRouter>);
  await screen.findByRole("heading", { level: 1 });
};
const ruleCard = () => screen.getByText("Why the rule fired").closest(".card") as HTMLElement;
const dd = (card: HTMLElement, term: string) => within(card).getByText(term, { selector: "dt" }).nextElementSibling as HTMLElement;

describe("AlertDetail rule alert", () => {
  it("shows the rule tag in the header and the Model row", async () => {
    alert = ruleAlert();
    await show();
    expect(screen.getByRole("heading", { level: 1 }).parentElement!.querySelector(".source-tag")).toHaveTextContent("rule");
    expect(screen.getByText("Suricata rule (no model)")).toBeInTheDocument();
    expect(screen.queryByText("not reported by this sensor")).toBeNull();
  });

  it("rule card: signature, sid and rev, category, severity label, matches", async () => {
    alert = ruleAlert({ count: 1 });
    await show();
    const c = ruleCard();
    expect(within(c).getByText("ET SCAN Nmap")).toBeInTheDocument();
    expect(dd(c, "Rule")).toHaveTextContent("sid 2024897 · rev 5");
    expect(dd(c, "Category")).toHaveTextContent("Attempted Information Leak");
    expect(dd(c, "Rule severity")).toHaveTextContent("2 (medium; 1 is the most severe)");
    expect(dd(c, "Matches")).toHaveTextContent("1");
    expect(c.textContent).toContain("Suricata matched the signature ET SCAN Nmap.");
    expect(c.textContent).not.toMatch(/It matched|folding window/);
  });

  it("rev null drops the rev, category null shows a dash", async () => {
    alert = ruleAlert({ rev: null, category: null });
    await show();
    const c = ruleCard();
    expect(dd(c, "Rule").textContent).toBe("sid 2024897");
    expect(dd(c, "Category").textContent).toBe("—");
  });

  it.each([[1, "high"], [2, "medium"], [3, "low"], [4, "informational"]])("severity %i is labelled %s", async (n, name) => {
    alert = ruleAlert({ severity: n });
    await show();
    expect(dd(ruleCard(), "Rule severity")).toHaveTextContent(`${n} (${name};`);
  });

  it("count above 1 adds the N times text and a formatted Matches", async () => {
    alert = ruleAlert({ count: 1500 });
    await show();
    const c = ruleCard();
    expect(c.textContent).toContain("Suricata matched the signature ET SCAN Nmap.");
    expect(c.textContent).toContain("It matched 1,500 times for this source, target and port within the folding window.");
    expect(dd(c, "Matches")).toHaveTextContent("1,500");
  });

  it("hides the SHAP and trust cards", async () => {
    alert = ruleAlert({ count: 3 });
    await show();
    expect(screen.queryByText("Why the model flagged this flow")).toBeNull();
    expect(screen.queryByText("Can I trust it?")).toBeNull();
    await waitFor(() => expect(h.api).toHaveBeenCalledWith("/alerts/7"));
    expect(h.api.mock.calls.some(([p]) => p === "/sensors/status")).toBe(false);
  });

  it("learning text says rule alerts don't change the model, with no Real class even when confirmed", async () => {
    alert = ruleAlert({}, { status: "confirmed", has_features: true, true_class: "DoS" });
    await show();
    expect(screen.getByText(/Raised by a Suricata rule, not the model/)).toHaveTextContent(/doesn't change the model/);
    expect(screen.queryByLabelText("Real class")).toBeNull();
    expect(screen.queryByText(/training row/)).toBeNull();
  });
});

describe("AlertDetail model alert is unchanged", () => {
  it.each([[{}], [{ source: "ml", rule: null }]])("no tag, SHAP card, real-class select when confirmed (%j)", async (extra) => {
    alert = mk({ ...extra, status: "confirmed", has_features: true, model_version: "v9" });
    await show();
    expect(screen.getByText("Why the model flagged this flow")).toBeInTheDocument();
    expect(screen.queryByText("Why the rule fired")).toBeNull();
    expect(document.querySelector(".source-tag")).toBeNull();
    expect(screen.getByText("v9")).toBeInTheDocument();
    expect(screen.queryByText("Suricata rule (no model)")).toBeNull();
    expect(screen.getByLabelText("Real class")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: /Explain this alert/ }));
  });
});

describe("AlertDetail rule alert header, rows and fallback", () => {
  it("header has the rule severity pill instead of the confidence pill", async () => {
    alert = ruleAlert({ severity: 3 });
    await show();
    const head = screen.getByRole("heading", { level: 1 }).parentElement!;
    expect(within(head).getByText("rule severity 3")).toHaveClass("pill");
    expect(within(head).queryByText(/^confidence/)).toBeNull();
  });

  it("no pill at all when the rule is null", async () => {
    alert = ruleAlert({}, { rule: null });
    await show();
    const head = screen.getByRole("heading", { level: 1 }).parentElement!;
    expect(head.textContent).not.toMatch(/confidence|rule severity/);
    expect(head.querySelector(".source-tag")).toHaveTextContent("rule");
  });

  it("model alerts keep the confidence pill and the Anomaly score row", async () => {
    alert = mk({ anomaly_score: 0.5 });
    await show();
    expect(screen.getByText("confidence 95.0%")).toBeInTheDocument();
    expect(screen.getByText("Anomaly score", { selector: "dt" })).toBeInTheDocument();
  });

  it("hides the Anomaly score row for rule alerts", async () => {
    alert = ruleAlert({}, { anomaly_score: 0.7 });
    await show();
    expect(screen.queryByText("Anomaly score")).toBeNull();
    expect(screen.queryByText("Isolation Forest")).toBeNull();
  });

  it("rule with no details: fallback card, no SHAP or Trust cards, no Anomaly score", async () => {
    alert = ruleAlert({}, { rule: null });
    await show();
    const c = screen.getByText("Why the rule fired").closest(".card") as HTMLElement;
    expect(c).toHaveTextContent("The sensor didn't send the rule's details.");
    expect(screen.queryByText("Why the model flagged this flow")).toBeNull();
    expect(screen.queryByText("Can I trust it?")).toBeNull();
    expect(screen.queryByText("Anomaly score")).toBeNull();
    expect(screen.getByText("Suricata rule (no model)")).toBeInTheDocument();
  });
});

describe("timeline for rule alerts", () => {
  const texts = (items: { text: unknown }[]) => items.map((i) => i.text);
  it("reads Suricata rule matched (sid N): class", () => {
    const items = timeline(ruleAlert({ sid: 99 }, { predicted_class: "ET SCAN" }) as never, [], T + 10);
    expect(texts(items)[1]).toBe("Suricata rule matched (sid 99): ET SCAN");
    expect(texts(items).join(" ")).not.toMatch(/scored|explained/);
  });
  it("omits the sid when the rule is null", () => {
    const items = timeline(ruleAlert({}, { rule: null, predicted_class: "ET SCAN" }) as never, [], T + 10);
    expect(texts(items)[1]).toBe("Suricata rule matched: ET SCAN");
  });
});

describe("isReservedIp", () => {
  it.each([
    "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.1.1",
    "100.64.0.1", "100.127.255.255", "203.0.113.5", "198.18.0.1", "198.19.255.255", "0.0.0.0", "224.0.0.1",
    "::1", "fe80::1", "fd00::1", "fc00::1", "2001:db8::1", "::ffff:1.2.3.4",
  ])("%s is reserved", (ip) => { expect(isReservedIp(ip)).toBe(true); });
  it.each([
    "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.167.1.1", "169.253.1.1", "198.17.0.1", "198.20.0.1",
    "8.8.8.8", "45.33.32.156", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "not-an-ip", "1.2.3",
  ])("%s is public", (ip) => { expect(isReservedIp(ip)).toBe(false); });
});

describe("ReputationCard", () => {
  const PUB = "45.33.32.156";
  const rep = (o: Record<string, unknown> = {}) => ({
    ip: PUB, available: true, reason: null, abuse_confidence: 80, total_reports: 1234, country: "DE", isp: "Acme ISP",
    usage_type: "Data Center", last_reported_at: "2026-02-01T10:00:00Z", checked_at: "2026-02-02T10:00:00Z", cached: false, ...o,
  });
  let reply: () => unknown;
  const repCalls = () => h.api.mock.calls.filter(([p]) => String(p).endsWith("/reputation"));
  const card = () => screen.getByText("Source reputation").closest(".card") as HTMLElement;
  const open = async (r: () => unknown, ip = PUB) => {
    alert = mk({ src_ip: ip });
    reply = r;
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string, o?: unknown) => (p === "/alerts/7/reputation" ? reply() : base(p, o)));
    await show();
  };
  const click = () => fireEvent.click(within(card()).getByRole("button"));

  it("public ip: button, key note, persistent status region, no request until clicked", async () => {
    await open(() => rep());
    expect(within(card()).getByRole("button", { name: `Check ${PUB} on AbuseIPDB` })).toBeInTheDocument();
    expect(card()).toHaveTextContent("If the SOC has an AbuseIPDB key, only the IP address is sent to AbuseIPDB.");
    expect(within(card()).getByRole("status")).toBeEmptyDOMElement();
    expect(repCalls()).toHaveLength(0);
    click();
    await within(card()).findByText("Abuse score");
    expect(repCalls()).toHaveLength(1);
    expect(within(card()).getByRole("status")).toHaveTextContent("Abuse score");
  });

  it.each(["10.0.0.1", "192.168.1.5", "::1"])("reserved ip %s shows the note and never requests", async (ip) => {
    await open(() => rep(), ip);
    expect(card()).toHaveTextContent(`${ip} is a private or reserved address: it has no public reputation and is never looked up.`);
    expect(within(card()).queryByRole("button")).toBeNull();
    expect(repCalls()).toHaveLength(0);
  });

  it("unavailable shows the reason and a Try again button that requests again", async () => {
    await open(() => rep({ available: false, reason: "no API key", abuse_confidence: null }));
    click();
    expect(await within(card()).findByText(`No reputation for ${PUB}: no API key.`)).toBeInTheDocument();
    expect(within(card()).queryByText(/abuse score/)).toBeNull();
    expect(card()).not.toHaveTextContent("only the IP address is sent");
    reply = () => rep({ abuse_confidence: 30 });
    fireEvent.click(within(card()).getByRole("button", { name: "Try again" }));
    expect(await within(card()).findByText("abuse score 30%")).toBeInTheDocument();
    expect(repCalls()).toHaveLength(2);
    expect(within(card()).queryByRole("button")).toBeNull();
  });

  it("available shows score pill, legend, reports, last reported, country, network, checked", async () => {
    await open(() => rep({ cached: true }));
    click();
    await within(card()).findByText("Abuse score");
    expect(within(card()).getByText("abuse score 80%")).toHaveClass("pill");
    const c = card();
    expect(dd(c, "Abuse score")).toHaveTextContent("80% (AbuseIPDB confidence; 25%+ suspicious, 75%+ high)");
    expect(dd(c, "Reports")).toHaveTextContent("1,234");
    expect(dd(c, "Last reported").textContent).not.toBe("never");
    expect(dd(c, "Country")).toHaveTextContent("DE");
    expect(dd(c, "Network")).toHaveTextContent("Acme ISP · Data Center");
    expect(dd(c, "Checked")).toHaveTextContent("(cached)");
    expect(c.querySelector("button")).toBeNull();
  });

  it("score dash and no pill when abuse_confidence is null", async () => {
    await open(() => rep({ abuse_confidence: null }));
    click();
    await within(card()).findByText("Abuse score");
    expect(dd(card(), "Abuse score").textContent).toMatch(/^— /);
    expect(within(card()).queryByText(/abuse score/)).toBeNull();
  });

  it("never when not reported, and no (cached) when fresh", async () => {
    await open(() => rep({ last_reported_at: null, cached: false }));
    click();
    await within(card()).findByText("Abuse score");
    expect(dd(card(), "Last reported")).toHaveTextContent("never");
    expect(dd(card(), "Checked").textContent).not.toContain("cached");
  });

  it.each([[75, "danger"], [100, "danger"], [74, "warn"], [25, "warn"], [24, "ok"], [0, "ok"]])("score %i has tone %s", async (n, tone) => {
    await open(() => rep({ abuse_confidence: n }));
    click();
    expect(await within(card()).findByText(`abuse score ${n}%`)).toHaveClass(tone);
  });

  it("a request error is shown and the button stays", async () => {
    await open(() => { throw new Error("quota exceeded"); });
    click();
    expect(await within(card()).findByText(/quota exceeded/)).toBeInTheDocument();
    expect(within(card()).getByRole("button", { name: `Check ${PUB} on AbuseIPDB` })).toBeInTheDocument();
  });
});
