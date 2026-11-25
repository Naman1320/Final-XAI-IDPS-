import { geoEqualEarth, geoGraticule10, geoInterpolate, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import countriesTopo from "world-atlas/countries-110m.json";
import { api, query } from "../api/client";
import { SEVERITIES, type Alert, type GeoLocation, type LiveAlert, type LiveBlockEvent, type Page, type Severity } from "../api/types";
import { Card, ErrorText, Pill, SeverityBadge, SourceTag, useLoad, useNow } from "../components/common";
import { dateTime, endpoint, oneLine } from "../format";
import { useLiveBlocks } from "../live";
import { useBlockMarks, useReducedMotion, type BlockMark } from "../liveBlocks";
import { useLiveRefresh } from "../useLiveRefresh";

interface GeoPoint {
  ip: string;
  count: number;
  max_severity: Severity;
  lat: number;
  lon: number;
  country: string | null;
  city: string | null;
  source: "geoip" | "demo";
}

interface GeoAttacks {
  hours: number;
  home: { lat: number; lon: number; label: string } | null;
  geoip_status: string;
  demo: boolean;
  points: GeoPoint[];
  unlocated_sources: number;
}

const WIDTH = 960;
const HEIGHT = 500;
/** At most this many shots fly at once; the rest are counted as "+N more" (floods stay readable). */
export const MAX_SHOTS = 30;
const SHOT_MS = 1400;
const FEED_SIZE = 20;
/** Block events keep their own places in the feed, so a flood of alerts can't push them out. */
const FEED_BLOCKS = 5;
const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const topo = countriesTopo as unknown as Topology<{ countries: GeometryCollection }>;
const COUNTRIES = feature(topo, topo.objects.countries) as FeatureCollection<Geometry>;

interface Shot { key: number; d: string; sev: Severity }
export type FeedItem =
  | { key: number; kind: "alert"; at: number; alert: Alert; located: boolean }
  | { key: number; kind: "block"; at: number; event: LiveBlockEvent };

/** Points from the last load plus live alerts since then: a new source appears at once (if the
 *  live message carried its location), a known one counts up. Exported for tests. */
export function mergeLivePoints(points: GeoPoint[], live: Map<string, { geo: GeoLocation; count: number; sev: Severity }>): GeoPoint[] {
  const out = points.map((p) => {
    const l = live.get(p.ip);
    if (!l) return p;
    return { ...p, count: p.count + l.count, max_severity: SEV_RANK[l.sev] > SEV_RANK[p.max_severity] ? l.sev : p.max_severity };
  });
  const known = new Set(points.map((p) => p.ip));
  for (const [ip, l] of live) {
    if (known.has(ip)) continue;
    out.push({ ip, count: l.count, max_severity: l.sev, lat: l.geo.lat, lon: l.geo.lon,
      country: l.geo.country, city: l.geo.city, source: l.geo.source });
  }
  return out;
}

/** Newest first: the latest FEED_SIZE alerts plus the latest FEED_BLOCKS block events.
 *  Exported for tests. */
export function trimFeed(items: FeedItem[]): FeedItem[] {
  let alerts = 0;
  let blocks = 0;
  return items.filter((i) => (i.kind === "alert" ? ++alerts <= FEED_SIZE : ++blocks <= FEED_BLOCKS));
}

function markText(m: BlockMark | undefined): string {
  return m === "blocked" ? " · blocked" : m === "would" ? " · would block (dry-run)" : "";
}

/** World attack map for the Maps page; the page owns the time window. `compact` (the Threat
 *  Center) draws only the map card, with the setup notices as one line under it.
 *  Live: each alert sends a shot along its line to the protected site, blocks mark their source,
 *  and (full page) a feed lists the latest events. With reduced motion there are no shots. */
export default function WorldMap({ hours, compact = false, playback = false }: { hours: number; compact?: boolean; playback?: boolean }) {
  const { data, error, reload } = useLoad(() => api<GeoAttacks>(`/geo/attacks${query({ hours })}`), [hours]);
  const recorded = useLoad(async () => {
    if (!playback) return [];
    const since = new Date(Date.now() - hours * 3_600_000).toISOString();
    const page = await api<Page<Alert>>(`/alerts${query({ since, limit: FEED_SIZE })}`);
    return page.items.slice().reverse();
  }, [hours, playback]);
  const [played, setPlayed] = useState(0);
  const currentMarks = useBlockMarks();
  const marks = playback ? new Map<string, BlockMark>() : currentMarks;
  const reduceMotion = useReducedMotion();
  const now = useNow(2000);

  const [shots, setShots] = useState<Shot[]>([]);
  const shotsRef = useRef<Shot[]>([]); // the source of truth, so a flood is counted exactly once
  const [overflow, setOverflow] = useState(0);
  const [feed, setFeed] = useState<FeedItem[]>([]);
  const [paused, setPaused] = useState(false);
  const [missed, setMissed] = useState(0);
  const [live, setLive] = useState<Map<string, { geo: GeoLocation; count: number; sev: Severity }>>(new Map());
  const recent = useRef<number[]>([]); // alert arrival times, for the per-minute count
  const seq = useRef(0);
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);
  const later = useCallback((fn: () => void, ms: number) => {
    const t = setTimeout(() => { timers.current.delete(t); fn(); }, ms);
    timers.current.add(t);
  }, []);

  // A fresh load already counts the live alerts it covers.
  useEffect(() => { setLive(new Map()); }, [data]);

  const projection = useMemo(() => geoEqualEarth().fitExtent([[8, 8], [WIDTH - 8, HEIGHT - 8]], { type: "Sphere" }), []);
  const path = useMemo(() => geoPath(projection), [projection]);
  const land = useMemo(() => COUNTRIES.features.map((f: Feature<Geometry>, i: number) => (
    <path key={i} d={path(f) ?? ""} className="map-land" />
  )), [path]);
  const home = data?.home ?? null;

  const arcFrom = useCallback((lon: number, lat: number): string => {
    if (!home) return "";
    const interp = geoInterpolate([lon, lat], [home.lon, home.lat]);
    const coords = Array.from({ length: 33 }, (_, i) => interp(i / 32));
    return path({ type: "LineString", coordinates: coords }) ?? "";
  }, [home, path]);

  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const pushFeed = useCallback((item: FeedItem) => {
    if (pausedRef.current) { setMissed((n) => n + 1); return; }
    setFeed((f) => trimFeed([item, ...f]));
  }, []);

  const onAlert = useCallback((a: Alert) => {
    const la = a as LiveAlert;
    const t = Date.now();
    recent.current = [...recent.current.filter((x) => x > t - 60_000), t];
    const geo = la.src_geo ?? null;
    if (geo) {
      setLive((m) => {
        const next = new Map(m);
        const cur = next.get(a.src_ip);
        next.set(a.src_ip, {
          geo, count: (cur?.count ?? 0) + 1,
          sev: cur && SEV_RANK[cur.sev] >= SEV_RANK[a.severity] ? cur.sev : a.severity,
        });
        return next;
      });
    }
    pushFeed({ key: ++seq.current, kind: "alert", at: playback ? Date.parse(a.received_at) : t, alert: a, located: !!geo });
    if (pausedRef.current || reduceMotion || !geo || !home) return;
    const d = arcFrom(geo.lon, geo.lat);
    if (!d) return;
    if (shotsRef.current.length >= MAX_SHOTS) { setOverflow((n) => n + 1); return; }
    const key = ++seq.current;
    shotsRef.current = [...shotsRef.current, { key, d, sev: a.severity }];
    setShots(shotsRef.current);
    later(() => {
      shotsRef.current = shotsRef.current.filter((x) => x.key !== key);
      setShots(shotsRef.current);
    }, SHOT_MS + 600);
  }, [arcFrom, home, later, playback, pushFeed, reduceMotion]);

  const connected = useLiveRefresh(playback ? () => {} : reload, playback ? undefined : onAlert);
  useLiveBlocks(useCallback((e: LiveBlockEvent) => {
    if (!playback) pushFeed({ key: ++seq.current, kind: "block", at: Date.now(), event: e });
  }, [playback, pushFeed]));

  useEffect(() => {
    const alert = recorded.data?.[played];
    if (!playback || paused || !alert || !data) return;
    const timer = setTimeout(() => {
      const event: LiveAlert = { ...alert, src_geo: data.points.find(p => p.ip === alert.src_ip) };
      onAlert(event);
      setPlayed(played + 1);
    }, 1500);
    return () => clearTimeout(timer);
  }, [playback, paused, played, recorded.data, data, onAlert]);

  // "+N more" fades out once the flood is over.
  useEffect(() => {
    if (overflow === 0) return;
    const t = setTimeout(() => setOverflow(0), 3000);
    return () => clearTimeout(t);
  }, [overflow]);

  const points = useMemo(() => mergeLivePoints(playback ? [] : data?.points ?? [], live), [data, live, playback]);
  const maxCount = Math.max(1, ...points.map((p) => p.count));
  const homeXY = home ? projection([home.lon, home.lat]) : null;
  const perMinute = recent.current.filter((x) => x > now - 60_000).length;

  // Compact (Threat Center grid): always one card, so the grid cell never empties or splits.
  if (compact && !data) {
    return (
      <Card title="Live attack map">
        <ErrorText error={error} />
        {!error && <p className="muted">Loading map…</p>}
      </Card>
    );
  }

  const rate = <Pill tone={perMinute > 0 ? "danger" : "neutral"}>{perMinute} / min</Pill>;
  const map = data && (
    <Card title={playback ? "Recorded alert playback" : compact ? "Live attack map" : "Where attacks come from"}
      actions={
        <div className="row-actions" style={{ alignItems: "center" }}>
          {playback ? <Pill>{played} / {recorded.data?.length ?? 0} alerts</Pill> : rate}
          {playback && played > 0 && played === recorded.data?.length &&
            <button type="button" onClick={() => { setPlayed(0); setFeed([]); setLive(new Map()); setPaused(false); }}>Play again</button>}
          {compact
            ? <Link to={`/maps${query({ view: "world", hours: hours === 1 ? undefined : hours })}`}>Open maps →</Link>
            : (!playback || played < (recorded.data?.length ?? 0)) && (
              <button type="button" className="small" aria-pressed={paused}
                onClick={() => { setPaused((p) => !p); setMissed(0); }}>
                {paused ? `Resume${missed ? ` (${missed} new)` : ""}` : "Pause"}
              </button>
            )}
        </div>
      }>
      <div className="map-wrap">
        <svg className="map-svg" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img"
          aria-label={`World map of ${points.length} attack sources`}>
          <path d={path({ type: "Sphere" }) ?? ""} className="map-sphere" />
          <path d={path(geoGraticule10()) ?? ""} className="map-graticule" />
          {land}
          {home && points.map((p) => (
            <path key={`arc-${p.ip}`} d={arcFrom(p.lon, p.lat)}
              className={`map-arc sev-stroke-${p.max_severity}${marks.get(p.ip) === "blocked" ? " blocked" : ""}`} />
          ))}
          {points.map((p) => {
            const xy = projection([p.lon, p.lat]);
            if (!xy) return null;
            const r = 3 + 9 * Math.sqrt(p.count / maxCount);
            const m = marks.get(p.ip);
            return (
              <g key={p.ip}>
                <circle cx={xy[0]} cy={xy[1]} r={r}
                  className={`map-point sev-fill-${p.max_severity}${p.source === "demo" ? " demo" : ""}`}>
                  <title>{`${p.ip} · ${p.count} alerts · ${p.city ?? ""} ${p.country ?? ""}${p.source === "demo" ? " (demo location)" : ""}${markText(m)}`}</title>
                </circle>
                {m && <circle cx={xy[0]} cy={xy[1]} r={r + 5} className={`map-mark ${m}`} aria-hidden="true" />}
              </g>
            );
          })}
          {shots.map((s) => (
            <circle key={s.key} r={4.5} className={`map-shot sev-fill-${s.sev}`} aria-hidden="true">
              <animateMotion dur={`${SHOT_MS}ms`} path={s.d} fill="freeze" />
            </circle>
          ))}
          {homeXY && shots.map((s) => (
            <circle key={`rip-${s.key}`} cx={homeXY[0]} cy={homeXY[1]} r={6} className="map-ripple" aria-hidden="true" />
          ))}
          {homeXY && (
            <g className="map-home">
              <circle cx={homeXY[0]} cy={homeXY[1]} r={6} />
              <text x={homeXY[0] + 9} y={homeXY[1] + 4}>{home!.label}</text>
            </g>
          )}
        </svg>
        {overflow > 0 && <span className="map-overflow" aria-live="polite">+{overflow} more</span>}
      </div>
      <p className="muted" style={{ marginBottom: 0 }}>
        {points.length} sources placed
        {!playback && data.unlocated_sources ? `, ${data.unlocated_sources} with no known location (private or unknown addresses)` : ""}.
        Dot size: number of alerts. Colour: highest severity.
        {!playback && " Red ring: blocked; dashed ring: a dry-run sensor would block it."}
        {data.demo && " Dashed outline: demo location, not real."}
        {reduceMotion && " Animation is off (your system asks for reduced motion)."}
      </p>
      {compact && (data.geoip_status !== "ok" || data.demo || !home) && (
        <p className="muted small-text" style={{ marginBottom: 0 }}>
          {data.demo && "Lab addresses are shown at made-up demo locations. "}
          {data.geoip_status !== "ok" && `Public addresses can't be placed: ${data.geoip_status}. `}
          {!home && "No protected site set (IDPS_SOC_HOME_LAT / IDPS_SOC_HOME_LON), so no attack lines."}
        </p>
      )}
      {data.geoip_status === "ok" && (
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.
        </p>
      )}
    </Card>
  );

  // A failed refresh keeps the map (and its last data) and says so above it.
  if (compact) return <><ErrorText error={error} />{map}</>;

  return (
    <>
      <ErrorText error={error} />
      {playback && <>
        <ErrorText error={recorded.error} />
        <p className="muted">Playback shows up to {FEED_SIZE} saved alerts from this window, one every 1.5 seconds, with their original receipt times.</p>
        {recorded.data?.length === 0 && <p>No saved alerts in this window. Choose a longer window to look further back.</p>}
      </>}
      {data && (
        <>
          {data.geoip_status !== "ok" && (
            <div className="card notice-box">
              Public addresses can't be placed on the map: {data.geoip_status}. See docs/soc.md.
            </div>
          )}
          {data.demo && (
            <div className="card notice-box">
              <b>Demo locations.</b> Lab (private) addresses are shown at made-up places marked
              “Demo:”. They are not real attacker locations.
            </div>
          )}
          {!home && (
            <div className="card notice-box">
              Set IDPS_SOC_HOME_LAT and IDPS_SOC_HOME_LON to draw attack lines to the protected site.
            </div>
          )}
          <div className="grid cols-main-side">
            {map}
            <LiveFeed items={feed} paused={paused} missed={missed} now={now} playback={playback} connected={connected} />
          </div>
          <Card title="Sources on the map">
            <div className="table-wrap">
              <table>
                <thead><tr><th>Source IP</th><th>Alerts</th><th>Highest severity</th>{!playback && <th>Response</th>}<th>Location</th></tr></thead>
                <tbody>
                  {points.slice().sort((a, b) => b.count - a.count).slice(0, 50).map((p) => {
                    const m = marks.get(p.ip);
                    return (
                      <tr key={p.ip}>
                        <td className="mono">{p.ip}</td>
                        <td>{p.count}</td>
                        <td><SeverityBadge severity={p.max_severity} /></td>
                        {!playback && <td>{m === "blocked" ? <Pill tone="danger">blocked</Pill> : m === "would" ? <Pill tone="warn">would block · dry-run</Pill> : <Pill>observe</Pill>}</td>}
                        <td>{[p.city, p.country].filter(Boolean).join(", ") || "—"}
                          {p.source === "demo" && <span className="muted"> (not real)</span>}</td>
                      </tr>
                    );
                  })}
                  {points.length === 0 && <tr><td colSpan={playback ? 4 : 5} className="muted">No located sources in this window.</td></tr>}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </>
  );
}

function ago(at: number, now: number): string {
  const s = Math.max(0, Math.round((now - at) / 1000));
  return s < 5 ? "now" : s < 60 ? `${s} s ago` : `${Math.floor(s / 60)} min ago`;
}

/** The latest live events, newest first. Announced politely to screen readers, one at a time. */
export function LiveFeed({ items, paused, missed, now, playback = false, connected = true }: {
  items: FeedItem[]; paused: boolean; missed: number; now: number; playback?: boolean; connected?: boolean;
}) {
  return (
    <Card title={playback ? "Recorded feed" : "Live feed"} className="live-feed"
      actions={paused ? <Pill tone="warn">paused{missed ? ` · ${missed} new` : ""}</Pill>
        : playback ? <Pill>recorded</Pill> : <Pill tone={connected ? "ok" : "warn"} dot>{connected ? "live" : "offline"}</Pill>}>
      {items.length === 0
        ? <div className="muted">{playback ? "No alerts played yet." : <>
            Waiting for attacks. New alerts and blocks appear here as sensors report them.{" "}
            <Link to="/maps?view=recorded&hours=168">Replay alerts from the last 7 days</Link>
          </>}</div>
        : (
          <ol className="feed-list" aria-live="polite" aria-relevant="additions">
            {items.map((i) => i.kind === "alert" ? (
              <li key={i.key} className={`feed-item sev-${i.alert.severity}`}>
                <span className="feed-time">{playback ? dateTime(i.alert.received_at) : ago(i.at, now)}</span>
                <span>
                  <Link to={`/alerts/${i.alert.id}`}><b>{oneLine(i.alert.predicted_class, 40)}</b></Link>{" "}
                  <SourceTag source={i.alert.source} />{" "}
                  <SeverityBadge severity={SEVERITIES.includes(i.alert.severity) ? i.alert.severity : "low"} />
                  <span className="mono feed-flow">{i.alert.src_ip} → {endpoint(i.alert.dst_ip, i.alert.dst_port, i.alert.protocol)}</span>
                  {!i.located && <span className="muted small-text"> (not on the map: no known location)</span>}
                </span>
              </li>
            ) : (
              <li key={i.key} className={`feed-item block-${i.event.event}`}>
                <span className="feed-time">{ago(i.at, now)}</span>
                <span>
                  {i.event.event === "blocked" && <Pill tone="danger">blocked · {i.event.source}</Pill>}
                  {i.event.event === "unblocked" && <Pill>unblocked</Pill>}
                  {i.event.event === "would_block" && <Pill tone="warn">would block · dry-run</Pill>}{" "}
                  <span className="mono">{i.event.ip}</span>
                  <span className="muted small-text" style={{ display: "block" }}>sensor #{i.event.sensor_id} · {oneLine(i.event.reason || "no reason given", 120)}</span>
                </span>
              </li>
            ))}
          </ol>
        )}
    </Card>
  );
}
