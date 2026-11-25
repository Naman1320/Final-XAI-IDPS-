const PROTOCOLS: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" };

export function protocolName(n: number): string {
  return PROTOCOLS[n] ?? String(n);
}

export function endpoint(ip: string, port: number, protocol: number): string {
  if (protocol !== 6 && protocol !== 17) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function dateTime(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

export function percent(x: number | null | undefined, digits = 0): string {
  return x === null || x === undefined ? "—" : `${(x * 100).toFixed(digits)}%`;
}

export function num(x: number | null | undefined, digits = 3): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return Math.abs(x) >= 1000 ? x.toLocaleString(undefined, { maximumFractionDigits: 0 }) : x.toFixed(digits);
}

export function label(s: string): string {
  return s.replace(/_/g, " ");
}

/** Untrusted text shown on one line (confirm dialogs, reasons in lists): whitespace, control,
 *  format (bidi, zero-width), private-use and line/paragraph separator characters collapse to one
 *  space, the same classes the server strips. Capped at `max` characters (code points, so an emoji
 *  is never cut in half). */
export function oneLine(text: string, max = 200): string {
  const flat = text.replace(/[\s\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]+/gu, " ").trim();
  const chars = [...flat];
  return chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : flat;
}
