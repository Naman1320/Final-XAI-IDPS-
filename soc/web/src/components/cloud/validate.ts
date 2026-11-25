// Client-side checks that mirror the backend's rules (soc/api/cloud), so a mistake is shown next
// to the field before anything is sent. The backend still validates everything.

export const INSTANCE_TYPES = ["t3.micro", "t3.small", "t3.medium", "t3.large", "m5.large", "m5.xlarge", "c5.large", "c5.xlarge", "r5.large"];
export const OPERATING_SYSTEMS = ["Ubuntu 22.04", "Ubuntu 24.04", "Debian 12", "Amazon Linux 2023", "Windows Server 2022"];
export const VOLUME_TYPES = ["gp3", "gp2", "io1", "st1"];

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// Control characters and direction overrides are refused by the server; flag them early.
// eslint-disable-next-line no-control-regex
const BAD_CHARS = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/;

export function checkName(v: string): string | null {
  if (!v) return "Enter a name.";
  if (v.length > 63) return "At most 63 characters.";
  if (!NAME_RE.test(v)) return "Start with a letter or digit; then letters, digits, dots, underscores or hyphens.";
  return null;
}

export function checkSgName(v: string): string | null {
  if (v.length < 3) return "At least 3 characters.";
  if (v.length > 64) return "At most 64 characters.";
  if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]*$/.test(v)) return "Start with a letter or digit; then letters, digits, spaces, dots, underscores or hyphens.";
  return null;
}

export function checkText(v: string, max: number): string | null {
  if (v.length > max) return `At most ${max} characters.`;
  if (BAD_CHARS.test(v)) return "Control or direction characters are not allowed.";
  return null;
}

export function checkBucketName(v: string): string | null {
  if (v.length < 3 || v.length > 63) return "3 to 63 characters.";
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(v)) return "Lower-case letters, digits, dots or hyphens; start and end with a letter or digit.";
  if (v.includes("..") || v.includes(".-") || v.includes("-.")) return "Must not contain '..', '.-' or '-.'.";
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return "Must not look like an IP address.";
  return null;
}

export function checkInt(v: string, min: number, max: number): string | null {
  if (!/^-?\d+$/.test(v.trim())) return "Enter a whole number.";
  const n = Number(v);
  if (n < min || n > max) return `Between ${min} and ${max}.`;
  return null;
}

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
/** IPv4 or IPv6 network in CIDR notation (a prefix is required). */
export function checkCidr(raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Enter a CIDR range such as 10.0.0.0/24.";
  if (v.length > 43) return "Too long for a CIDR range.";
  const m = V4.exec(v);
  if (m) {
    if ([1, 2, 3, 4].some((i) => Number(m[i]) > 255)) return "Each part of the address is 0 to 255.";
    if (Number(m[5]) > 32) return "An IPv4 prefix is 0 to 32.";
    return null;
  }
  if (v.includes(":")) {
    const [addr, prefix, ...rest] = v.split("/");
    if (rest.length || prefix === undefined || !/^\d{1,3}$/.test(prefix) || Number(prefix) > 128) return "An IPv6 range needs a prefix of 0 to 128.";
    const groups = addr.split(":");
    const dbl = (addr.match(/::/g) ?? []).length;
    if (dbl > 1 || !/^[0-9a-fA-F:]+$/.test(addr) || groups.some((g) => g.length > 4)) return "Not a valid IPv6 address.";
    if (dbl === 0 && groups.length !== 8) return "Not a valid IPv6 address.";
    if (groups.length > 8) return "Not a valid IPv6 address.";
    return null;
  }
  return "Use CIDR notation, such as 10.0.0.0/24 (a /32 is a single address).";
}

export interface TagParse { tags: Record<string, string>; error: string | null }
/** One `key=value` per line. */
export function parseTags(text: string): TagParse {
  const tags: Record<string, string> = {};
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    const i = line.indexOf("=");
    if (i < 1) return { tags, error: `"${line.slice(0, 30)}": write each tag as key=value.` };
    const k = line.slice(0, i).trim(), v = line.slice(i + 1).trim();
    if (!/^[A-Za-z0-9 _.:/=+@-]{1,64}$/.test(k)) return { tags, error: `Tag key "${k.slice(0, 30)}": 1 to 64 letters, digits or _ . : / = + @ - or space.` };
    if (v.length > 128) return { tags, error: `Tag "${k}": the value is at most 128 characters.` };
    if (BAD_CHARS.test(v)) return { tags, error: `Tag "${k}": control characters are not allowed.` };
    tags[k] = v;
  }
  if (Object.keys(tags).length > 20) return { tags, error: "At most 20 tags." };
  return { tags, error: null };
}
export const tagsToText = (tags: Record<string, string>) => Object.entries(tags).map(([k, v]) => `${k}=${v}`).join("\n");
