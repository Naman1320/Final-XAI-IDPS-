import { toIsoZ } from "./ui";

/** Two datetime-local inputs. Values are local; `rangeParams` turns them into the ISO-with-Z the API needs. */
export function TimeRangeFields({ since, until, onChange }: {
  since: string; until: string; onChange: (key: "since" | "until", value: string) => void;
}) {
  return (
    <>
      <label className="field">From (your local time)
        <input type="datetime-local" value={since} onChange={(e) => onChange("since", e.target.value)} />
      </label>
      <label className="field">To (your local time)
        <input type="datetime-local" value={until} onChange={(e) => onChange("until", e.target.value)} />
      </label>
    </>
  );
}

export function rangeError(since: string, until: string): string | null {
  if (since && !toIsoZ(since)) return "The start time is not a valid date.";
  if (until && !toIsoZ(until)) return "The end time is not a valid date.";
  if (since && until && new Date(since) > new Date(until)) return "The start time is after the end time.";
  return null;
}

export function rangeParams(since: string, until: string): { since?: string; until?: string } {
  return { since: toIsoZ(since) || undefined, until: toIsoZ(until) || undefined };
}
