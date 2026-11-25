import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { cloudApi } from "../../api/cloud";
import { ApiError } from "../../api/client";
import { useAuth } from "../../auth";
import "../../pages/cloud/cloud.css";

/** Count of unresolved cloud alerts, for the top navigation. A link to the cloud Alerts page.
 *  Renders nothing while loading, after an error, or when the user may not see cloud data (it
 *  never shows an error in the nav). Refreshes every `pollMs`. */
export default function CloudAlertsBadge({ pollMs = 60_000, to = "/cloud/alerts" }: { pollMs?: number; to?: string }) {
  const { me, can } = useAuth();
  const allowed = me?.permissions === undefined ? Boolean(me) : can("cloud.view");
  const [counts, setCounts] = useState<{ open: number; acknowledged: number; critical: boolean } | null>(null);

  useEffect(() => {
    if (!allowed) { setCounts(null); return; }
    let live = true;
    let denied = false;
    const load = async () => {
      if (denied || document.hidden) return;
      try {
        const r = await cloudApi.notifications(20);
        if (live) setCounts({ open: r.open, acknowledged: r.acknowledged, critical: r.items.some((a) => a.severity === "critical" && a.status === "open") });
      } catch (err) {
        if (live && err instanceof ApiError && err.status === 403) { denied = true; setCounts(null); }
      }
    };
    void load();
    const id = setInterval(() => void load(), pollMs);
    return () => { live = false; clearInterval(id); };
  }, [allowed, pollMs]);

  if (!counts) return null;
  return (
    <Link to={to} className={`cl-badge${counts.critical ? " critical" : ""}`}
      aria-label={`Cloud alerts: ${counts.open} open, ${counts.acknowledged} acknowledged${counts.critical ? ", at least one critical" : ""}`}>
      <span aria-hidden="true">{counts.critical ? "✕ " : "! "}</span>
      Cloud alerts <span className="cl-badge-count">{counts.open}</span>
    </Link>
  );
}
