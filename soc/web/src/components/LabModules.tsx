import { useEffect, useState, type ReactNode } from "react";
import { workspace } from "../workspace";

const endpoints = { cloud: "/cloud/overview", iam: "/iam/me/permissions", c6: "/c6" };
export type Module = keyof typeof endpoints;

// Lab images may predate these modules. Protected routes answer 401/403 even
// before sign-in. Only a 404 positively identifies an absent endpoint.
export function useMissingLabModules(signedIn: boolean) {
  const [missing, setMissing] = useState<Module[] | null>(workspace.lab ? null : []);
  useEffect(() => {
    if (!workspace.lab || !signedIn) return;
    const controller = new AbortController();
    async function check() {
      const results = await Promise.all(Object.entries(endpoints).map(async ([key, path]) => {
        const r = await fetch(workspace.api + path, { credentials: "omit", signal: controller.signal });
        return r.status === 404 ? key as Module : null;
      }));
      if (!controller.signal.aborted) setMissing(results.filter((key): key is Module => key !== null));
    }
    void check().catch(() => { if (!controller.signal.aborted) setMissing([]); });
    return () => controller.abort();
  }, [signedIn]);
  return missing;
}

export function ModulePage({ name, missing, children }: { name: Module; missing: Module[] | null; children: ReactNode }) {
  if (!missing) return <p role="status">Checking lab modules…</p>;
  if (!missing.includes(name)) return children;
  const label = { cloud: "Cloud", iam: "IAM", c6: "C6" }[name];
  return <section className="card"><h1>{label}</h1>
    <p>The running lab SOC does not provide this module.</p>
    <a href={`/${name}`}>Open {label} in Development SOC</a>
  </section>;
}
