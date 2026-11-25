// Each document belongs to one SOC. Switching replaces the document, closing its
// sockets and dropping pending requests, MFA state and in-memory page caches.
export function workspaceFor(path: string, unified: boolean) {
  const lab = unified && (path === "/lab" || path.startsWith("/lab/"));
  return {
    unified, lab,
    base: lab ? "/lab" : "",
    api: lab ? "/lab-api" : "/api",
    storageKey: (key: string) => lab ? key + ":lab" : key,
  };
}

export const phoneBuild = import.meta.env.MODE === "iphone";
export const workspace = workspaceFor(window.location.pathname, phoneBuild || import.meta.env.MODE === "unified");

// Carry the section across, never a record ID, search, or an SSO callback from another database.
const sections = new Set(["alerts", "response", "cases", "maps", "assistant", "reports", "demo",
  "cloud", "iam", "c6", "privacy", "admin", "account"]);
export function workspaceDestination(path: string, next: "/" | "/lab") {
  const section = path.replace(/^\/lab(?:\/|$)/, "/").split("/")[1];
  return (next === "/lab" ? "/lab" : "") + (sections.has(section) ? "/" + section : "/");
}
