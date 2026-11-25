import { lazy, Suspense } from "react";
import { Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { Pill } from "./components/common";
import ErrorBoundary from "./components/ErrorBoundary";
import { useLiveStatus } from "./live";
import { blockingMode, useSensors } from "./sensors";
import Account from "./pages/Account";
import Assistant from "./pages/Assistant";
import Privacy, { PublicPrivacy } from "./pages/Privacy";
import Reports from "./pages/Reports";
import Admin from "./pages/Admin";
import AlertDetail from "./pages/AlertDetail";
import Alerts from "./pages/Alerts";
import Cases from "./pages/Cases";
import Demo from "./pages/Demo";
import C6 from "./pages/C6";
import { ModulePage, useMissingLabModules } from "./components/LabModules";
import WorkspacePicker from "./components/WorkspacePicker";
import Login from "./pages/Login";
import CloudAlertsBadge from "./components/cloud/CloudAlertsBadge";
import Response from "./pages/Response";

// The map libraries are large, so those pages load on demand.
const ThreatCenter = lazy(() => import("./pages/ThreatCenter"));
const Maps = lazy(() => import("./pages/Maps"));
const CloudModule = lazy(() => import("./pages/cloud"));
const IamModule = lazy(() => import("./pages/iam"));

function Shield() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function LiveBadge() {
  const live = useLiveStatus();
  return live
    ? <Pill tone="ok" round dot>Live feed</Pill>
    : <Pill tone="neutral" round dot>Live feed offline</Pill>;
}

/** What the online sensors do with a block decision. Hidden until a sensor reports its status. */
function ModeBadge() {
  const { data } = useSensors();
  const mode = blockingMode(data);
  if (mode === "unknown") return null;
  if (mode === "on") return <Pill tone="danger" round>Blocking ON · dry-run off</Pill>;
  if (mode === "dry-run") return <Pill tone="warn" round>Dry-run · blocks are only logged</Pill>;
  return <Pill tone="warn" round>Blocking on some sensors only</Pill>;
}

const loading = <p className="muted">Loading…</p>;

/** Redirect an old address, keeping its query string (e.g. /blocks?ip=… → /response?ip=…). */
function Redirect({ to, add = {} }: { to: string; add?: Record<string, string> }) {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  for (const [k, v] of Object.entries(add)) params.set(k, v);
  const qs = params.toString();
  return <Navigate to={qs ? `${to}?${qs}` : to} replace />;
}

export default function App() {
  const { me, loading: authLoading, logout, can } = useAuth();
  // UI hint only: the backend enforces every permission.
  const showIam = ["iam.users.view", "iam.roles.view", "iam.groups.view", "iam.policies.view", "iam.audit.view", "iam.logins.view"].some(can);
  const location = useLocation();
  const missing = useMissingLabModules(Boolean(me));

  if (authLoading) return <p className="muted" style={{ padding: 24 }}>Loading…</p>;
  if (!me) return location.pathname.replace(/\/+$/, "") === "/privacy" ? <PublicPrivacy /> : <Login />;

  return (
    <div className="app">
      <div className="shell">
        <header className="topbar">
          <div className="brand"><Shield />IDPS SOC</div>
          <WorkspacePicker />
          <nav className="nav" aria-label="Main">
            <NavLink to="/" end>Dashboard</NavLink>
            <NavLink to="/alerts">Alerts</NavLink>
            <NavLink to="/response">Response</NavLink>
            <NavLink to="/cases">Cases</NavLink>
            <NavLink to="/maps">Maps</NavLink>
            <NavLink to="/assistant">Assistant</NavLink>
            <NavLink to="/reports">Reports</NavLink>
            <NavLink to="/demo">Live demo</NavLink>
            {me.role === "admin" && <NavLink to="/c6">C6</NavLink>}
            {can("cloud.view") && <NavLink to="/cloud">Cloud</NavLink>}
            {showIam && <NavLink to="/iam">IAM</NavLink>}
            <NavLink to="/privacy">Privacy</NavLink>
            {me.role === "admin" && <NavLink to="/admin">Admin</NavLink>}
          </nav>
          <div className="topbar-status">
            {missing && !missing.includes("cloud") && <CloudAlertsBadge />}
            <LiveBadge />
            <ModeBadge />
            <div className="userbox">
              <NavLink to="/account" className="userlink" title="Account and two-factor sign-in">
                <b>{me.username}</b> ({me.role})
              </NavLink>
              <button type="button" onClick={logout}>Sign out</button>
            </div>
          </div>
        </header>
        <main>
          <ErrorBoundary resetKey={location.pathname + location.search}>
            <Routes>
              <Route path="/" element={<Suspense fallback={loading}><ThreatCenter /></Suspense>} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/response" element={<Response />} />
              <Route path="/assistant" element={<Assistant />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/cases/:id" element={<Cases />} />
              <Route path="/maps" element={<Suspense fallback={loading}><Maps /></Suspense>} />
              <Route path="/account" element={<Account />} />
              <Route path="/reports" element={<Reports />} />
              {me.role === "admin" && <Route path="/c6" element={<ModulePage name="c6" missing={missing}><C6 /></ModulePage>} />}
              <Route path="/demo" element={<Demo />} />
              <Route path="/cloud/*" element={<ModulePage name="cloud" missing={missing}><Suspense fallback={loading}><CloudModule /></Suspense></ModulePage>} />
              <Route path="/iam/*" element={<ModulePage name="iam" missing={missing}><Suspense fallback={loading}><IamModule /></Suspense></ModulePage>} />
              <Route path="/privacy" element={<Privacy />} />
              {/* Old addresses, kept so bookmarks and links in docs still work. */}
              <Route path="/metrics" element={<Redirect to="/" />} />
              <Route path="/blocks" element={<Redirect to="/response" />} />
              <Route path="/actions" element={<Redirect to="/response" />} />
              <Route path="/map" element={<Redirect to="/maps" add={{ view: "world" }} />} />
              <Route path="/topology" element={<Redirect to="/maps" />} />
              {me.role === "admin" && <Route path="/admin" element={<Admin />} />}
              <Route path="*" element={<p className="muted">Page not found.</p>} />
            </Routes>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
