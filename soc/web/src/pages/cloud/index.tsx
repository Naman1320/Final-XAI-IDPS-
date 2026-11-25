import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { CloudContextProvider, DataSourceBanner, ToastProvider, useSourceState } from "../../components/cloud/ui";
import Activity from "./Activity";
import Alerts from "./Alerts";
import Compute from "./Compute";
import Cost from "./Cost";
import InstanceDetail from "./InstanceDetail";
import Monitoring from "./Monitoring";
import Network from "./Network";
import Overview from "./Overview";
import Storage from "./Storage";
import "./cloud.css";

const SECTIONS: { to: string; label: string; end?: boolean }[] = [
  { to: ".", label: "Overview", end: true },
  { to: "compute", label: "Compute" },
  { to: "storage", label: "Storage" },
  { to: "network", label: "Network" },
  { to: "monitoring", label: "Monitoring" },
  { to: "cost", label: "Cost" },
  { to: "alerts", label: "Alerts" },
  { to: "activity", label: "Activity" },
];

/** Cloud management: mount at /cloud/*. Everything it shows comes from /api/cloud; the banner
 *  repeats whatever data_source_label the API sends. */
export default function CloudModule() {
  const source = useSourceState();
  return (
    <CloudContextProvider value={source}>
      <ToastProvider>
        <div className="cl-module">
          <p className="eyebrow cl-eyebrow">Cloud management</p>
          <DataSourceBanner />
          <nav className="cl-subnav" aria-label="Cloud sections">
            {SECTIONS.map((s) => <NavLink key={s.label} to={s.to} end={s.end}>{s.label}</NavLink>)}
          </nav>
          <Routes>
            <Route index element={<Overview />} />
            <Route path="compute" element={<Compute />} />
            <Route path="compute/:id" element={<InstanceDetail />} />
            <Route path="storage" element={<Storage />} />
            <Route path="network" element={<Network />} />
            <Route path="monitoring" element={<Monitoring />} />
            <Route path="cost" element={<Cost />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="activity" element={<Activity />} />
            <Route path="*" element={<Navigate to="." replace />} />
          </Routes>
        </div>
      </ToastProvider>
    </CloudContextProvider>
  );
}
