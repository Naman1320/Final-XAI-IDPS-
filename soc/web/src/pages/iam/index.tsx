// The IAM module: sub-navigation plus its pages. The app mounts it at /iam/*.
import { NavLink, Route, Routes } from "react-router-dom";
import { ToastProvider, useCan } from "../../components/iam/ui";
import { useBase } from "../../components/iam/shared";
import Audit from "./Audit";
import Groups from "./Groups";
import Logins from "./Logins";
import Overview, { SECTIONS } from "./Overview";
import Policies from "./Policies";
import Roles from "./Roles";
import UserDetail from "./UserDetail";
import Users from "./Users";
import "./iam.css";

function SubNav() {
  const can = useCan();
  const base = useBase();
  return (
    <nav className="iam-subnav" aria-label="Identity and access sections">
      <NavLink to={base || "/"} end>Overview</NavLink>
      {SECTIONS.filter((s) => can(s.perm)).map((s) => <NavLink key={s.path} to={`${base}/${s.path}`}>{s.title}</NavLink>)}
    </nav>
  );
}

export default function IamModule() {
  return (
    <ToastProvider>
      <div className="stack">
        <SubNav />
        <Routes>
          <Route index element={<Overview />} />
          <Route path="users" element={<Users />} />
          <Route path="users/:id" element={<UserDetail />} />
          <Route path="roles" element={<Roles />} />
          <Route path="groups" element={<Groups />} />
          <Route path="policies" element={<Policies />} />
          <Route path="logins" element={<Logins />} />
          <Route path="audit" element={<Audit />} />
          <Route path="*" element={<div className="error" role="alert">That IAM page does not exist.</div>} />
        </Routes>
      </div>
    </ToastProvider>
  );
}
