import { workspace, workspaceDestination } from "../workspace";

export default function WorkspacePicker() {
  if (!workspace.unified) return null;
  return <div className="workspace-picker">
    <label htmlFor="soc-workspace">Workspace</label>
    <select id="soc-workspace" value={workspace.base || "/"} onChange={e => window.location.assign(
      workspaceDestination(window.location.pathname, e.target.value === "/lab" ? "/lab" : "/"))}>
      <option value="/">Development SOC</option>
      <option value="/lab">Lab SOC</option>
    </select>
  </div>;
}
