import { render, screen } from "@testing-library/react";
import { ModulePage } from "../components/LabModules";
import { workspaceDestination, workspaceFor } from "../workspace";

it("separates lab routes, tokens and SSO state while preserving existing development sessions", () => {
  const dev = workspaceFor("/alerts", true);
  const lab = workspaceFor("/lab/alerts", true);
  expect([dev.api, lab.api]).toEqual(["/api", "/lab-api"]);
  for (const key of ["idps-soc-token", "idps-sso-binding"]) {
    expect(dev.storageKey(key)).toBe(key);
    expect(lab.storageKey(key)).not.toBe(dev.storageKey(key));
  }
  expect(workspaceFor("/laboratory", true).lab).toBe(false);
  expect(workspaceFor("/lab", true).lab).toBe(true);
  expect(workspaceFor("/lab", false).lab).toBe(false);
});

it("switches databases within the same section without carrying a resource ID or callback", () => {
  expect(workspaceDestination("/lab/alerts/12", "/")).toBe("/alerts");
  expect(workspaceDestination("/iam/users/4", "/lab")).toBe("/lab/iam");
  expect(workspaceDestination("/lab/auth/callback", "/")).toBe("/");
});

it("identifies an unavailable lab module and keeps the development destination explicit", () => {
  render(<ModulePage name="iam" missing={["iam"]}>Lab users</ModulePage>);
  expect(screen.queryByText("Lab users")).toBeNull();
  expect(screen.getByRole("link", { name: "Open IAM in Development SOC" })).toHaveAttribute("href", "/iam");
});
