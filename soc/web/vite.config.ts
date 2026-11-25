/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { Agent } from "node:https";
import { defineConfig, type ProxyOptions } from "vite";

// Both HTTP and WebSocket traffic use the same fixed upstream for a workspace.
// Worker/ingest endpoints are service interfaces, outside the lab browser gateway.
function labPath(url: string) {
  const rest = url.slice("/lab-api".length);
  const path = rest.split("?", 1)[0];
  let decoded: string;
  try { decoded = decodeURIComponent(path); } catch { return "/__unavailable__"; }
  if (!/^\/[\w./:-]*$/.test(decoded) || /(^|\/)\.{1,2}(\/|$)|\/\//.test(decoded)) return "/__unavailable__";
  const sections = /^\/(health|auth|alerts|actions|blocks|cases|metrics|geo|topology|assistant|reports|privacy|models|sensors|status|training|iam|cloud|ws)(\/|$)/;
  const admin = /^\/admin\/(audit|users|sensors|retention|integrations|privacy|reports)(\/|$)/;
  return sections.test(decoded) || admin.test(decoded) ||
    ["/demo", "/admin/demo/cancel", "/c6", "/admin/c6/run"].includes(decoded) ? rest : "/__unavailable__";
}

function labAgent() {
  const file = process.env.IDPS_SOC_LAB_CA;
  if (file) return new Agent({ ca: readFileSync(file) });
  try {
    return new Agent({ ca: execFileSync("docker", ["exec", "idps-soc", "cat", "/run/idps-soc/ca.pem"],
      { timeout: 4000, stdio: ["ignore", "pipe", "ignore"] }) });
  } catch {
    // Development remains usable when the lab is down. TLS still requires a trusted certificate.
    return new Agent();
  }
}

export default defineConfig(({ mode, command }) => {
  const unified = mode === "unified";
  const proxy: Record<string, ProxyOptions> = {
    "^/api(?:/|$)": {
      target: process.env.IDPS_SOC_API ?? (unified ? "http://127.0.0.1:8040" : "http://127.0.0.1:8000"),
      changeOrigin: true, ws: true, rewrite: path => path.replace(/^\/api/, ""),
    },
  };
  if (unified && command === "serve") {
    const lab = new URL(process.env.IDPS_SOC_LAB_API ?? "https://127.0.0.1:8443");
    if (lab.protocol !== "https:" || lab.hostname !== "127.0.0.1" || lab.username ||
        lab.password || lab.pathname !== "/" || lab.search || lab.hash) {
      throw new Error("IDPS_SOC_LAB_API must be a loopback HTTPS origin on 127.0.0.1");
    }
    proxy["^/lab-api(?:/|$)"] = {
      target: lab.origin, agent: labAgent(), secure: true,
      changeOrigin: true, ws: true, rewrite: labPath,
    };
  }
  return {
    plugins: [react()],
    build: { outDir: mode === "iphone" ? "dist-iphone" : unified ? "dist-unified" : "dist" },
    server: { host: "127.0.0.1", port: 5173, strictPort: unified, proxy },
    preview: { host: "127.0.0.1", port: unified ? 5173 : 4173, strictPort: unified, proxy },
    test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"] },
  };
});
