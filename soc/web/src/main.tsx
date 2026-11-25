import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { workspace } from "./workspace";
import App from "./App";
import { AuthProvider } from "./auth";
import "./styles.css";

if (workspace.unified) {
  window.addEventListener("pageshow", event => {
    if (event.persisted) window.location.reload();
  });
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter basename={workspace.base || "/"}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
