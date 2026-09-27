// Demo entry point - everything backend-dependent is intercepted before the
// real app is even imported, so `../src/App` and everything under it renders
// completely unmodified. See mock-backend.ts for what's intercepted and why.
import { installMockBackend } from "./mock-backend";
installMockBackend();

import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "../src/App";
import DemoNotice from "./demo-notice";
import "../src/index.css";

// HashRouter (not BrowserRouter) so client-side routes work from a GitHub
// Pages project subpath with no server-side rewrite rule available.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <DemoNotice />
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>,
);
