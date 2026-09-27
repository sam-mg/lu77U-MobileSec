import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Read the project's identity from pyproject.toml, the single source of truth
 * for name, version and URLs. Deliberately a narrow reader rather than a TOML
 * dependency: only the handful of `key = "value"` lines under [project] and
 * [project.urls] are needed, and the build must not gain a dependency to get
 * them.
 */
function projectMeta() {
  const toml = readFileSync(resolve(here, "../../pyproject.toml"), "utf8");
  const section = (name) => {
    const match = toml.match(
      new RegExp(`^\\[${name.replace(".", "\\.")}\\]([\\s\\S]*?)(?=^\\[|\\Z)`, "m"),
    );
    return match ? match[1] : "";
  };
  const value = (body, key) => {
    const match = body.match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, "m"));
    return match ? match[1] : "";
  };

  const project = section("project");
  return {
    name: value(project, "name") || "app",
    version: value(project, "version") || "0.0.0",
    description: value(project, "description"),
    homepage: value(section("project.urls"), "Homepage"),
  };
}

const meta = projectMeta();

/** Substitute %APP_NAME% and friends in index.html at build time. */
function htmlMeta() {
  return {
    name: "project-meta-html",
    transformIndexHtml(html) {
      return html
        .replace(/%APP_NAME%/g, meta.name)
        .replace(/%APP_DESCRIPTION%/g, meta.description);
    },
  };
}

export default defineConfig({
  plugins: [react(), htmlMeta()],
  define: {
    __APP_NAME__: JSON.stringify(meta.name),
    __APP_VERSION__: JSON.stringify(meta.version),
    __APP_HOMEPAGE__: JSON.stringify(meta.homepage),
    __DEMO__: false,
  },
  build: {
    outDir: "../web/static",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true, ws: true },
    },
  },
});
