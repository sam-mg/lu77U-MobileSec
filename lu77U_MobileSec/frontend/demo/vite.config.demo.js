import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const here = dirname(fileURLToPath(import.meta.url)); // .../frontend/demo

/**
 * Same narrow `pyproject.toml` reader as the real `vite.config.js`, one
 * directory deeper (`demo/` instead of `frontend/`) - everything else about
 * this build is a static-demo variant of that file, not a fork of it.
 */
function projectMeta() {
  const toml = readFileSync(resolve(here, "../../../pyproject.toml"), "utf8");
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

/**
 * Copy the shared favicon set into the demo build.
 *
 * The real app's `public/` directory is Vite's publicDir for the packaged
 * build only; this build's root is `demo/`, whose own `public/` holds the
 * mock API fixtures. Rather than committing a second copy of the icons, the
 * three served files are copied straight out of the app's public directory at
 * the end of the build, so both sites always ship byte-identical icons.
 */
function sharedFavicons() {
  const files = ["favicon.svg", "favicon.ico", "apple-touch-icon.png"];
  const from = resolve(here, "../public");
  return {
    name: "shared-favicons",
    apply: "build",
    closeBundle() {
      const out = resolve(here, "../../../demo-dist");
      mkdirSync(out, { recursive: true });
      for (const file of files) {
        copyFileSync(resolve(from, file), resolve(out, file));
      }
    },
  };
}

const meta = projectMeta();

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
  root: here,
  base: "./",
  plugins: [react(), htmlMeta(), sharedFavicons()],
  resolve: {
    // The static demo cannot upload or scan anything, so the real upload card
    // is swapped for one that says so instead of offering a file picker.
    alias: {
      "../components/UploadCard": resolve(here, "stubs/UploadCard.tsx"),
    },
  },
  define: {
    __APP_NAME__: JSON.stringify(meta.name),
    __APP_VERSION__: JSON.stringify(meta.version),
    __APP_HOMEPAGE__: JSON.stringify(meta.homepage),
    __DEMO__: true,
  },
  build: {
    // Never lands anywhere near `web/static` - the real app's build target -
    // so the packaged app is unaffected by this build.
    outDir: resolve(here, "../../../demo-dist"),
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    fs: {
      // The demo imports `../src/App` etc. from outside its own root.
      allow: [resolve(here, "..")],
    },
  },
});
