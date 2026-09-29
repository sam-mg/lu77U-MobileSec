// Extends the real app's Tailwind config rather than duplicating its theme
// tokens - the demo must render with exactly the same colors, fonts and
// motion as the app it's a preview of, so there is one source of truth for
// them. Only `content` differs: it has to see classes used in `../src` (the
// unmodified app) as well as the demo's own files.
//
// The globs are built from this file's own location rather than left as
// plain relative strings, because Tailwind resolves `content` against
// `process.cwd()` (the frontend/ root `npm run build:demo` is invoked from),
// not against this config file's directory - a bare "../src/**/*.{ts,tsx}"
// silently pointed one directory too high and matched nothing, and a bare
// "./**/*.{ts,tsx}" reached into frontend/node_modules, which is the
// "accidentally matching all of node_modules" warning this file used to
// produce.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import base from "../tailwind.config.js";

const here = dirname(fileURLToPath(import.meta.url));

/** @type {import('tailwindcss').Config} */
export default {
  ...base,
  content: [
    resolve(here, "index.html"),
    resolve(here, "**/*.{ts,tsx}"),
    resolve(here, "../src/**/*.{ts,tsx}"),
  ],
};
