// Extends the real app's Tailwind config rather than duplicating its theme
// tokens - the demo must render with exactly the same colors, fonts and
// motion as the app it's a preview of, so there is one source of truth for
// them. Only `content` differs: it has to see classes used in `../src` (the
// unmodified app) as well as the demo's own two files.
import base from "../tailwind.config.js";

/** @type {import('tailwindcss').Config} */
export default {
  ...base,
  content: ["./index.html", "./**/*.{ts,tsx}", "../src/**/*.{ts,tsx}"],
};
