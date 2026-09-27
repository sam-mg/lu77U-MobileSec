import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Tailwind is pointed at `demo/tailwind.config.js` by absolute path rather
// than left to find a config on its own. Auto-discovery resolves against the
// working directory, which is `frontend/` for `npm run build:demo`, so it
// picked up the app's `tailwind.config.js` - whose `content` covers only
// `./src`. Any utility used solely in `demo/*.tsx` was therefore scanned out
// of the stylesheet and silently arrived unstyled in the browser; classes
// that happened to also appear somewhere under `src/` kept working, which is
// what hid the problem.
const here = dirname(fileURLToPath(import.meta.url));

export default {
  plugins: {
    tailwindcss: { config: resolve(here, "tailwind.config.js") },
    autoprefixer: {},
  },
};
