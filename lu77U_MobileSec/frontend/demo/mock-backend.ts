/**
 * Static-demo backend.
 *
 * Patches `window.fetch` so the shipped React app - its components and
 * `../src/api.ts` are imported completely unmodified - reads pre-generated
 * JSON instead of talking to a real server:
 *
 *   - Reads  (GET /api/version|status|scans|scans/:id|settings|
 *             settings/models/:provider) resolve to files under
 *             `demo-data/`, built by `scripts/build_demo_data.py`.
 *             Logs are not published: the log panel is compiled out of
 *             the demo build, so that route answers empty.
 *   - Writes (anything else under /api/ - create/stop/pause/resume/delete
 *             scan, settings PUT, credentials, test) resolve to HTTP 501.
 *             `api.ts`'s `http()` helper turns that into an `ApiError`,
 *             which the components already render in their own error slots
 *             - no new UI, just the app's existing failure path.
 *
 * `window.confirm` (gates the Delete buttons) and clicks on the report/log
 * download links (`<a href="/api/...">`, not `fetch` calls) are intercepted
 * the same way below, so every backend-dependent control stays visible and
 * styled exactly as in the real app but never reaches a real action.
 */

export const DEMO_MESSAGE =
  "This is a static demonstration - no analysis runs here. Install and run lu77U-MobileSec locally to analyze your own app.";

/** Fired on `window` whenever a blocked action is attempted, so the toast in
 * `demo-notice.tsx` can surface it without this module reaching into React. */
export const DEMO_BLOCKED_EVENT = "demo:blocked";

const realFetch = window.fetch.bind(window);

function notifyDemo() {
  window.dispatchEvent(new CustomEvent(DEMO_BLOCKED_EVENT, { detail: DEMO_MESSAGE }));
}

/** Resolve a `demo-data/...` file relative to wherever this page actually
 * lives (works unmodified under a GitHub Pages project subpath). */
function dataUrl(relPath: string): string {
  return new URL(`demo-data/${relPath}`, document.baseURI).toString();
}

async function readJsonFile(relPath: string): Promise<any | null> {
  try {
    const res = await realFetch(dataUrl(relPath));
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function denied(): Response {
  notifyDemo();
  return jsonResponse({ detail: DEMO_MESSAGE }, 501);
}

function notFound(detail = "Not found in this demo."): Response {
  return jsonResponse({ detail }, 404);
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function requestMethod(input: RequestInfo | URL, init?: RequestInit): string {
  if (init?.method) return init.method.toUpperCase();
  if (typeof input !== "string" && !(input instanceof URL)) return (input.method || "GET").toUpperCase();
  return "GET";
}

async function handleApi(pathname: string, method: string): Promise<Response> {
  if (method !== "GET") return denied();

  if (pathname === "/api/version") {
    return jsonResponse((await readJsonFile("version.json")) ?? { name: "lu77U-MobileSec", version: "" });
  }
  if (pathname === "/api/status") {
    return jsonResponse((await readJsonFile("status.json")) ?? {});
  }
  if (pathname === "/api/scans") {
    return jsonResponse((await readJsonFile("scans.json")) ?? { scans: [] });
  }
  if (pathname === "/api/settings") {
    const settings = await readJsonFile("settings.json");
    return settings ? jsonResponse(settings) : notFound();
  }

  // No logs ship with the demo (the log panel is compiled out of this build),
  // so anything still asking for them gets an empty, successful answer rather
  // than an error the UI would have to render.
  let m = pathname.match(/^\/api\/scans\/([^/]+)\/logs$/);
  if (m) {
    return jsonResponse({ scan_id: m[1], count: 0, logs: [], persisted: false });
  }

  m = pathname.match(/^\/api\/scans\/([^/]+)$/);
  if (m) {
    const scan = await readJsonFile(`scans/${m[1]}.json`);
    return scan ? jsonResponse(scan) : notFound("Scan not found");
  }

  m = pathname.match(/^\/api\/settings\/models\/([^/]+)$/);
  if (m) {
    const models = await readJsonFile(`models/${m[1]}.json`);
    return jsonResponse(models ?? { provider: m[1], models: [] });
  }

  // Settings.tsx's CLI status block reads its found/signed-in state from
  // THIS live-probe endpoint, not from the `/api/settings` snapshot's own
  // (cheaper, PATH-only) `cli_found` field - so without this route every
  // CLI provider in the demo would show "not found on PATH" regardless of
  // what settings.json says, defeating the point of demoing it at all.
  // Faked straight from the matching provider's settings.json entry.
  m = pathname.match(/^\/api\/settings\/cli-status\/([^/]+)$/);
  if (m) {
    const settings = await readJsonFile("settings.json");
    const provider = settings?.providers?.[m[1]];
    if (!provider?.is_cli) return notFound();
    return jsonResponse({
      binary_path: provider.binary_path ?? "",
      cli_binary: provider.cli_binary,
      cli_found: provider.cli_found ?? false,
      cli_resolved_path: provider.cli_resolved_path ?? null,
      signin_hint: provider.signin_hint ?? "",
      signed_in: provider.cli_found ?? false,
      detail: null,
    });
  }

  return notFound();
}

function installFetchPatch() {
  window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = requestUrl(input);
    let pathname: string;
    try {
      pathname = new URL(url, window.location.href).pathname;
    } catch {
      pathname = url;
    }
    if (!pathname.startsWith("/api/")) return realFetch(input, init);
    return handleApi(pathname, requestMethod(input, init));
  }) as typeof window.fetch;
}

/**
 * The only `confirm()` in the app gates the Delete buttons
 * ("Delete this scan and its outputs?" - Scans.tsx, ScanDetail.tsx).
 * Always declining keeps every Delete click a no-op past this point, so the
 * mutating call below it never fires - belt-and-braces alongside the 501s.
 */
function installConfirmPatch() {
  window.confirm = () => {
    notifyDemo();
    return false;
  };
}

/**
 * Report/log download links (`ReportLink` in ScanDetail.tsx, `logsDownloadUrl`)
 * are plain `<a href="/api/...">` anchors, not `fetch` calls - caught here
 * with one document-level listener instead of editing that component.
 */
function installDownloadInterceptor() {
  document.addEventListener(
    "click",
    (e) => {
      const anchor = (e.target as HTMLElement)?.closest?.("a[href]") as HTMLAnchorElement | null;
      if (!anchor) return;
      const href = anchor.getAttribute("href") || "";
      if (!href.startsWith("/api/")) return;
      e.preventDefault();
      notifyDemo();
    },
    true,
  );
}

/** A couple of the Settings save buttons fire-and-forget without their own
 * `.catch` - this still surfaces the demo message instead of letting the
 * click die silently in the console. */
function installUnhandledRejectionNotice() {
  window.addEventListener("unhandledrejection", (e) => {
    notifyDemo();
    e.preventDefault();
  });
}

export function installMockBackend() {
  installFetchPatch();
  installConfirmPatch();
  installDownloadInterceptor();
  installUnhandledRejectionNotice();
}
