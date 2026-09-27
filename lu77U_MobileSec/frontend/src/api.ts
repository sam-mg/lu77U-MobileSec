// Typed client for the lu77U-MobileSec local API.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanSummary {
  primary_framework?: string | null;
  total_vulnerabilities?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  security_score?: number | null;
  package_name?: string | null;
  app_name?: string | null;
  analysis_supported?: boolean;
}

export type ScanStatus =
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled";

export interface ScanMeta {
  id: string;
  filename: string;
  status: ScanStatus;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  duration: number;
  progress: number;
  phase: string;
  error?: string | null;
  /** Why a paused scan is paused: "user" (Pause button), "interrupted"
   * (server died mid-scan and reconciled it on the next boot), or
   * "provider_quota" (a subscription-CLI-backed provider's rolling-window
   * quota ran out mid-scan - see ai/cli_provider.py - and will retry
   * automatically once `resume_after` passes). */
  pause_reason?: "user" | "interrupted" | "provider_quota" | null;
  /** How many times auto-resume has already retried this scan after a
   * server-crash interruption. Separate from a quota pause's own counter
   * (`quota_resume_attempts`) - the two never share a budget. */
  resume_attempts?: number;
  /** ISO timestamp: when a "provider_quota" pause is next eligible for
   * automatic resume. Only set for that pause reason. */
  resume_after?: string | null;
  /** How many times a "provider_quota" pause has already been auto-resumed. */
  quota_resume_attempts?: number;
  /** Whether a checkpoint exists to resume from. */
  resumable?: boolean;
  summary: ScanSummary;
  reports: Partial<Record<"json" | "html" | "pdf", boolean>>;
}

export interface LogLine {
  message: string;
  ts: string;
}

export interface CodeContext {
  start_line: number;
  end_line: number;
  highlight_start: number;
  highlight_end: number;
  lines: string[];
  lines_html?: string[];
}

/** What the validation gates concluded about a finding. */
export interface GateResult {
  verdict: "PASS" | "DOWNGRADE" | "CHAIN_REQUIRED" | "FALSE_POSITIVE" | "INFORMATIONAL";
  reasons: string[];
  warnings?: string[];
  /** Severity before grading - shown so a downgrade is visible, not silent. */
  original_severity: string;
  final_severity: string;
  chain_eligible: boolean;
  weak_class_rule?: string;
  /** Set only when FALSE_POSITIVE was reached by checking the finding's own
   * cited code for the construct its title names, with no model call - e.g.
   * a title claiming "Hardcoded AES key" whose snippet contains none of
   * AES/SecretKeySpec/Cipher/javax.crypto. Distinguishes that from an LLM
   * review that simply was not convinced. */
  mechanically_refuted?: boolean;
}

/** An exploit chain: several findings that combine into one attack path. */
export interface Chain {
  id: string;
  pattern: string;
  priority: boolean;
  /** Titles of the findings this chain is built from. */
  components: string[];
  /** Ordered attacker steps. */
  flow: string[];
}

export interface Vulnerability {
  title: string;
  severity: string;
  description?: string;
  file?: string;
  location?: string;
  line_start?: number;
  line_end?: number;
  impact?: string;
  cwe?: string;
  owasp_mobile?: string;
  code_snippet?: string;
  code_context?: CodeContext | null;
  exploitation?: string;
  recommendation?: string;
  /** Catalogue code, e.g. "AND-05" or a chain pattern id. */
  vuln_class?: string;
  gate_result?: GateResult | null;
  chain?: Chain | null;
  /** Chain ids this finding is a component of. */
  chained_into?: string[];
  /** Same-file groupings and unconfirmed chain-table pairings. Not a verdict:
      `confirmed` is only true once the chain builder validated the pair. */
  related_findings?: {
    pattern: string;
    reason: string;
    confirmed: boolean;
    with: { title: string; file: string; line: string };
  }[];
  /** Which detector produced it: "static-analyzer", "semgrep", "chain-builder". */
  source?: string;
  /** Which surface agent found it. */
  surface?: string;
}

export interface FrameworkInfo {
  name: string;
  confidence: number;
  confidence_level: string;
  indicators_found?: string[];
}

export interface ScanResult {
  metadata?: Record<string, unknown>;
  framework_detection?: {
    detected: boolean;
    primary_framework: string;
    confidence: number;
    confidence_level: string;
    frameworks: FrameworkInfo[];
  };
  application_info?: {
    package_name?: string;
    app_name?: string;
    version_name?: string;
    version_code?: number;
    min_sdk?: number;
    target_sdk?: number;
    file_size?: number;
    file_size_mb?: number;
    permissions?: string[];
    activities?: string[];
    services?: string[];
    receivers?: string[];
    providers?: string[];
  };
  vulnerability_analysis?: {
    analyzed: boolean;
    total_vulnerabilities: number;
    by_severity: Record<Severity, number>;
    vulnerabilities: Record<Severity, Vulnerability[]>;
    /** Findings the mechanical evidence gate refuted before any model call.
     * Already excluded from `by_severity`/`vulnerabilities`/the score above -
     * kept here, never dropped, so the tool's own mistakes stay visible. */
    refuted?: Vulnerability[];
    refuted_count?: number;
  };
  summary?: {
    framework_detected?: boolean;
    vulnerability_scan_complete?: boolean;
    total_vulnerabilities?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    /** Refuted by the mechanical evidence gate - never counted or scored. */
    refuted_count?: number;
    /** null when nothing was analysed - render an em dash, not a perfect score. */
    security_score?: number | null;
    /** Uncapped severity-weighted total. Comparable across scans; the 0-100
        score compresses at high finding counts and this one does not. */
    weighted_finding_count?: number;
    security_grade?: string;
  };
  analysis?: {
    supported: boolean;
    success: boolean;
    files_analyzed: number;
    analysis_time: number;
    framework: string;
    decompilation_status?: string;
    unsupported_framework?: boolean;
    error?: string | null;
  };
  reports?: Record<"json" | "html" | "pdf", boolean>;
}

export interface StoredApiKey {
  index: number;
  /** e.g. "3f49…avIX" - the full value is never included here; fetch it
   * explicitly with `api.revealCredential`. */
  masked: string;
}

export interface ProviderSettings {
  name: string;
  display_name: string;
  model: string;
  mode?: string | null;
  base_url?: string | null;
  cloud_host?: string | null;
  local_host?: string | null;
  has_api_key: boolean;
  /** The failover pool, in the order a scan tries them. */
  api_keys: StoredApiKey[];
  api_key_count: number;
  /** How many calls into this provider a scan may run at once, across every
   * region thread. A single call that runs long - a model that fails to
   * converge, a slow network - used to let every other thread queue up
   * behind it with nothing coordinating them; this caps how many can be in
   * flight together instead. */
  max_concurrent_requests: number;
  default_model: string;
  needs_api_key: boolean;
  /** True for a subscription-CLI-backed provider (Claude Code, Copilot,
   * Kimi, Codex, Antigravity CLIs) - billed against a login, not an API
   * key. See `cli_binary` / `binary_path` / `signin_hint` below. */
  is_cli: boolean;
  /** User-set override; empty string means "resolve from PATH". Only
   * meaningful when `is_cli` is true. */
  binary_path?: string;
  /** The executable name this provider shells out to, e.g. "claude". */
  cli_binary?: string;
  /** Cheap PATH-resolution check - does NOT confirm the subscription is
   * signed in; see `getCliStatus` for the live probe. */
  cli_found?: boolean;
  cli_resolved_path?: string | null;
  /** One-line instruction for the one-time interactive sign-in this tool
   * cannot do on the user's behalf. */
  signin_hint?: string;
}

export interface CliStatus {
  binary_path: string;
  cli_binary: string;
  cli_found: boolean;
  cli_resolved_path: string | null;
  signin_hint: string;
  /** Result of a live, cheap probe call - false whenever `cli_found` is
   * false too, since there is nothing to probe. */
  signed_in: boolean;
  detail: string | null;
}

export interface CustomPreset {
  label: string;
  base_url: string;
  model: string;
}

export interface AnalysisStatus {
  jadx_configured: boolean;
  ollama_configured: boolean;
  blutter_configured: boolean;
  hermes_decomp_configured: boolean;
  rn_decompiler_configured: boolean;
  ready_for_analysis: boolean;
}

/** One real vendor, grouping the one or two backend provider keys it's
 * reachable through - `api` (a metered API key) and/or `cli` (a
 * subscription CLI login, see `ProviderSettings.is_cli`). A vendor with
 * both is one provider two ways, e.g. Claude = {api: "claude",
 * cli: "claude_cli"}; Codex CLI and Antigravity CLI are OpenAI's and
 * Google's own `cli` here, not separate vendors. See `ai/registry.py`'s
 * `PROVIDER_VENDORS`, the single source of truth this mirrors. */
export interface ProviderVendor {
  id: string;
  label: string;
  api?: string;
  cli?: string;
}

export interface Settings {
  active_provider: string;
  provider_order: string[];
  providers: Record<string, ProviderSettings>;
  vendors: ProviderVendor[];
  /** Free (no subscription) OpenAI-compatible endpoints, offered as a
   * one-click fill for the "custom" provider's base_url/model. */
  custom_presets: CustomPreset[];
  jadx_path: string;
  blutter_path: string;
  hermes_decomp_path: string;
  rn_decompiler_path: string;
  pdf_generation: boolean;
  /** Re-queue scans that were interrupted by a server crash/Ctrl+C, once the
   * server comes back and finds a checkpoint for them. */
  auto_resume: boolean;
  /** Ceiling on the AI phase. 0 in either field means no limit. */
  agent_budget?: { max_steps_per_region: number; max_minutes: number };
  agent_budget_limits?: Record<string, [number, number]>;
  max_concurrent_requests_range?: [number, number];
  status: AnalysisStatus;
}

async function http<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let detail: unknown;
    try {
      detail = (await res.json()).detail;
    } catch {
      detail = await res.text();
    }
    const message =
      typeof detail === "string"
        ? detail
        : (detail as { message?: string })?.message || `Request failed (${res.status})`;
    throw new ApiError(message, res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

export const api = {
  version: () => http<{ name: string; version: string }>("/api/version"),
  status: () => http<AnalysisStatus>("/api/status"),

  listScans: () => http<{ scans: ScanMeta[] }>("/api/scans"),
  getScan: (id: string) =>
    http<{ meta: ScanMeta; result: ScanResult | null }>(`/api/scans/${id}`),
  deleteScan: (id: string) =>
    http<{ deleted: string }>(`/api/scans/${id}`, { method: "DELETE" }),
  /** Graceful cancel - the scan stops at its next checkpoint and keeps whatever
   * findings it already produced. */
  stopScan: (id: string) =>
    http<{ stopping: string }>(`/api/scans/${id}/stop`, { method: "POST" }),
  /** Pause at the next checkpoint, keeping all state so it can resume. */
  pauseScan: (id: string) =>
    http<{ pausing: string }>(`/api/scans/${id}/pause`, { method: "POST" }),
  /** Re-queue a paused scan, continuing from its checkpoint. */
  resumeScan: (id: string) =>
    http<{ resuming: string }>(`/api/scans/${id}/resume`, { method: "POST" }),

  createScanUpload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return http<{ id: string }>("/api/scans", { method: "POST", body: form });
  },
  createScanPath: (path: string) => {
    const form = new FormData();
    form.append("path", path);
    return http<{ id: string }>("/api/scans", { method: "POST", body: form });
  },

  getSettings: () => http<Settings>("/api/settings"),
  updateSettings: (payload: Record<string, unknown>) =>
    http<Settings>("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  /** Adds one key to the provider's pool, or clears the whole pool when
   * `api_key` is null. To drop a single key use `removeCredential`. */
  setCredential: (provider: string, api_key: string | null) =>
    http<{ ok: boolean; provider: string }>("/api/settings/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, api_key }),
    }),
  removeCredential: (provider: string, index: number) =>
    http<{ ok: boolean; provider: string }>(
      `/api/settings/credentials/${provider}/${index}`,
      { method: "DELETE" },
    ),
  /** The full value of one stored key. Called only on an explicit user click
   * - never bundled into `getSettings`. */
  revealCredential: (provider: string, index: number) =>
    http<{ provider: string; index: number; key: string }>(
      `/api/settings/credentials/${provider}/reveal`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ index }),
      },
    ),
  listModels: (provider: string) =>
    http<{ provider: string; models: string[] }>(`/api/settings/models/${provider}`),
  /** Detection + live sign-in probe for a subscription-CLI-backed provider. */
  getCliStatus: (provider: string) =>
    http<CliStatus>(`/api/settings/cli-status/${provider}`),
  testProvider: (provider?: string) =>
    http<{ ok: boolean; provider?: string; model?: string; error?: string | null }>(
      "/api/settings/test",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: provider ?? null }),
      },
    ),

  /**
   * A scan's complete log, oldest first.
   *
   * Only written when the server runs verbose, so `persisted` false means
   * nothing was recorded rather than nothing happened.
   */
  getLogs: (id: string, limit?: number) =>
    http<{ scan_id: string; count: number; logs: LogLine[]; persisted: boolean }>(
      `/api/scans/${id}/logs${limit ? `?limit=${limit}` : ""}`,
    ),

  reportUrl: (id: string, fmt: "json" | "html" | "pdf") =>
    `/api/scans/${id}/report/${fmt}`,

  logsDownloadUrl: (id: string) => `/api/scans/${id}/logs/download`,
};

export function scanWsUrl(id: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/api/ws/scans/${id}`;
}