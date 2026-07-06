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

export type ScanStatus = "queued" | "running" | "completed" | "failed";

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
  summary: ScanSummary;
  reports: Partial<Record<"json" | "html" | "pdf", boolean>>;
}

export interface CodeContext {
  start_line: number;
  end_line: number;
  highlight_start: number;
  highlight_end: number;
  lines: string[];
  lines_html?: string[];
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
  };
  summary?: {
    framework_detected?: boolean;
    vulnerability_scan_complete?: boolean;
    total_vulnerabilities?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    security_score?: number;
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

export interface ProviderSettings {
  name: string;
  display_name: string;
  model: string;
  mode?: string | null;
  base_url?: string | null;
  cloud_host?: string | null;
  local_host?: string | null;
  has_api_key: boolean;
  default_model: string;
  needs_api_key: boolean;
}

export interface AnalysisStatus {
  jadx_configured: boolean;
  ollama_configured: boolean;
  ready_for_analysis: boolean;
}

export interface Settings {
  active_provider: string;
  provider_order: string[];
  providers: Record<string, ProviderSettings>;
  jadx_path: string;
  pdf_generation: boolean;
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
  setCredential: (provider: string, api_key: string | null) =>
    http<{ ok: boolean; provider: string }>("/api/settings/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, api_key }),
    }),
  listModels: (provider: string) =>
    http<{ provider: string; models: string[] }>(`/api/settings/models/${provider}`),
  testProvider: (provider?: string) =>
    http<{ ok: boolean; provider?: string; model?: string; error?: string | null }>(
      "/api/settings/test",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: provider ?? null }),
      },
    ),

  reportUrl: (id: string, fmt: "json" | "html" | "pdf") =>
    `/api/scans/${id}/report/${fmt}`,
};

export function scanWsUrl(id: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/api/ws/scans/${id}`;
}