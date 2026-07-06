import type { Severity } from "../api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<
  Severity,
  { label: string; text: string; bg: string; ring: string; dot: string; hex: string }
> = {
  critical: { label: "Critical", text: "text-rose-300", bg: "bg-rose-500/10", ring: "ring-rose-500/30", dot: "bg-rose-500", hex: "#f43f5e" },
  high: { label: "High", text: "text-orange-300", bg: "bg-orange-500/10", ring: "ring-orange-500/30", dot: "bg-orange-500", hex: "#f97316" },
  medium: { label: "Medium", text: "text-amber-300", bg: "bg-amber-500/10", ring: "ring-amber-500/30", dot: "bg-amber-500", hex: "#f59e0b" },
  low: { label: "Low", text: "text-emerald-300", bg: "bg-emerald-500/10", ring: "ring-emerald-500/30", dot: "bg-emerald-500", hex: "#10b981" },
  info: { label: "Info", text: "text-sky-300", bg: "bg-sky-500/10", ring: "ring-sky-500/30", dot: "bg-sky-500", hex: "#38bdf8" },
};

export function normalizeSeverity(value?: string): Severity {
  const v = (value || "").toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v.startsWith("high")) return "high";
  if (v.startsWith("med")) return "medium";
  if (v.startsWith("low")) return "low";
  return "info";
}

export function formatBytes(bytes?: number): string {
  if (!bytes && bytes !== 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatDate(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  if (isNaN(d)) return "—";
  const diff = Date.now() - d;
  const s = Math.floor(diff / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.floor(h / 24);
  return `${days}d ago`;
}

export function scoreColor(score?: number | null): string {
  if (score == null) return "text-slate-300";
  if (score >= 85) return "text-emerald-400";
  if (score >= 65) return "text-amber-400";
  if (score >= 40) return "text-orange-400";
  return "text-rose-400";
}