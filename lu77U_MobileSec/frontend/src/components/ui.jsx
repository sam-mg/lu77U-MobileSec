import type { ReactNode } from "react";
import { Loader2 } from "lucide-react";
import type { ScanStatus, Severity } from "../api";
import { SEVERITY_META, normalizeSeverity, scoreColor } from "../lib/format";

export function SeverityBadge({ severity, count }: { severity: Severity | string; count?: number }) {
  const s = normalizeSeverity(typeof severity === "string" ? severity : severity);
  const m = SEVERITY_META[s];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${m.bg} ${m.text} ${m.ring}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
      {count != null && <span className="opacity-80">· {count}</span>}
    </span>
  );
}

const STATUS_META: Record<ScanStatus, { label: string; cls: string; pulse?: boolean }> = {
  queued: { label: "Queued", cls: "bg-slate-500/10 text-slate-300 ring-slate-500/30" },
  running: { label: "Running", cls: "bg-brand-500/10 text-brand-300 ring-brand-500/30", pulse: true },
  completed: { label: "Completed", cls: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" },
  failed: { label: "Failed", cls: "bg-rose-500/10 text-rose-300 ring-rose-500/30" },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const m = STATUS_META[status] ?? STATUS_META.queued;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${m.cls}`}>
      {m.pulse && <Loader2 className="h-3 w-3 animate-spin" />}
      {!m.pulse && <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />}
      {m.label}
    </span>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`card p-5 ${className}`}>{children}</div>;
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{children}</h2>
      {action}
    </div>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return <Loader2 className={`animate-spin ${className}`} />;
}

export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      {icon && <div className="mb-1 text-slate-600">{icon}</div>}
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="max-w-sm text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function ScoreRing({ score, size = 92 }: { score?: number | null; size?: number }) {
  const value = score == null ? 0 : Math.max(0, Math.min(100, score));
  const stroke = 8;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (value / 100) * c;
  const colorHex =
    score == null ? "#64748b" : value >= 85 ? "#10b981" : value >= 65 ? "#f59e0b" : value >= 40 ? "#f97316" : "#f43f5e";
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#1e293b" strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={colorHex}
          strokeWidth={stroke}
          strokeLinecap="round"
          fill="none"
          strokeDasharray={c}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-xl font-bold ${scoreColor(score)}`}>{score == null ? "—" : Math.round(value)}</span>
        <span className="text-[10px] uppercase tracking-wider text-slate-500">score</span>
      </div>
    </div>
  );
}

export function PlatformBadge({ framework }: { framework?: string | null }) {
  if (!framework) return <span className="text-slate-500">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md bg-ink-800 px-2 py-0.5 text-xs font-medium text-slate-300 ring-1 ring-inset ring-ink-700">
      {framework}
    </span>
  );
}