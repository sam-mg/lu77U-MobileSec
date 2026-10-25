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
  paused: { label: "Paused", cls: "bg-amber-500/10 text-amber-300 ring-amber-500/30" },
  completed: { label: "Completed", cls: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" },
  failed: { label: "Failed", cls: "bg-rose-500/10 text-rose-300 ring-rose-500/30" },
  // User-intended stop, not an error - neutral grey, no alarm colour.
  cancelled: { label: "Stopped", cls: "bg-slate-500/10 text-slate-400 ring-slate-500/30" },
};

/** Optional, only meaningful when `status === "paused"` - distinguishes a
 * user pause from a server-crash interruption or an exhausted subscription
 * provider quota (see web/jobs.py's pause_reason values). */
export function StatusBadge({ status, pauseReason }: { status: ScanStatus; pauseReason?: string | null }) {
  const m = STATUS_META[status] ?? STATUS_META.queued;
  const label = status === "paused" && pauseReason === "provider_quota" ? "Quota paused" : m.label;
  const title = status === "paused" && pauseReason === "provider_quota"
    ? "Paused - the AI provider's subscription quota ran out; resumes automatically once it resets"
    : undefined;
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${m.cls}`}
    >
      {m.pulse && <Loader2 className="h-3 w-3 animate-spin" />}
      {!m.pulse && <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />}
      {label}
    </span>
  );
}

/**
 * An iOS-style on/off switch. The whole row is the hit target (≥44px) - the
 * old inline toggle only registered taps on the 44×24 track, and its knob
 * vanished in the "on" state because track and knob were both white. Here the
 * knob darkens when on, so the state reads at a glance, and it moves by
 * transform (compositor-friendly), not by shifting `left`.
 */
export function Switch({
  checked,
  onChange,
  label,
  icon,
  disabled,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: ReactNode;
  icon?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="flex min-h-[44px] w-full items-center justify-between gap-3 text-left disabled:opacity-50"
    >
      <span className="flex min-w-0 items-center gap-1.5 text-sm text-slate-300">
        {icon && <span className="shrink-0 text-slate-500">{icon}</span>}
        <span className="min-w-0">{label}</span>
      </span>
      <span
        className={`relative flex h-6 w-11 shrink-0 items-center rounded-full transition-colors duration-150 ${
          checked ? "bg-white" : "bg-white/[0.14]"
        }`}
      >
        <span
          className={`h-5 w-5 rounded-full shadow transition-transform duration-150 ${
            checked ? "translate-x-[20px] bg-black" : "translate-x-0.5 bg-slate-300"
          }`}
        />
      </span>
    </button>
  );
}

/**
 * Sibling stats on ONE panel with hairline dividers, label left / value right -
 * not a grid of separately-bordered cards. A single unbreakable label like
 * "VULNERABILITIES" used to force all flex shrinkage onto its icon until the
 * icon disappeared; a full-width row gives the label its own space.
 */
export function StatPanel({
  items,
}: {
  items: { icon?: ReactNode; label: string; value: ReactNode; tone?: "warn" | "bad" }[];
}) {
  return (
    <div className="card divide-y divide-white/[0.06]">
      {items.map((it) => (
        <div key={it.label} className="flex items-center justify-between gap-3 px-4 py-3">
          <span className="flex min-w-0 items-center gap-2 text-slate-500">
            {it.icon && <span className="shrink-0">{it.icon}</span>}
            <span className="truncate text-xs font-medium uppercase">{it.label}</span>
          </span>
          <span
            className={`shrink-0 text-xl font-bold tabular-nums ${
              it.tone === "bad" ? "text-rose-400" : it.tone === "warn" ? "text-amber-400" : "text-white"
            }`}
          >
            {it.value}
          </span>
        </div>
      ))}
    </div>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`card p-5 ${className}`}>{children}</div>;
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <h2 className="min-w-0 text-sm font-semibold uppercase tracking-wider text-slate-400">{children}</h2>
      {action && <div className="shrink-0">{action}</div>}
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
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.10)" strokeWidth={stroke} fill="none" />
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
        <span className={`text-xl font-bold ${scoreColor(score)}`}>{score == null ? "-" : Math.round(value)}</span>
        <span className="text-[10px] uppercase tracking-wider text-slate-500">score</span>
      </div>
    </div>
  );
}

/**
 * A segmented control - mutually-exclusive options in one pill-shaped track,
 * the selected one raised. Shared by Ollama's cloud/local Mode switch and
 * Settings' provider Access (API key/CLI) toggle so the two controls stay
 * visually identical and any hit-target/focus fix lands in one place.
 * `role="radiogroup"`/`aria-checked` carry the selection through to screen
 * readers and color-filtered viewing, since the raised segment is the only
 * visual cue otherwise.
 */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  disabled,
}: {
  value: T;
  onChange: (next: T) => void;
  options: { value: T; label: ReactNode }[];
  disabled?: boolean;
}) {
  return (
    <div role="radiogroup" className="flex rounded-lg bg-ink-800/60 p-0.5 text-xs">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          disabled={disabled}
          onClick={() => onChange(opt.value)}
          className={`min-h-11 flex-1 rounded-md px-3 py-1.5 font-medium capitalize transition-colors disabled:opacity-50 md:min-h-8 ${
            value === opt.value ? "bg-ink-700 text-white" : "text-slate-400 hover:text-slate-200"
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export function PlatformBadge({ framework }: { framework?: string | null }) {
  if (!framework) return <span className="text-slate-500">-</span>;
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md bg-ink-800 px-2 py-0.5 text-xs font-medium text-slate-300 ring-1 ring-inset ring-ink-700">
      {framework}
    </span>
  );
}