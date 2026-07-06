import { useMemo, useState } from "react";
import { ChevronDown, ShieldCheck } from "lucide-react";
import type { CodeContext, ScanResult, Severity, Vulnerability } from "../api";
import { SEVERITIES, SEVERITY_META, normalizeSeverity } from "../lib/format";
import { SeverityBadge, EmptyState } from "./ui";

function flatten(result: ScanResult): { sev: Severity; v: Vulnerability }[] {
  const buckets = result.vulnerability_analysis?.vulnerabilities;
  if (!buckets) return [];
  const out: { sev: Severity; v: Vulnerability }[] = [];
  for (const sev of SEVERITIES) {
    for (const v of buckets[sev] || []) out.push({ sev: normalizeSeverity(v.severity || sev), v });
  }
  return out;
}

export default function VulnList({ result }: { result: ScanResult }) {
  const all = useMemo(() => flatten(result), [result]);
  const counts = result.vulnerability_analysis?.by_severity;
  const [active, setActive] = useState<Severity | "all">("all");

  const visible = active === "all" ? all : all.filter((x) => x.sev === active);

  if (all.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck className="h-8 w-8 text-emerald-500/70" />}
        title="No vulnerabilities reported"
        hint="The AI analysis did not flag any source-level issues for this app."
      />
    );
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-2">
        <FilterChip label={`All · ${all.length}`} active={active === "all"} onClick={() => setActive("all")} />
        {SEVERITIES.map((s) => {
          const n = counts?.[s] ?? 0;
          if (!n) return null;
          return (
            <FilterChip
              key={s}
              label={`${SEVERITY_META[s].label} · ${n}`}
              active={active === s}
              tone={s}
              onClick={() => setActive(s)}
            />
          );
        })}
      </div>
      <div className="space-y-2.5">
        {visible.map((x, i) => (
          <VulnCard key={i} sev={x.sev} v={x.v} />
        ))}
      </div>
    </div>
  );
}

function FilterChip({ label, active, tone, onClick }: { label: string; active: boolean; tone?: Severity; onClick: () => void }) {
  const ring = tone ? SEVERITY_META[tone].ring : "ring-ink-700";
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset transition-colors ${
        active ? "bg-ink-700 text-white ring-ink-600" : `bg-ink-800/40 text-slate-400 hover:text-slate-200 ${ring}`
      }`}
    >
      {label}
    </button>
  );
}

function VulnCard({ sev, v }: { sev: Severity; v: Vulnerability }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`rounded-xl border border-ink-800 bg-ink-900/50 transition-colors ${open ? "ring-1 ring-inset ring-ink-700" : ""}`}>
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <SeverityBadge severity={sev} />
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-200">{v.title || "Untitled finding"}</span>
        <div className="hidden shrink-0 items-center gap-2 text-[11px] text-slate-500 sm:flex">
          {v.cwe && <span className="rounded bg-ink-800 px-1.5 py-0.5">{v.cwe}</span>}
          {v.owasp_mobile && <span className="rounded bg-ink-800 px-1.5 py-0.5">{v.owasp_mobile}</span>}
        </div>
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="space-y-4 border-t border-ink-800 px-4 py-4 text-sm">
          {(v.file || v.location) && (
            <div className="font-mono text-xs text-slate-400">
              {v.file}
              {v.location ? <span className="text-slate-600"> · {v.location}</span> : null}
            </div>
          )}
          {v.description && <Field label="Description">{v.description}</Field>}
          {v.code_context?.lines?.length ? (
            <div>
              <div className="label">Code</div>
              <CodeContextBlock context={v.code_context} />
            </div>
          ) : (
            v.code_snippet && (
              <div>
                <div className="label">Code</div>
                <pre className="overflow-x-auto rounded-lg border border-ink-800 bg-ink-950 p-3 font-mono text-xs text-slate-300">
                  <code>{v.code_snippet}</code>
                </pre>
              </div>
            )
          )}
          {v.impact && <Field label="Impact">{v.impact}</Field>}
          {v.exploitation && <Field label="Exploitation">{v.exploitation}</Field>}
          {v.recommendation && (
            <div className="rounded-lg bg-emerald-500/5 p-3 ring-1 ring-inset ring-emerald-500/15">
              <div className="label !text-emerald-400">Recommendation</div>
              <p className="text-slate-300">{v.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CodeContextBlock({ context }: { context: CodeContext }) {
  const { start_line, highlight_start, highlight_end, lines, lines_html } = context;
  const hasHtml = Array.isArray(lines_html) && lines_html.length === lines.length;
  return (
    <pre className="overflow-x-auto rounded-lg border border-ink-800 bg-ink-950 font-mono text-xs text-slate-300">
      {lines.map((line, i) => {
        const lineNo = start_line + i;
        const isHl = lineNo >= highlight_start && lineNo <= highlight_end;
        return (
          <div key={lineNo} className={`flex px-3 ${isHl ? "bg-rose-500/10" : ""}`}>
            <span className={`mr-3 w-8 shrink-0 select-none text-right ${isHl ? "text-rose-400" : "text-slate-600"}`}>
              {lineNo}
            </span>
            {hasHtml ? (
              <code
                className="whitespace-pre-wrap break-words"
                dangerouslySetInnerHTML={{ __html: lines_html[i] || "&nbsp;" }}
              />
            ) : (
              <code className="whitespace-pre-wrap break-words">{line || " "}</code>
            )}
          </div>
        );
      })}
    </pre>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="label">{label}</div>
      <p className="leading-relaxed text-slate-300">{children}</p>
    </div>
  );
}