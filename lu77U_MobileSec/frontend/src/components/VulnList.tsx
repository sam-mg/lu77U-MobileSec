import { useMemo, useState } from "react";
import { ChevronDown, ShieldCheck } from "lucide-react";
import type { Chain, CodeContext, GateResult, ScanResult, Severity, Vulnerability } from "../api";
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
  const refuted = result.vulnerability_analysis?.refuted ?? [];
  const [active, setActive] = useState<Severity | "all">("all");

  const visible = active === "all" ? all : all.filter((x) => x.sev === active);

  if (all.length === 0 && refuted.length === 0) {
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
      {all.length > 0 && (
        <>
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
        </>
      )}
      {refuted.length > 0 && <RefutedSection items={refuted} />}
    </div>
  );
}

/**
 * Findings the mechanical evidence gate refuted before any model call - e.g.
 * a title claiming "Hardcoded AES key" whose cited code contains none of
 * AES/SecretKeySpec/Cipher/javax.crypto. Kept out of every count and the
 * severity filter chips above, never dropped: collapsed by default here (the
 * live page can afford that, unlike the PDF's headless print pass) so the
 * tool's own mistakes stay visible without crowding the real findings.
 */
function RefutedSection({ items }: { items: Vulnerability[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-6 rounded-xl border border-ink-800 bg-ink-900/30">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <span className="min-w-0 flex-1 text-sm font-medium text-slate-400">
          Refuted findings · {items.length}
        </span>
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="space-y-2.5 border-t border-ink-800 p-4">
          <p className="text-xs leading-relaxed text-slate-500">
            The evidence gate checked each of these against the code it cited and found
            none of the construct the title claims, before any model weighed in.
          </p>
          {items.map((v, i) => (
            <VulnCard key={i} sev="info" v={v} />
          ))}
        </div>
      )}
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
        {v.chain && <span className="shrink-0 rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-rose-300">Chain</span>}
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-200">{v.title || "Untitled finding"}</span>
        <div className="hidden shrink-0 items-center gap-2 text-[11px] text-slate-500 sm:flex">
          {v.vuln_class && <span className="rounded bg-ink-800 px-1.5 py-0.5">{v.vuln_class}</span>}
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
          {v.chain && <ChainBlock chain={v.chain} />}
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
          {v.gate_result && <GateBlock gate={v.gate_result} chainedInto={v.chained_into} />}
        </div>
      )}
    </div>
  );
}

function ChainBlock({ chain }: { chain: Chain }) {
  return (
    <div className="rounded-lg bg-rose-500/5 p-3 ring-1 ring-inset ring-rose-500/15">
      <div className="label !text-rose-400">
        Exploit chain {chain.priority ? "· high priority" : ""}
      </div>
      {chain.components?.length > 0 && (
        <p className="mb-2 text-xs text-slate-400">
          Combines: {chain.components.join(" + ")}
        </p>
      )}
      {chain.flow?.length > 0 && (
        <ol className="space-y-1 text-slate-300">
          {chain.flow.map((step, i) => (
            <li key={i} className="flex gap-2">
              <span className="shrink-0 font-mono text-xs text-rose-400/70">{i + 1}.</span>
              <span className="leading-relaxed">{step}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

/**
 * Why a finding sits where it does. Only rendered when the gates actually
 * changed something: a PASS with nothing to say would be noise on every card.
 */
function GateBlock({ gate, chainedInto }: { gate: GateResult; chainedInto?: string[] }) {
  const downgraded = gate.original_severity !== gate.final_severity;
  const hasNotes = (gate.reasons?.length || 0) > 0 || (gate.warnings?.length || 0) > 0;
  if (gate.verdict === "PASS" && !hasNotes) return null;

  const label =
    gate.verdict === "FALSE_POSITIVE" && gate.mechanically_refuted
      // Checked against its own cited code with no model call - a stronger
      // statement than "an LLM reviewed this and was not convinced".
      ? "Refuted mechanically - the cited code does not contain the claimed construct"
      : gate.verdict === "CHAIN_REQUIRED"
        ? "Not independently reportable"
        : gate.verdict === "FALSE_POSITIVE"
          ? "Reviewed against the source - not confirmed"
          : gate.verdict === "INFORMATIONAL"
            ? "Reported as information"
            : gate.verdict === "DOWNGRADE"
              ? "Severity reduced"
              : "Review notes";

  return (
    <div className="rounded-lg border border-ink-800 bg-ink-950/60 p-3">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <span className="label !mb-0 !text-slate-400">{label}</span>
        {downgraded && (
          <span className="font-mono text-[11px] text-slate-500">
            {gate.original_severity} → {gate.final_severity}
          </span>
        )}
        {gate.weak_class_rule && (
          <span className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
            {gate.weak_class_rule}
          </span>
        )}
      </div>
      {gate.reasons?.length > 0 && (
        <ul className="space-y-1 text-xs leading-relaxed text-slate-400">
          {gate.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
      {gate.warnings && gate.warnings.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs leading-relaxed text-amber-400/80">
          {gate.warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
      {chainedInto && chainedInto.length > 0 && (
        <p className="mt-2 text-xs text-rose-300/80">
          Part of exploit chain {chainedInto.join(", ")} - see that finding for the full path.
        </p>
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