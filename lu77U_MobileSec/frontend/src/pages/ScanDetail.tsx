import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft, Download, FileJson, FileText, FileCode2, Terminal, Package,
  Cpu, Layers, AlertTriangle, Trash2, Search, Copy, Check, ChevronDown,
  Pause, Play, Square, PauseCircle,
} from "lucide-react";
import { api, type LogLine, type ScanMeta, type ScanResult } from "../api";
import { useScanStream } from "../lib/useScanStream";
import { Card, SectionTitle, Spinner, StatusBadge, ScoreRing, PlatformBadge } from "../components/ui";
import VulnList from "../components/VulnList";
import { formatBytes } from "../lib/format";

export default function ScanDetail() {
  const { id = "" } = useParams();
  const [meta, setMeta] = useState<ScanMeta | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  const refetch = useCallback(async () => {
    try {
      const { meta, result } = await api.getScan(id);
      setMeta(meta);
      setResult(result);
    } catch {
      setNotFound(true);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  const resting = meta?.status === "paused";
  const terminal =
    meta?.status === "completed" || meta?.status === "failed" || meta?.status === "cancelled";
  const stream = useScanStream(id, !!meta && !terminal && !resting, () => refetch());

  // Live status overrides the (possibly stale) initial meta while streaming.
  const liveStatus = stream.status ?? meta?.status;
  const isRunning = liveStatus === "running" || liveStatus === "queued";

  if (loading) return <div className="flex justify-center py-24"><Spinner className="h-7 w-7 text-slate-500" /></div>;
  if (notFound || !meta)
    return (
      <div className="py-24 text-center">
        <p className="text-slate-300">Scan not found.</p>
        <Link to="/scans" className="mt-2 inline-block text-sm text-brand-400 hover:text-brand-300">Back to scans</Link>
      </div>
    );

  const sum = meta.summary || {};
  const app = result?.application_info;
  const fw = result?.framework_detection;
  const title = sum.app_name || app?.app_name || meta.filename;

  async function remove() {
    if (!confirm("Delete this scan and its outputs?")) return;
    await api.deleteScan(id).catch(() => {});
    window.location.href = "/scans";
  }

  // Pause / Stop / Resume are all recoverable - act immediately, no prompt.
  async function act(fn: (id: string) => Promise<unknown>) {
    await fn(id).catch(() => {});
    refetch();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link to="/scans" className="mb-2 inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300">
            <ArrowLeft className="h-3.5 w-3.5" /> Scans
          </Link>
          <h1 className="truncate text-2xl font-bold text-white">{title}</h1>
          <p className="mt-1 break-all font-mono text-xs text-slate-500">{app?.package_name || sum.package_name || meta.filename}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={(liveStatus as ScanMeta["status"]) || "queued"} />
          {isRunning && (
            <>
              <button className="btn-ghost" onClick={() => act(api.pauseScan)}><Pause className="h-4 w-4" /> Pause</button>
              <button className="btn-ghost" onClick={() => act(api.stopScan)}><Square className="h-4 w-4" /> Stop</button>
            </>
          )}
          {liveStatus === "paused" && (
            <button className="btn-primary" onClick={() => act(api.resumeScan)}><Play className="h-4 w-4" /> Resume</button>
          )}
          <button className="btn-danger" onClick={remove}><Trash2 className="h-4 w-4" /> Delete</button>
        </div>
      </div>

      {isRunning ? (
        <ProgressView id={id} meta={meta} stream={stream} />
      ) : liveStatus === "failed" ? (
        <FailedView id={id} meta={meta} stream={stream} />
      ) : liveStatus === "paused" ? (
        <PausedView id={id} meta={meta} stream={stream} />
      ) : liveStatus === "cancelled" ? (
        <StoppedView id={id} meta={meta} result={result} stream={stream} />
      ) : result ? (
        <CompletedView id={id} meta={meta} result={result} stream={stream} />
      ) : (
        <Card><p className="text-sm text-slate-400">No result available for this scan.</p></Card>
      )}
    </div>
  );
}

type Stream = ReturnType<typeof useScanStream>;

function ProgressView({ id, meta, stream }: { id: string; meta: ScanMeta; stream: Stream }) {
  const pct = stream.progress.percent || meta.progress || 0;
  const phase = stream.progress.phase || meta.phase || "starting";
  return (
    <div className="space-y-6">
      <Card>
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
            <Spinner className="h-4 w-4 text-brand-400" /> Analyzing - <span className="capitalize text-slate-400">{phase.replace(/_/g, " ")}</span>
          </div>
          <span className="text-sm font-semibold text-brand-300">{Math.round(pct)}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-ink-800">
          <div className="h-full rounded-full bg-gradient-to-r from-brand-600 to-brand-400 transition-all duration-500" style={{ width: `${pct}%` }} />
        </div>
        {stream.progress.message && <p className="mt-2 text-xs text-slate-500">{stream.progress.message}</p>}
      </Card>
      <LogPanel id={id} logs={stream.logs} loading={stream.loadingHistory} persisted={stream.logsPersisted} live />
    </div>
  );
}

function FailedView({ id, meta, stream }: { id: string; meta: ScanMeta; stream: Stream }) {
  return (
    <div className="space-y-6">
      <Card className="border-rose-900/50 bg-rose-950/20">
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
          <div>
            <h2 className="text-sm font-semibold text-rose-200">Scan failed</h2>
            <p className="mt-1 text-sm text-rose-300/80">{stream.error || meta.error || "An error occurred during analysis."}</p>
          </div>
        </div>
      </Card>
      <LogPanel id={id} logs={stream.logs} loading={stream.loadingHistory} persisted={stream.logsPersisted} defaultOpen />
    </div>
  );
}

function PausedView({ id, meta, stream }: { id: string; meta: ScanMeta; stream: Stream }) {
  const interrupted = meta.pause_reason === "interrupted";
  const quotaExhausted = meta.pause_reason === "provider_quota";
  const gaveUp = interrupted && (meta.resume_attempts ?? 0) >= 2;
  const pct = stream.progress.percent || meta.progress || 0;
  const resumeAt = meta.resume_after ? new Date(meta.resume_after) : null;
  const resumeAtText = resumeAt && !Number.isNaN(resumeAt.getTime())
    ? resumeAt.toLocaleString()
    : null;
  return (
    <div className="space-y-6">
      <Card className="border-amber-900/40 bg-amber-950/10">
        <div className="flex items-start gap-3">
          <PauseCircle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-amber-200">
              {interrupted ? "Scan interrupted" : quotaExhausted ? "Paused - AI provider quota exhausted" : "Scan paused"}
            </h2>
            <p className="mt-1 text-sm text-amber-300/80">
              {interrupted
                ? "The server stopped while this scan was running. Its progress was checkpointed - press Resume to continue from where it left off."
                : quotaExhausted
                  ? "The AI provider's subscription usage limit was reached mid-scan. Everything found so far is kept, and the exact spot it stopped at will pick back up - nothing is re-analyzed from the start."
                  : "Paused at a checkpoint. Press Resume to continue; the AI work already done is kept."}
              {" "}Stopped at about {Math.round(pct)}%
              {meta.phase ? ` (${meta.phase.replace(/_/g, " ")})` : ""}.
              {gaveUp && " Auto-resume stopped retrying after two attempts - resume it by hand when ready."}
            </p>
            {quotaExhausted && (
              <p className="mt-2 text-xs text-amber-400/70">
                {resumeAtText
                  ? `Retries automatically after about ${resumeAtText}, or press Resume any time before then.`
                  : "Retries automatically once the usage window is expected to have reset, or press Resume any time."}
                {(meta.quota_resume_attempts ?? 0) > 0 && ` (auto-retried ${meta.quota_resume_attempts}x so far)`}
              </p>
            )}
          </div>
        </div>
      </Card>
      <LogPanel id={id} logs={stream.logs} loading={stream.loadingHistory} persisted={stream.logsPersisted} defaultOpen />
    </div>
  );
}

function StoppedView({ id, meta, result, stream }: { id: string; meta: ScanMeta; result: ScanResult | null; stream: Stream }) {
  const partialCount = result?.vulnerability_analysis?.total_vulnerabilities ?? 0;
  return (
    <div className="space-y-6">
      <Card>
        <div className="flex items-start gap-3">
          <Square className="mt-0.5 h-5 w-5 shrink-0 text-slate-400" />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-slate-200">Scan stopped</h2>
            <p className="mt-1 text-sm text-slate-400">
              This scan was stopped before it finished
              {meta.phase ? ` (${meta.phase.replace(/_/g, " ")})` : ""}.
              {partialCount > 0
                ? " The findings gathered up to that point are below - the analysis is incomplete."
                : " No findings had been recorded yet."}
            </p>
          </div>
        </div>
      </Card>
      {partialCount > 0 && result && (
        <Card>
          <SectionTitle>Partial findings</SectionTitle>
          <VulnList result={result} />
        </Card>
      )}
      <LogPanel id={id} logs={stream.logs} loading={stream.loadingHistory} persisted={stream.logsPersisted} defaultOpen />
    </div>
  );
}

function CompletedView({ id, meta, result, stream }: {
  id: string; meta: ScanMeta; result: ScanResult; stream: Stream;
}) {
  const app = result.application_info || {};
  const fw = result.framework_detection;
  const analysis = result.analysis;
  const score = result.summary?.security_score;

  return (
    <div className="space-y-6">
      {/* Top row: score + framework + downloads */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="flex items-center gap-5">
          <ScoreRing score={score} />
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-500">Security score</div>
            <div className="mt-1 text-sm text-slate-300">{meta.summary?.total_vulnerabilities ?? 0} findings</div>
            <div className="mt-2 text-[11px] text-slate-500">Analyzed in {analysis?.analysis_time ? `${Math.round(Number(analysis.analysis_time))}s` : `${meta.duration}s`}</div>
          </div>
        </Card>

        <Card>
          <SectionTitle>Framework</SectionTitle>
          <div className="flex items-center gap-2">
            <PlatformBadge framework={fw?.primary_framework} />
            {fw?.confidence != null && (
              <span className="text-xs text-slate-500">{Math.round((fw.confidence || 0) * 100)}% · {fw.confidence_level}</span>
            )}
          </div>
          {fw?.frameworks && fw.frameworks.length > 1 && (
            <div className="mt-3 space-y-1.5">
              {fw.frameworks.slice(1, 4).map((f) => (
                <div key={f.name} className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">{f.name}</span>
                  <span className="text-slate-500">{Math.round((f.confidence || 0) * 100)}%</span>
                </div>
              ))}
            </div>
          )}
          {analysis && !analysis.supported && (
            <p className="mt-3 rounded-lg bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-300 ring-1 ring-inset ring-amber-500/20">
              Deep vulnerability analysis isn’t supported for this framework yet - detection-only report.
            </p>
          )}
        </Card>

        <Card>
          <SectionTitle>Reports</SectionTitle>
          <div className="flex flex-col gap-2">
            <ReportLink id={id} fmt="pdf" enabled={!!result.reports?.pdf} icon={<FileText className="h-4 w-4" />} label="PDF report" />
            <ReportLink id={id} fmt="html" enabled={!!result.reports?.html} icon={<FileCode2 className="h-4 w-4" />} label="HTML report" />
            <ReportLink id={id} fmt="json" enabled={!!result.reports?.json} icon={<FileJson className="h-4 w-4" />} label="JSON export" />
          </div>
        </Card>
      </div>

      {/* App info */}
      <Card>
        <SectionTitle>Application</SectionTitle>
        <div className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3 lg:grid-cols-4">
          <Info icon={<Package className="h-3.5 w-3.5" />} label="Package" value={app.package_name} mono />
          <Info label="Version" value={app.version_name ? `${app.version_name} (${app.version_code ?? "?"})` : undefined} />
          <Info icon={<Cpu className="h-3.5 w-3.5" />} label="SDK" value={app.min_sdk || app.target_sdk ? `${app.min_sdk ?? "?"} → ${app.target_sdk ?? "?"}` : undefined} />
          <Info label="Size" value={app.file_size ? formatBytes(app.file_size) : undefined} />
          <Info icon={<Layers className="h-3.5 w-3.5" />} label="Activities" value={app.activities?.length ?? 0} />
          <Info label="Services" value={app.services?.length ?? 0} />
          <Info label="Receivers" value={app.receivers?.length ?? 0} />
          <Info label="Providers" value={app.providers?.length ?? 0} />
        </div>
      </Card>

      {/* Vulnerabilities */}
      <Card>
        <SectionTitle>Vulnerability findings</SectionTitle>
        <VulnList result={result} />
      </Card>

      {/* The log is kept after completion rather than discarded: it is the only
          record of what the engine actually did, and the reason a finding looks
          the way it does is usually in it. Collapsed so it does not push the
          findings off the screen. */}
      <LogPanel id={id} logs={stream.logs} loading={stream.loadingHistory} persisted={stream.logsPersisted} />
    </div>
  );
}

function ReportLink({ id, fmt, enabled, icon, label }: { id: string; fmt: "json" | "html" | "pdf"; enabled: boolean; icon: React.ReactNode; label: string }) {
  if (!enabled)
    return (
      <div className="flex items-center gap-2 rounded-lg border border-ink-800 px-3 py-2 text-sm text-slate-600">
        {icon} {label} <span className="ml-auto text-[11px]">unavailable</span>
      </div>
    );
  return (
    <a
      href={api.reportUrl(id, fmt)}
      target="_blank"
      rel="noreferrer"
      className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-800/50 px-3 py-2 text-sm text-slate-200 transition-colors hover:bg-ink-700"
    >
      {icon} {label} <Download className="ml-auto h-4 w-4 text-slate-400" />
    </a>
  );
}

function Info({ icon, label, value, mono }: { icon?: React.ReactNode; label: string; value?: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="flex items-center gap-1 text-[11px] uppercase tracking-wide text-slate-500">
        {icon} {label}
      </div>
      <div className={`mt-1 truncate text-sm text-slate-200 ${mono ? "font-mono text-xs" : ""}`} title={typeof value === "string" ? value : undefined}>
        {value ?? "-"}
      </div>
    </div>
  );
}

/**
 * How many lines are put in the DOM before the panel starts windowing.
 *
 * The log array itself is never truncated - this is only about how many React
 * elements exist at once. A verbose scan of a large app runs to tens of
 * thousands of lines, and mounting that many nodes janks the page badly, so the
 * newest slice renders by default and "show all" is one click away.
 */
const LOG_RENDER_WINDOW = 3000;

interface LogPanelProps {
  id: string;
  logs: LogLine[];
  loading?: boolean;
  persisted?: boolean;
  live?: boolean;
  defaultOpen?: boolean;
}

/**
 * The static demo ships no logs - no scan ever runs in that build, so the panel
 * would only ever be an empty box. `__DEMO__` is a build-time constant, so the
 * whole panel below is dead code there and drops out of the bundle.
 */
function LogPanel(props: LogPanelProps) {
  if (__DEMO__) return null;
  return <LogPanelBody {...props} />;
}

function LogPanelBody({ id, logs, loading, persisted, live, defaultOpen }: LogPanelProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [stick, setStick] = useState(true);
  const [open, setOpen] = useState(defaultOpen ?? !!live);
  const [query, setQuery] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [copied, setCopied] = useState(false);

  const needle = query.trim().toLowerCase();
  const matched = useMemo(
    () => (needle ? logs.filter((l) => l.message.toLowerCase().includes(needle)) : logs),
    [logs, needle],
  );
  const windowed = showAll || matched.length <= LOG_RENDER_WINDOW;
  const shown = windowed ? matched : matched.slice(-LOG_RENDER_WINDOW);
  //: The index the rendered slice starts at, so line numbers stay true to the
  //: real log rather than restarting at 1.
  const offset = needle ? 0 : logs.length - shown.length;

  useEffect(() => {
    // Following the tail only makes sense unfiltered; while searching, the user
    // is reading, and yanking the scroll away is hostile.
    if (stick && !needle && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [shown.length, stick, needle]);

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(matched.map((l) => l.message).join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked - the download link is the fallback */
    }
  }

  return (
    <Card className="!p-0">
      <div className="flex flex-wrap items-center gap-2 border-b border-ink-800 px-4 py-2.5">
        <button
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-2 text-sm font-medium text-slate-300 hover:text-white"
        >
          <Terminal className="h-4 w-4 text-slate-500" />
          Logs
          <ChevronDown className={`h-3.5 w-3.5 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} />
        </button>
        {live && (
          <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> live
          </span>
        )}
        <span className="text-[11px] text-slate-600">
          {loading ? "loading history…"
            : needle ? `${matched.length} of ${logs.length} lines`
            : `${logs.length} lines`}
        </span>

        <div className="ml-auto flex items-center gap-2">
          {open && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter…"
                className="w-36 rounded-md border border-ink-800 bg-ink-950 py-1 pl-7 pr-2 font-mono text-[11px] text-slate-300 placeholder:text-slate-600 focus:border-ink-600 focus:outline-none sm:w-48"
              />
            </div>
          )}
          <button
            onClick={copyAll}
            disabled={!matched.length}
            title="Copy the lines shown"
            className="rounded-md border border-ink-800 p-1.5 text-slate-500 transition-colors hover:text-slate-200 disabled:opacity-40"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
          {persisted && (
            <a
              href={api.logsDownloadUrl(id)}
              title="Download the full log"
              className="rounded-md border border-ink-800 p-1.5 text-slate-500 transition-colors hover:text-slate-200"
            >
              <Download className="h-3.5 w-3.5" />
            </a>
          )}
        </div>
      </div>

      {open && (
        <>
          {!windowed && (
            <div className="flex items-center gap-2 border-b border-ink-800 bg-ink-950/60 px-4 py-1.5 text-[11px] text-slate-500">
              Showing the last {LOG_RENDER_WINDOW.toLocaleString()} of {matched.length.toLocaleString()} lines.
              <button onClick={() => setShowAll(true)} className="text-brand-400 hover:text-brand-300">
                Render all
              </button>
              <span className="text-slate-600">(may take a moment)</span>
            </div>
          )}
          <div
            ref={ref}
            onScroll={(e) => {
              const el = e.currentTarget;
              setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
            }}
            className="max-h-[32rem] overflow-y-auto p-3 font-mono text-[11px] leading-relaxed text-slate-400"
          >
            {loading && logs.length === 0 ? (
              <p className="px-1 py-6 text-center text-slate-600">Loading log history…</p>
            ) : shown.length === 0 ? (
              <p className="px-1 py-6 text-center text-slate-600">
                {needle ? `Nothing matches "${query}".`
                  : live ? "Waiting for engine output…"
                  : "No log was recorded. The log is only written to disk when the server runs in verbose mode."}
              </p>
            ) : (
              shown.map((l, i) => (
                <div
                  key={`${offset + i}-${l.ts}`}
                  // content-visibility lets the browser skip layout and paint
                  // for lines scrolled out of view while keeping the scrollbar
                  // honest, which is what makes thousands of wrapped lines
                  // scroll smoothly without fixed-height virtualization.
                  style={{ contentVisibility: "auto", containIntrinsicSize: "0 16px" }}
                  className="flex gap-3 px-1 hover:bg-ink-800/40"
                >
                  <span className="w-12 shrink-0 select-none text-right text-slate-700">
                    {offset + i + 1}
                  </span>
                  <span className="min-w-0 whitespace-pre-wrap break-words">{l.message}</span>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </Card>
  );
}
