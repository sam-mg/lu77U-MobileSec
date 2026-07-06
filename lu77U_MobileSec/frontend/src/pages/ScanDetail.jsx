import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft, Download, FileJson, FileText, FileCode2, Terminal, Package,
  Cpu, Layers, AlertTriangle, Trash2,
} from "lucide-react";
import { api, type ScanMeta, type ScanResult } from "../api";
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

  const terminal = meta?.status === "completed" || meta?.status === "failed";
  const stream = useScanStream(id, !!meta && !terminal, () => refetch());

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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link to="/scans" className="mb-2 inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300">
            <ArrowLeft className="h-3.5 w-3.5" /> Scans
          </Link>
          <h1 className="truncate text-2xl font-bold text-white">{title}</h1>
          <p className="mt-1 font-mono text-xs text-slate-500">{app?.package_name || sum.package_name || meta.filename}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={(liveStatus as ScanMeta["status"]) || "queued"} />
          <button className="btn-danger" onClick={remove}><Trash2 className="h-4 w-4" /> Delete</button>
        </div>
      </div>

      {isRunning ? (
        <ProgressView meta={meta} stream={stream} />
      ) : liveStatus === "failed" ? (
        <FailedView meta={meta} stream={stream} />
      ) : result ? (
        <CompletedView id={id} meta={meta} result={result} />
      ) : (
        <Card><p className="text-sm text-slate-400">No result available for this scan.</p></Card>
      )}
    </div>
  );
}

function ProgressView({ meta, stream }: { meta: ScanMeta; stream: ReturnType<typeof useScanStream> }) {
  const pct = stream.progress.percent || meta.progress || 0;
  const phase = stream.progress.phase || meta.phase || "starting";
  return (
    <div className="space-y-6">
      <Card>
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
            <Spinner className="h-4 w-4 text-brand-400" /> Analyzing — <span className="capitalize text-slate-400">{phase.replace(/_/g, " ")}</span>
          </div>
          <span className="text-sm font-semibold text-brand-300">{Math.round(pct)}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-ink-800">
          <div className="h-full rounded-full bg-gradient-to-r from-brand-600 to-brand-400 transition-all duration-500" style={{ width: `${pct}%` }} />
        </div>
        {stream.progress.message && <p className="mt-2 text-xs text-slate-500">{stream.progress.message}</p>}
      </Card>
      <LogPanel logs={stream.logs} live />
    </div>
  );
}

function FailedView({ meta, stream }: { meta: ScanMeta; stream: ReturnType<typeof useScanStream> }) {
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
      <LogPanel logs={stream.logs} />
    </div>
  );
}

function CompletedView({ id, meta, result }: { id: string; meta: ScanMeta; result: ScanResult }) {
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
              Deep vulnerability analysis isn’t supported for this framework yet — detection-only report.
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
        {value ?? "—"}
      </div>
    </div>
  );
}

function LogPanel({ logs, live }: { logs: { message: string; ts: string }[]; live?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const [stick, setStick] = useState(true);
  useEffect(() => {
    if (stick && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs, stick]);

  return (
    <Card className="!p-0">
      <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-2.5">
        <Terminal className="h-4 w-4 text-slate-500" />
        <span className="text-sm font-medium text-slate-300">Logs</span>
        {live && <span className="ml-1 inline-flex items-center gap-1 text-[11px] text-emerald-400"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" /> live</span>}
        <span className="ml-auto text-[11px] text-slate-600">{logs.length} lines</span>
      </div>
      <div
        ref={ref}
        onScroll={(e) => {
          const el = e.currentTarget;
          setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
        }}
        className="max-h-80 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed text-slate-400"
      >
        {logs.length === 0 ? (
          <p className="px-1 py-6 text-center text-slate-600">Waiting for engine output…</p>
        ) : (
          logs.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap break-words px-1 hover:bg-ink-800/40">
              {l.message}
            </div>
          ))
        )}
      </div>
    </Card>
  );
}