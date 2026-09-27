import { Link } from "react-router-dom";
import { Trash2, FileText, ChevronRight, Pause, Play, Square } from "lucide-react";
import type { ScanMeta } from "../api";
import { StatusBadge, PlatformBadge } from "./ui";
import { timeAgo, scoreColor } from "../lib/format";

function SevCell({ n, cls }: { n?: number; cls: string }) {
  const v = n ?? 0;
  return <span className={v > 0 ? cls : "text-slate-600"}>{v}</span>;
}

interface Actions {
  onDelete?: (id: string) => void;
  onStop?: (id: string) => void;
  onPause?: (id: string) => void;
  onResume?: (id: string) => void;
}

function RowActions({ s, onDelete, onStop, onPause, onResume, chevron }: Actions & { s: ScanMeta; chevron?: boolean }) {
  const active = s.status === "running" || s.status === "queued";
  const paused = s.status === "paused";
  const iconBtn = "rounded-md p-1.5 text-slate-500 hover:bg-ink-700 hover:text-slate-200";
  return (
    <div className="flex items-center justify-end gap-1">
      {active && onPause && (
        <button className={iconBtn} title="Pause scan" onClick={() => onPause(s.id)}>
          <Pause className="h-4 w-4" />
        </button>
      )}
      {active && onStop && (
        <button className={iconBtn} title="Stop scan" onClick={() => onStop(s.id)}>
          <Square className="h-4 w-4" />
        </button>
      )}
      {paused && onResume && (
        <button className={iconBtn} title="Resume scan" onClick={() => onResume(s.id)}>
          <Play className="h-4 w-4" />
        </button>
      )}
      <Link to={`/scans/${s.id}`} className={iconBtn} title="View report">
        <FileText className="h-4 w-4" />
      </Link>
      {onDelete && (
        <button
          className="rounded-md p-1.5 text-slate-500 hover:bg-rose-900/40 hover:text-rose-300"
          title="Delete scan"
          onClick={() => onDelete(s.id)}
        >
          <Trash2 className="h-4 w-4" />
        </button>
      )}
      {chevron && (
        <Link to={`/scans/${s.id}`} className="rounded-md p-1.5 text-slate-600 hover:text-slate-300">
          <ChevronRight className="h-4 w-4" />
        </Link>
      )}
    </div>
  );
}

export default function ScanTable({ scans, onDelete, onStop, onPause, onResume }: Actions & { scans: ScanMeta[] }) {
  const acts = { onDelete, onStop, onPause, onResume };
  return (
    <>
      {/* Phone: one panel of stacked rows - the 10-column table below does not
          fit a narrow screen and sideways-scrolling a table is hostile. */}
      <div className="divide-y divide-white/[0.06] md:hidden">
        {scans.map((s) => {
          const sum = s.summary || {};
          const name = sum.app_name || s.filename;
          return (
            <div key={s.id} className="flex items-start gap-2 px-2 py-3">
              <Link to={`/scans/${s.id}`} className="min-w-0 flex-1">
                <div className="truncate font-medium text-slate-200">{name}</div>
                <div className="truncate font-mono text-[11px] text-slate-500">{sum.package_name || s.filename}</div>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
                  <StatusBadge status={s.status} pauseReason={s.pause_reason} />
                  {sum.primary_framework && <PlatformBadge framework={sum.primary_framework} />}
                  <span className="tabular-nums text-slate-600">
                    <SevCell n={sum.critical} cls="text-rose-400" /> /{" "}
                    <SevCell n={sum.high} cls="text-orange-400" /> /{" "}
                    <SevCell n={sum.medium} cls="text-amber-400" /> /{" "}
                    <SevCell n={sum.low} cls="text-emerald-400" />
                  </span>
                  {sum.security_score != null && (
                    <span className={`font-semibold tabular-nums ${scoreColor(sum.security_score)}`}>
                      {Math.round(sum.security_score)}
                    </span>
                  )}
                  <span className="text-slate-500">{timeAgo(s.created_at)}</span>
                </div>
              </Link>
              <div className="shrink-0">
                <RowActions s={s} {...acts} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Wider screens: the full table, scrolling sideways inside its own box
          if it ever overflows - never the page. */}
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-ink-800 text-xs uppercase tracking-wider text-slate-500">
              <th className="px-3 py-2.5 font-medium">Application</th>
              <th className="px-3 py-2.5 font-medium">Framework</th>
              <th className="px-3 py-2.5 text-center font-medium" title="Critical">C</th>
              <th className="px-3 py-2.5 text-center font-medium" title="High">H</th>
              <th className="px-3 py-2.5 text-center font-medium" title="Medium">M</th>
              <th className="px-3 py-2.5 text-center font-medium" title="Low">L</th>
              <th className="px-3 py-2.5 text-center font-medium">Score</th>
              <th className="px-3 py-2.5 font-medium">Status</th>
              <th className="px-3 py-2.5 font-medium">When</th>
              <th className="px-3 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => {
              const sum = s.summary || {};
              const name = sum.app_name || s.filename;
              return (
                <tr key={s.id} className="group border-b border-ink-800/60 transition-colors hover:bg-ink-800/30">
                  <td className="px-3 py-3">
                    <Link to={`/scans/${s.id}`} className="block">
                      <div className="font-medium text-slate-200 group-hover:text-white">{name}</div>
                      <div className="font-mono text-[11px] text-slate-500">{sum.package_name || s.filename}</div>
                    </Link>
                  </td>
                  <td className="px-3 py-3">
                    <PlatformBadge framework={sum.primary_framework} />
                  </td>
                  <td className="px-3 py-3 text-center tabular-nums"><SevCell n={sum.critical} cls="text-rose-400" /></td>
                  <td className="px-3 py-3 text-center tabular-nums"><SevCell n={sum.high} cls="text-orange-400" /></td>
                  <td className="px-3 py-3 text-center tabular-nums"><SevCell n={sum.medium} cls="text-amber-400" /></td>
                  <td className="px-3 py-3 text-center tabular-nums"><SevCell n={sum.low} cls="text-emerald-400" /></td>
                  <td className={`px-3 py-3 text-center font-semibold tabular-nums ${scoreColor(sum.security_score)}`}>
                    {sum.security_score == null ? "-" : Math.round(sum.security_score)}
                  </td>
                  <td className="px-3 py-3"><StatusBadge status={s.status} pauseReason={s.pause_reason} /></td>
                  <td className="px-3 py-3 text-slate-400">{timeAgo(s.created_at)}</td>
                  <td className="px-3 py-3">
                    <RowActions s={s} {...acts} chevron />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
