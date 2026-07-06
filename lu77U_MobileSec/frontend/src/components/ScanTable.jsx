import { Link } from "react-router-dom";
import { Trash2, FileText, ChevronRight } from "lucide-react";
import type { ScanMeta } from "../api";
import { StatusBadge, PlatformBadge } from "./ui";
import { timeAgo, scoreColor } from "../lib/format";

function SevCell({ n, cls }: { n?: number; cls: string }) {
  const v = n ?? 0;
  return <span className={v > 0 ? cls : "text-slate-600"}>{v}</span>;
}

export default function ScanTable({
  scans,
  onDelete,
}: {
  scans: ScanMeta[];
  onDelete?: (id: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
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
                <td className="px-3 py-3 text-center"><SevCell n={sum.critical} cls="text-rose-400" /></td>
                <td className="px-3 py-3 text-center"><SevCell n={sum.high} cls="text-orange-400" /></td>
                <td className="px-3 py-3 text-center"><SevCell n={sum.medium} cls="text-amber-400" /></td>
                <td className="px-3 py-3 text-center"><SevCell n={sum.low} cls="text-emerald-400" /></td>
                <td className={`px-3 py-3 text-center font-semibold ${scoreColor(sum.security_score)}`}>
                  {sum.security_score == null ? "—" : Math.round(sum.security_score)}
                </td>
                <td className="px-3 py-3"><StatusBadge status={s.status} /></td>
                <td className="px-3 py-3 text-slate-400">{timeAgo(s.created_at)}</td>
                <td className="px-3 py-3">
                  <div className="flex items-center justify-end gap-1">
                    <Link
                      to={`/scans/${s.id}`}
                      className="rounded-md p-1.5 text-slate-500 hover:bg-ink-700 hover:text-slate-200"
                      title="View report"
                    >
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
                    <Link to={`/scans/${s.id}`} className="rounded-md p-1.5 text-slate-600 hover:text-slate-300">
                      <ChevronRight className="h-4 w-4" />
                    </Link>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}