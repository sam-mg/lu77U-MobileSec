import { useEffect, useMemo, useState } from "react";
import { Search, ScanLine, RefreshCw } from "lucide-react";
import { api, type ScanMeta } from "../api";
import ScanTable from "../components/ScanTable";
import { Card, EmptyState, Spinner } from "../components/ui";

const FILTERS = ["all", "running", "completed", "failed"] as const;

export default function Scans() {
  const [scans, setScans] = useState<ScanMeta[] | null>(null);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const [refreshing, setRefreshing] = useState(false);

  async function load() {
    setRefreshing(true);
    try {
      const r = await api.listScans();
      setScans(r.scans);
    } catch {
      setScans([]);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
    // Poll while anything is in flight so statuses update without a manual refresh.
    const t = setInterval(() => {
      setScans((cur) => {
        if (cur && cur.some((s) => s.status === "running" || s.status === "queued")) load();
        return cur;
      });
    }, 4000);
    return () => clearInterval(t);
  }, []);

  async function remove(id: string) {
    if (!confirm("Delete this scan and its outputs?")) return;
    await api.deleteScan(id).catch(() => {});
    setScans((cur) => (cur ? cur.filter((s) => s.id !== id) : cur));
  }

  const filtered = useMemo(() => {
    let list = scans || [];
    if (filter !== "all") list = list.filter((s) => s.status === filter);
    const needle = q.trim().toLowerCase();
    if (needle)
      list = list.filter((s) => {
        const sum = s.summary || {};
        return (
          s.filename.toLowerCase().includes(needle) ||
          (sum.app_name || "").toLowerCase().includes(needle) ||
          (sum.package_name || "").toLowerCase().includes(needle) ||
          (sum.primary_framework || "").toLowerCase().includes(needle)
        );
      });
    return list;
  }, [scans, q, filter]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Scans</h1>
          <p className="mt-1 text-sm text-slate-400">All analyses run on this machine.</p>
        </div>
        <button className="btn-ghost" onClick={load} disabled={refreshing}>
          <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      <Card className="!p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-ink-800 p-4">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              className="input pl-9"
              placeholder="Search by app, package, or framework…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <div className="flex rounded-lg bg-ink-800/60 p-0.5 text-xs">
            {FILTERS.map((f) => (
              <button
                key={f}
                className={`rounded-md px-3 py-1.5 font-medium capitalize ${filter === f ? "bg-ink-700 text-white" : "text-slate-400 hover:text-slate-200"}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        <div className="p-2">
          {scans == null ? (
            <div className="flex justify-center py-16"><Spinner className="h-6 w-6 text-slate-500" /></div>
          ) : filtered.length === 0 ? (
            <EmptyState
              icon={<ScanLine className="h-8 w-8" />}
              title={scans.length === 0 ? "No scans yet" : "No matching scans"}
              hint={scans.length === 0 ? "Start one from the Overview page." : "Try a different search or filter."}
            />
          ) : (
            <ScanTable scans={filtered} onDelete={remove} />
          )}
        </div>
      </Card>
    </div>
  );
}