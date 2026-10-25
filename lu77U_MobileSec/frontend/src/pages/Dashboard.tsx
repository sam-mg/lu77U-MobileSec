import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { ScanLine, ShieldAlert, Activity, Boxes, ArrowRight } from "lucide-react";
import { api, type ScanMeta, type AnalysisStatus } from "../api";
import UploadCard from "../components/UploadCard";
import ScanTable from "../components/ScanTable";
import { Card, SectionTitle, EmptyState, Spinner, StatPanel } from "../components/ui";
import { SEVERITIES, SEVERITY_META } from "../lib/format";

/** Loose but real shape check on one parsed-JSON scan entry - enough to trust it before it is aggregated and charted below. */
function isScanMeta(value: unknown): value is ScanMeta {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { id?: unknown }).id === "string" &&
    typeof (value as { status?: unknown }).status === "string"
  );
}

export default function Dashboard() {
  const [scans, setScans] = useState<ScanMeta[] | null>(null);
  const [status, setStatus] = useState<AnalysisStatus | null>(null);

  useEffect(() => {
    // Validate the fetched list right where it enters the component, so the memos below never fold or chart an entry that isn't shaped like a scan.
    api
      .listScans()
      .then((r) => setScans(Array.isArray(r.scans) ? r.scans.filter(isScanMeta) : []))
      .catch(() => setScans([]));
    api.status().then(setStatus).catch(() => {});
  }, []);

  const totals = useMemo(() => {
    const list = scans || [];
    const acc = { scans: list.length, completed: 0, vulns: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const s of list) {
      if (s.status === "completed") acc.completed += 1;
      const sum = s.summary || {};
      acc.vulns += (sum.critical || 0) + (sum.high || 0) + (sum.medium || 0) + (sum.low || 0);
      acc.critical += sum.critical || 0;
      acc.high += sum.high || 0;
      acc.medium += sum.medium || 0;
      acc.low += sum.low || 0;
    }
    return acc;
  }, [scans]);

  const donut = useMemo(
    () =>
      SEVERITIES.filter((s) => s !== "info").map((s) => ({
        name: SEVERITY_META[s].label,
        value: (totals as Record<string, number>)[s] || 0,
        color: SEVERITY_META[s].hex,
      })),
    [totals],
  );
  const donutTotal = donut.reduce((a, b) => a + b.value, 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Security Overview</h1>
        <p className="mt-1 text-sm text-slate-400">Android app scans: findings graded by severity, exploit chains, and what was verified on a device.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <UploadCard ready={!!status?.ready_for_analysis} />
        </div>
        <StatPanel
          items={[
            { icon: <ScanLine className="h-4 w-4 shrink-0" />, label: "Total scans", value: totals.scans },
            { icon: <Activity className="h-4 w-4 shrink-0" />, label: "Completed", value: totals.completed },
            { icon: <ShieldAlert className="h-4 w-4 shrink-0" />, label: "Vulnerabilities", value: totals.vulns, tone: "warn" },
            { icon: <Boxes className="h-4 w-4 shrink-0" />, label: "Critical issues", value: totals.critical, tone: "bad" },
          ]}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <SectionTitle>Severity distribution</SectionTitle>
          <div className="flex flex-wrap items-center gap-4">
            <div
              className="relative aspect-square shrink-0"
              style={{ width: "clamp(116px, 40vw, 144px)" }}
            >
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={donutTotal ? donut : [{ name: "none", value: 1, color: "rgba(255,255,255,0.08)" }]} dataKey="value" innerRadius="70%" outerRadius="100%" paddingAngle={donutTotal ? 2 : 0} stroke="none">
                    {(donutTotal ? donut : [{ color: "rgba(255,255,255,0.08)" }]).map((d, i) => (
                      <Cell key={i} fill={(d as { color: string }).color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-xl font-bold tabular-nums text-white">{donutTotal}</span>
                <span className="text-[9px] uppercase tracking-wide text-slate-500">vulnerabilities</span>
              </div>
            </div>
            <div className="grow basis-36 space-y-1.5">
              {SEVERITIES.filter((s) => s !== "info").map((s) => (
                <div key={s} className="flex items-center justify-between gap-2 text-sm">
                  <span className="flex min-w-0 items-center gap-2 text-slate-400">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_META[s].hex }} />
                    <span className="truncate">{SEVERITY_META[s].label}</span>
                  </span>
                  <span className="shrink-0 font-medium tabular-nums text-slate-200">{(totals as Record<string, number>)[s] || 0}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <SectionTitle action={<Link to="/scans" className="flex items-center gap-1 text-xs text-brand-400 hover:text-brand-300">View all <ArrowRight className="h-3 w-3 shrink-0" /></Link>}>
            Recent scans
          </SectionTitle>
          {scans == null ? (
            <div className="flex justify-center py-12"><Spinner className="h-6 w-6 text-slate-500" /></div>
          ) : scans.length === 0 ? (
            <EmptyState icon={<ScanLine className="h-8 w-8" />} title="No scans yet" hint="Upload an APK above to run your first analysis." />
          ) : (
            <ScanTable scans={scans.slice(0, 5)} compact />
          )}
        </Card>
      </div>
    </div>
  );
}