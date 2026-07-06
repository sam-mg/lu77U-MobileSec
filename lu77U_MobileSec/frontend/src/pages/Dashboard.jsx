import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { ScanLine, ShieldAlert, Activity, Boxes, ArrowRight } from "lucide-react";
import { api, type ScanMeta, type AnalysisStatus } from "../api";
import UploadCard from "../components/UploadCard";
import ScanTable from "../components/ScanTable";
import { Card, SectionTitle, EmptyState, Spinner } from "../components/ui";
import { SEVERITIES, SEVERITY_META } from "../lib/format";

export default function Dashboard() {
  const [scans, setScans] = useState<ScanMeta[] | null>(null);
  const [status, setStatus] = useState<AnalysisStatus | null>(null);

  useEffect(() => {
    api.listScans().then((r) => setScans(r.scans)).catch(() => setScans([]));
    api.status().then(setStatus).catch(() => {});
  }, []);

  const totals = useMemo(() => {
    const list = scans || [];
    const acc = { scans: list.length, completed: 0, vulns: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const s of list) {
      if (s.status === "completed") acc.completed += 1;
      const sum = s.summary || {};
      acc.vulns += sum.total_vulnerabilities || 0;
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
        <p className="mt-1 text-sm text-slate-400">Scan Android apps for framework fingerprints and source-level vulnerabilities.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <UploadCard ready={!!status?.ready_for_analysis} />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <Stat icon={<ScanLine className="h-4 w-4" />} label="Total scans" value={totals.scans} />
          <Stat icon={<Activity className="h-4 w-4" />} label="Completed" value={totals.completed} />
          <Stat icon={<ShieldAlert className="h-4 w-4" />} label="Vulnerabilities" value={totals.vulns} tone="warn" />
          <Stat icon={<Boxes className="h-4 w-4" />} label="Critical issues" value={totals.critical} tone="bad" />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <SectionTitle>Severity distribution</SectionTitle>
          <div className="flex items-center gap-4">
            <div className="relative h-36 w-36 shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={donutTotal ? donut : [{ name: "none", value: 1, color: "#1e293b" }]} dataKey="value" innerRadius={46} outerRadius={66} paddingAngle={donutTotal ? 2 : 0} stroke="none">
                    {(donutTotal ? donut : [{ color: "#1e293b" }]).map((d, i) => (
                      <Cell key={i} fill={(d as { color: string }).color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-xl font-bold text-white">{donutTotal}</span>
                <span className="text-[10px] uppercase tracking-wider text-slate-500">findings</span>
              </div>
            </div>
            <div className="flex-1 space-y-1.5">
              {SEVERITIES.filter((s) => s !== "info").map((s) => (
                <div key={s} className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2 text-slate-400">
                    <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_META[s].hex }} />
                    {SEVERITY_META[s].label}
                  </span>
                  <span className="font-medium text-slate-200">{(totals as Record<string, number>)[s] || 0}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <SectionTitle action={<Link to="/scans" className="flex items-center gap-1 text-xs text-brand-400 hover:text-brand-300">View all <ArrowRight className="h-3 w-3" /></Link>}>
            Recent scans
          </SectionTitle>
          {scans == null ? (
            <div className="flex justify-center py-12"><Spinner className="h-6 w-6 text-slate-500" /></div>
          ) : scans.length === 0 ? (
            <EmptyState icon={<ScanLine className="h-8 w-8" />} title="No scans yet" hint="Upload an APK above to run your first analysis." />
          ) : (
            <ScanTable scans={scans.slice(0, 6)} />
          )}
        </Card>
      </div>
    </div>
  );
}

function Stat({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: number; tone?: "warn" | "bad" }) {
  const valueCls = tone === "bad" ? "text-rose-400" : tone === "warn" ? "text-amber-400" : "text-white";
  return (
    <Card className="flex flex-col justify-between !p-4">
      <div className="flex items-center gap-2 text-slate-500">
        {icon}
        <span className="text-xs font-medium uppercase tracking-wide">{label}</span>
      </div>
      <div className={`mt-3 text-3xl font-bold ${valueCls}`}>{value}</div>
    </Card>
  );
}