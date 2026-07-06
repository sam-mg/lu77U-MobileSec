import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { LayoutDashboard, ScanLine, Settings as SettingsIcon, ShieldCheck, Github, CircleDot } from "lucide-react";
import { api, type AnalysisStatus } from "../api";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/scans", label: "Scans", icon: ScanLine },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

export default function Layout() {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [version, setVersion] = useState<string>("");

  useEffect(() => {
    api.status().then(setStatus).catch(() => {});
    api.version().then((v) => setVersion(v.version)).catch(() => {});
  }, []);

  return (
    <div className="flex h-full min-h-screen bg-ink-950">
      {/* Sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-ink-800 bg-ink-900/60 p-4 md:flex">
        <div className="mb-8 flex items-center gap-2.5 px-2">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-brand-600/15 ring-1 ring-brand-500/30">
            <ShieldCheck className="h-5 w-5 text-brand-400" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-white">lu77U-MobileSec</div>
            <div className="text-[11px] text-slate-500">Mobile Security Scanner</div>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive ? "bg-brand-600/15 text-brand-300 ring-1 ring-inset ring-brand-500/20" : "text-slate-400 hover:bg-ink-800 hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-4 space-y-3 border-t border-ink-800 pt-4">
          <ReadinessIndicator status={status} />
          <a
            href="https://github.com/sam-mg/lu77U-MobileSec"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-2 text-xs text-slate-500 hover:text-slate-300"
          >
            <Github className="h-3.5 w-3.5" /> GitHub
          </a>
          <div className="px-2 text-[11px] text-slate-600">v{version || "0.0.3"}</div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-ink-800 bg-ink-950/80 px-5 backdrop-blur md:px-8">
          <div className="flex items-center gap-2 md:hidden">
            <ShieldCheck className="h-5 w-5 text-brand-400" />
            <span className="text-sm font-semibold text-white">lu77U-MobileSec</span>
          </div>
          <div className="hidden md:block" />
          <ReadinessPill status={status} />
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-5 py-6 md:px-8 md:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function ReadinessIndicator({ status }: { status: AnalysisStatus | null }) {
  const ready = status?.ready_for_analysis;
  return (
    <div className="rounded-lg bg-ink-800/50 px-3 py-2 text-xs">
      <div className="mb-1.5 font-medium text-slate-400">Engine status</div>
      <Row label="JADX" ok={status?.jadx_configured} />
      <Row label="AI provider" ok={status?.ollama_configured} />
      <div className={`mt-1.5 font-medium ${ready ? "text-emerald-400" : "text-amber-400"}`}>
        {ready ? "Ready to scan" : "Setup required"}
      </div>
    </div>
  );
}

function Row({ label, ok }: { label: string; ok?: boolean }) {
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-slate-500">{label}</span>
      <span className={ok ? "text-emerald-400" : "text-rose-400"}>{ok ? "configured" : "not set"}</span>
    </div>
  );
}

function ReadinessPill({ status }: { status: AnalysisStatus | null }) {
  if (!status) return null;
  const ready = status.ready_for_analysis;
  return (
    <NavLink
      to="/settings"
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium ring-1 ring-inset ${
        ready ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-amber-500/10 text-amber-300 ring-amber-500/30"
      }`}
    >
      <CircleDot className="h-3.5 w-3.5" />
      {ready ? "Ready to scan" : "Finish setup in Settings"}
    </NavLink>
  );
}