import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { LayoutDashboard, ScanLine, Settings as SettingsIcon, ShieldCheck, Github, CircleDot, Menu, X } from "lucide-react";
import { api, type AnalysisStatus } from "../api";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/scans", label: "Scans", icon: ScanLine },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

export default function Layout() {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [version, setVersion] = useState<string>("");
  const [navOpen, setNavOpen] = useState(false);
  const drawerRef = useRef<HTMLElement>(null);
  const { pathname } = useLocation();

  useEffect(() => {
    api.status().then(setStatus).catch(() => {});
    api.version().then((v) => setVersion(v.version)).catch(() => {});
  }, []);

  // A summoned layer must not trap the user: close it on navigation, on
  // Escape, and lock the page behind it while it is open.
  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!navOpen) return;
    const restore = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawerRef.current?.querySelector<HTMLElement>("a, button")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKey);
      restore?.focus?.();
    };
  }, [navOpen]);

  return (
    // No `h-full`: with it (and index.css's `html,body,#root{height:100%}`)
    // this container resolved to exactly 100vh, so the sticky aside/header
    // below had zero scroll travel inside it and just scrolled away with the
    // page. `min-h-screen` alone lets it grow with content instead.
    <div className="min-h-screen bg-ink-950">
      {/* Sidebar - fixed, not sticky: pulled out of flow entirely so it never
          moves, matching the mobile drawer's own `fixed` positioning below.
          `backdrop-blur` because page content now scrolls BENEATH this
          translucent (`bg-ink-900/60`) panel, same treatment the header
          already uses for the same reason. `top-[var(--app-banner-h,0px)]`
          instead of the `0` half of `inset-y-0`: `fixed` is anchored to the
          true viewport regardless of this element's position in the
          document flow, so anything rendered above the app in normal flow
          (the demo build's banner) would otherwise sit BEHIND this panel's
          left 16rem rather than push it down. The variable defaults to
          `0px` and is only ever set by the demo build, so the real app's
          layout is unaffected. */}
      <aside className="fixed left-0 top-[var(--app-banner-h,0px)] bottom-0 z-30 hidden w-64 flex-col overflow-y-auto border-r border-ink-800 bg-ink-900/60 p-4 pl-[max(1rem,env(safe-area-inset-left))] backdrop-blur md:flex">
        <SidebarBody status={status} version={version} />
      </aside>

      {/* Mobile navigation drawer - the sidebar's content as a summoned sheet. */}
      <div className="md:hidden">
        <div
          onClick={() => setNavOpen(false)}
          aria-hidden="true"
          className={`fixed inset-0 z-40 bg-black/60 transition-opacity duration-200 ${
            navOpen ? "opacity-100" : "pointer-events-none opacity-0"
          }`}
        />
        <aside
          ref={drawerRef}
          role="dialog"
          aria-modal="true"
          aria-label="Navigation"
          className={`fixed inset-y-0 left-0 z-50 flex w-72 max-w-[86vw] flex-col overflow-y-auto border-r border-ink-800 bg-ink-900/80 p-4 pb-[max(1rem,env(safe-area-inset-bottom))] pl-[max(1rem,env(safe-area-inset-left))] transition-[transform,opacity,backdrop-filter] ease-[cubic-bezier(0.32,0.72,0,1)] ${
            navOpen
              ? "translate-x-0 scale-100 opacity-100 backdrop-blur-xl duration-[380ms]"
              : "pointer-events-none -translate-x-full scale-[0.98] opacity-0 backdrop-blur-none duration-200"
          }`}
        >
          <button
            type="button"
            onClick={() => setNavOpen(false)}
            aria-label="Close navigation"
            className="absolute right-3 top-3 grid h-9 w-9 place-items-center rounded-lg text-slate-400 hover:bg-ink-800"
          >
            <X className="h-4 w-4" />
          </button>
          <SidebarBody status={status} version={version} onNavigate={() => setNavOpen(false)} />
        </aside>
      </div>

      {/* Main - `md:pl-64` clears the fixed aside on desktop; `main`'s own
          `mx-auto max-w-7xl` centres inside whatever space is left. */}
      <div className="flex min-h-screen min-w-0 flex-col md:pl-64">
        <header className="sticky top-[var(--app-banner-h,0px)] z-10 flex h-16 items-center justify-between gap-3 border-b border-ink-800 bg-ink-950/80 px-5 pl-[max(1.25rem,env(safe-area-inset-left))] backdrop-blur md:px-8">
          <div className="flex min-w-0 items-center gap-1.5 md:hidden">
            <button
              type="button"
              aria-label="Open navigation"
              aria-expanded={navOpen}
              onClick={() => setNavOpen(true)}
              className="-ml-1 grid h-10 w-10 shrink-0 place-items-center rounded-lg text-slate-300 hover:bg-ink-800"
            >
              <Menu className="h-5 w-5" />
            </button>
            <ShieldCheck className="h-5 w-5 shrink-0 text-brand-400" />
            <span className="truncate text-sm font-semibold text-white">{__APP_NAME__}</span>
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

function SidebarBody({ status, version, onNavigate }: { status: AnalysisStatus | null; version: string; onNavigate?: () => void }) {
  return (
    <>
      <div className="mb-8 flex items-center gap-2.5 px-2">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-brand-600/15 ring-1 ring-brand-500/30">
          <ShieldCheck className="h-5 w-5 text-brand-400" />
        </div>
        <div className="min-w-0 leading-tight">
          <div className="truncate text-sm font-semibold text-white">{__APP_NAME__}</div>
          <div className="text-[11px] text-slate-500">Mobile Security Scanner</div>
        </div>
      </div>

      <nav className="flex flex-1 flex-col gap-1">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive ? "bg-brand-600/15 text-brand-300 ring-1 ring-inset ring-brand-500/20" : "text-slate-400 hover:bg-ink-800 hover:text-slate-200"
              }`
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-4 space-y-3 border-t border-ink-800 pt-4">
        <ReadinessIndicator status={status} />
        <a
          href={__APP_HOMEPAGE__}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-2 px-2 text-xs text-slate-500 hover:text-slate-300"
        >
          <Github className="h-3.5 w-3.5 shrink-0" /> GitHub
        </a>
        {/* slate-600 is ~2.2:1 at 11px - fails outright. slate-500 (~3.7:1)
            still isn't enough below 18pt, so this is the floor: slate-400. */}
        <div className="px-2 text-[11px] text-slate-400">v{version || __APP_VERSION__}</div>
      </div>
    </>
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
      {/* slate-500 is ~3.7:1 on ink-800 at this 12px size - below the 4.5:1
          floor for text under 18pt; slate-400 (~7:1) clears it. */}
      <span className="text-slate-400">{label}</span>
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
      className={`inline-flex shrink-0 items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium ring-1 ring-inset ${
        ready ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-amber-500/10 text-amber-300 ring-amber-500/30"
      }`}
    >
      <CircleDot className="h-3.5 w-3.5 shrink-0" />
      <span className="truncate">{ready ? "Ready to scan" : "Finish setup in Settings"}</span>
    </NavLink>
  );
}
