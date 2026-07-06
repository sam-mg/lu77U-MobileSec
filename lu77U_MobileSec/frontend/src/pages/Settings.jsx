import { useEffect, useState } from "react";
import {
  Check, KeyRound, Loader2, Plug, RefreshCw, Save, Wrench, FileText, X, Eye, EyeOff,
} from "lucide-react";
import { api, type Settings as SettingsT } from "../api";
import { Card, SectionTitle, Spinner } from "../components/ui";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [selected, setSelected] = useState<string>("");

  async function reload() {
    const s = await api.getSettings();
    setSettings(s);
    setSelected((cur) => cur || s.active_provider);
  }

  useEffect(() => {
    reload().catch(() => {});
  }, []);

  if (!settings) return <div className="flex justify-center py-24"><Spinner className="h-7 w-7 text-slate-500" /></div>;

  const provider = settings.providers[selected];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="mt-1 text-sm text-slate-400">Configure the AI provider, decompiler, and reporting.</p>
      </div>

      <ReadinessBanner settings={settings} />

      <div className="grid gap-6 lg:grid-cols-3">
        <GeneralCard settings={settings} onChange={reload} />
        <div className="lg:col-span-2">
          <Card>
            <SectionTitle>AI providers</SectionTitle>
            <div className="mb-4 flex flex-wrap gap-2">
              {settings.provider_order.map((name) => {
                const p = settings.providers[name];
                const isActive = settings.active_provider === name;
                return (
                  <button
                    key={name}
                    onClick={() => setSelected(name)}
                    className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium ring-1 ring-inset transition-colors ${
                      selected === name ? "bg-ink-700 text-white ring-ink-600" : "bg-ink-800/40 text-slate-400 ring-ink-800 hover:text-slate-200"
                    }`}
                  >
                    {p.display_name.split(" ")[0]}
                    {p.has_api_key && <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" title="API key set" />}
                    {isActive && <span className="rounded bg-brand-600/30 px-1 text-[10px] text-brand-300">active</span>}
                  </button>
                );
              })}
            </div>
            {provider && <ProviderEditor key={selected} settings={settings} name={selected} onChange={reload} />}
          </Card>
        </div>
      </div>
    </div>
  );
}

function ReadinessBanner({ settings }: { settings: SettingsT }) {
  const { jadx_configured, ollama_configured, ready_for_analysis } = settings.status;
  if (ready_for_analysis)
    return (
      <div className="flex items-center gap-2 rounded-xl bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300 ring-1 ring-inset ring-emerald-500/20">
        <Check className="h-4 w-4" /> Everything is configured — you’re ready to scan.
      </div>
    );
  return (
    <div className="rounded-xl bg-amber-500/10 px-4 py-3 text-sm text-amber-300 ring-1 ring-inset ring-amber-500/20">
      <p className="font-medium">Setup required before scanning:</p>
      <ul className="mt-1 list-inside list-disc text-amber-300/80">
        {!jadx_configured && <li>Set a valid JADX executable path.</li>}
        {!ollama_configured && <li>Configure an API key (or local mode) for the active provider.</li>}
      </ul>
    </div>
  );
}

function GeneralCard({ settings, onChange }: { settings: SettingsT; onChange: () => Promise<void> }) {
  const [jadx, setJadx] = useState(settings.jadx_path);
  const [pdf, setPdf] = useState(settings.pdf_generation);
  const [saving, setSaving] = useState(false);

  async function save(payload: Record<string, unknown>) {
    setSaving(true);
    try {
      await api.updateSettings(payload);
      await onChange();
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <SectionTitle>General</SectionTitle>
      <div className="space-y-5">
        <div>
          <label className="label">Active provider</label>
          <select
            className="input"
            value={settings.active_provider}
            onChange={(e) => save({ active_provider: e.target.value })}
          >
            {settings.provider_order.map((n) => (
              <option key={n} value={n}>{settings.providers[n].display_name}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="label flex items-center gap-1"><Wrench className="h-3 w-3" /> JADX path</label>
          <div className="flex gap-2">
            <input className="input font-mono text-xs" value={jadx} onChange={(e) => setJadx(e.target.value)} placeholder="/opt/homebrew/bin/jadx" />
            <button className="btn-ghost shrink-0" disabled={saving} onClick={() => save({ jadx_path: jadx })}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            </button>
          </div>
          <p className={`mt-1 text-[11px] ${settings.status.jadx_configured ? "text-emerald-400" : "text-slate-500"}`}>
            {settings.status.jadx_configured ? "JADX detected at this path." : "Path to the JADX decompiler executable."}
          </p>
        </div>

        <label className="flex cursor-pointer items-center justify-between">
          <span className="flex items-center gap-1.5 text-sm text-slate-300"><FileText className="h-4 w-4 text-slate-500" /> Generate PDF reports</span>
          <button
            role="switch"
            aria-checked={pdf}
            onClick={() => { setPdf(!pdf); save({ pdf_generation: !pdf }); }}
            className={`relative h-6 w-11 rounded-full transition-colors ${pdf ? "bg-brand-600" : "bg-ink-700"}`}
          >
            <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${pdf ? "left-5" : "left-0.5"}`} />
          </button>
        </label>
      </div>
    </Card>
  );
}

function ProviderEditor({ settings, name, onChange }: { settings: SettingsT; name: string; onChange: () => Promise<void> }) {
  const p = settings.providers[name];
  const [model, setModel] = useState(p.model);
  const [mode, setMode] = useState(p.mode || "cloud");
  const [baseUrl, setBaseUrl] = useState(p.base_url || "");
  const [models, setModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [savingCfg, setSavingCfg] = useState(false);
  const [savingKey, setSavingKey] = useState(false);
  const [test, setTest] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testing, setTesting] = useState(false);

  async function loadModels() {
    setLoadingModels(true);
    try {
      const r = await api.listModels(name);
      setModels(r.models);
    } finally {
      setLoadingModels(false);
    }
  }

  useEffect(() => {
    loadModels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  async function saveConfig() {
    setSavingCfg(true);
    try {
      const fields: Record<string, unknown> = { model };
      if (name === "ollama") fields.mode = mode;
      if (name === "custom") fields.base_url = baseUrl;
      await api.updateSettings({ providers: { [name]: fields } });
      await onChange();
    } finally {
      setSavingCfg(false);
    }
  }

  async function saveKey(clear = false) {
    setSavingKey(true);
    try {
      await api.setCredential(name, clear ? null : apiKey);
      setApiKey("");
      await onChange();
    } finally {
      setSavingKey(false);
    }
  }

  async function runTest() {
    setTesting(true);
    setTest(null);
    try {
      const r = await api.testProvider(name);
      setTest({ ok: r.ok, msg: r.ok ? `Reachable · ${r.model}` : r.error || "Validation failed" });
    } catch (e) {
      setTest({ ok: false, msg: e instanceof Error ? e.message : "Test failed" });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="space-y-5 rounded-xl border border-ink-800 bg-ink-950/40 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200">{p.display_name}</h3>
        {name !== settings.active_provider && (
          <button className="text-xs text-brand-400 hover:text-brand-300" onClick={() => api.updateSettings({ active_provider: name }).then(onChange)}>
            Make active
          </button>
        )}
      </div>

      {name === "ollama" && (
        <div>
          <label className="label">Mode</label>
          <div className="flex rounded-lg bg-ink-800/60 p-0.5 text-xs">
            {["cloud", "local"].map((m) => (
              <button key={m} onClick={() => setMode(m)} className={`flex-1 rounded-md px-3 py-1.5 font-medium capitalize ${mode === m ? "bg-ink-700 text-white" : "text-slate-400"}`}>
                {m}
              </button>
            ))}
          </div>
        </div>
      )}

      {name === "custom" && (
        <div>
          <label className="label">Base URL</label>
          <input className="input font-mono text-xs" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://10.0.0.5:1234/v1" />
        </div>
      )}

      <div>
        <label className="label flex items-center justify-between">
          <span>Model</span>
          <button onClick={loadModels} className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300">
            <RefreshCw className={`h-3 w-3 ${loadingModels ? "animate-spin" : ""}`} /> refresh
          </button>
        </label>
        <input className="input mb-2" value={model} onChange={(e) => setModel(e.target.value)} placeholder={p.default_model || "model id"} list={`models-${name}`} />
        <datalist id={`models-${name}`}>
          {models.map((m) => <option key={m} value={m} />)}
        </datalist>
        {models.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {models.slice(0, 8).map((m) => (
              <button key={m} onClick={() => setModel(m)} className={`rounded-md px-2 py-0.5 text-[11px] ring-1 ring-inset ${model === m ? "bg-brand-600/20 text-brand-300 ring-brand-500/30" : "bg-ink-800/60 text-slate-400 ring-ink-800 hover:text-slate-200"}`}>
                {m}
              </button>
            ))}
          </div>
        )}
      </div>

      <div>
        <label className="label flex items-center gap-1">
          <KeyRound className="h-3 w-3" /> API key {p.has_api_key && <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] text-emerald-300">stored</span>}
        </label>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              className="input pr-9"
              type={showKey ? "text" : "password"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={p.has_api_key ? "•••••••• (set — enter to replace)" : name === "custom" ? "optional" : "Paste API key"}
            />
            <button className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300" onClick={() => setShowKey((s) => !s)}>
              {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          <button className="btn-primary shrink-0" disabled={savingKey || !apiKey} onClick={() => saveKey(false)}>
            {savingKey ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />} Save
          </button>
          {p.has_api_key && (
            <button className="btn-danger shrink-0" disabled={savingKey} onClick={() => saveKey(true)} title="Remove stored key">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        <p className="mt-1 text-[11px] text-slate-500">Stored in your OS keychain — never written to disk in plaintext.</p>
      </div>

      <div className="flex items-center gap-2 border-t border-ink-800 pt-4">
        <button className="btn-primary" disabled={savingCfg} onClick={saveConfig}>
          {savingCfg ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save config
        </button>
        <button className="btn-ghost" disabled={testing} onClick={runTest}>
          {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plug className="h-4 w-4" />} Test connection
        </button>
        {test && (
          <span className={`text-xs ${test.ok ? "text-emerald-400" : "text-rose-400"}`}>
            {test.ok ? <Check className="mr-1 inline h-3.5 w-3.5" /> : <X className="mr-1 inline h-3.5 w-3.5" />}
            {test.msg}
          </span>
        )}
      </div>
    </div>
  );
}