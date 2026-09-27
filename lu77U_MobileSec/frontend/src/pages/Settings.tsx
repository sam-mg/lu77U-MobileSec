import { useEffect, useState } from "react";
import {
  Check, Copy, Gauge, KeyRound, Loader2, Plug, RefreshCw, Save, Wrench, FileText, X, Eye, EyeOff,
  Terminal,
} from "lucide-react";
import {
  api, type Settings as SettingsT, type StoredApiKey, type CliStatus, type ProviderVendor,
} from "../api";
import { Card, SectionTitle, Segmented, Spinner, Switch } from "../components/ui";

/** Which of a vendor's one or two backends is being viewed/edited. Ignored
 * for a single-backend vendor (Ollama, Custom, GitHub Copilot, Kimi). */
type Access = "api" | "cli";

/** The vendor that owns `providerKey` (its `api` or `cli` field equals it),
 * or undefined if `providerKey` is empty/unknown. */
function vendorFor(vendors: ProviderVendor[], providerKey: string): ProviderVendor | undefined {
  return vendors.find((v) => v.api === providerKey || v.cli === providerKey);
}

/** The actual backend provider key a vendor + access resolves to. A
 * single-backend vendor ignores `access` entirely. */
function resolveProvider(v: ProviderVendor, access: Access): string | undefined {
  if (v.api && v.cli) return access === "api" ? v.api : v.cli;
  return v.api ?? v.cli;
}

/** Which backend to show first when a vendor is selected: whichever one is
 * already active, else whichever is configured, else API key over CLI. */
function defaultAccess(v: ProviderVendor, s: SettingsT): Access {
  if (v.cli && s.active_provider === v.cli) return "cli";
  if (v.api && s.active_provider === v.api) return "api";
  if (v.api && s.providers[v.api]?.has_api_key) return "api";
  if (v.cli && s.providers[v.cli]?.cli_found) return "cli";
  return v.api ? "api" : "cli";
}

export default function Settings() {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [selectedVendorId, setSelectedVendorId] = useState<string>("");
  const [access, setAccess] = useState<Access>("api");

  async function reload() {
    const s = await api.getSettings();
    setSettings(s);
  }

  useEffect(() => {
    reload().catch(() => {});
  }, []);

  // Sticky selection, same as the old `cur || s.active_provider`: only the
  // FIRST load (or a load before any chip was ever clicked) picks a vendor -
  // a later reload (after Save, after "Make active") must not yank the
  // editor out from under whatever the user is looking at.
  useEffect(() => {
    if (!settings || selectedVendorId) return;
    const v = vendorFor(settings.vendors, settings.active_provider) ?? settings.vendors[0];
    if (v) {
      setSelectedVendorId(v.id);
      setAccess(defaultAccess(v, settings));
    }
  }, [settings, selectedVendorId]);

  if (!settings) return <div className="flex justify-center py-24"><Spinner className="h-7 w-7 text-slate-500" /></div>;

  const vendor = settings.vendors.find((v) => v.id === selectedVendorId);
  const resolved = vendor ? resolveProvider(vendor, access) : undefined;
  const provider = resolved ? settings.providers[resolved] : undefined;

  function selectVendor(v: ProviderVendor) {
    setSelectedVendorId(v.id);
    setAccess(defaultAccess(v, settings!));
  }

  // Approved behaviour: flipping Access always changes what's being edited,
  // and ALSO moves `active_provider` - but only when this vendor already
  // owns it. For any other vendor, flipping just changes what the editor
  // below shows; the existing "Make active" button commits it.
  async function changeAccess(next: Access) {
    setAccess(next);
    if (!vendor) return;
    const vendorOwnsActive = vendor.api === settings!.active_provider || vendor.cli === settings!.active_provider;
    const nextResolved = resolveProvider(vendor, next);
    if (vendorOwnsActive && nextResolved && nextResolved !== settings!.active_provider) {
      await api.updateSettings({ active_provider: nextResolved });
      await reload();
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="mt-1 text-sm text-slate-400">Configure the AI provider, decompiler, and reporting.</p>
      </div>

      <ReadinessBanner settings={settings} />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6">
          <GeneralCard settings={settings} onChange={reload} />
          <FrameworkToolsCard settings={settings} onChange={reload} />
        </div>
        <div className="lg:col-span-2">
          <Card>
            <SectionTitle>AI providers</SectionTitle>
            <div className="mb-4 flex flex-wrap gap-2">
              {settings.vendors.map((v) => {
                const activeKey = v.api === settings.active_provider ? v.api
                  : v.cli === settings.active_provider ? v.cli : undefined;
                const isActive = !!activeKey;
                const isConfigured = !!(
                  (v.api && settings.providers[v.api]?.has_api_key) ||
                  (v.cli && settings.providers[v.cli]?.cli_found)
                );
                return (
                  <button
                    key={v.id}
                    onClick={() => selectVendor(v)}
                    aria-current={selectedVendorId === v.id ? "true" : undefined}
                    className={`flex min-h-11 items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium ring-1 ring-inset transition-colors md:min-h-8 ${
                      selectedVendorId === v.id ? "bg-ink-700 text-white ring-ink-600" : "bg-ink-800/40 text-slate-400 ring-ink-800 hover:text-slate-200"
                    }`}
                  >
                    {v.label}
                    <VendorDot active={isActive} configured={isConfigured} />
                  </button>
                );
              })}
            </div>
            {vendor && vendor.api && vendor.cli && (
              <div className="mb-4">
                <label className="label">Access</label>
                <Segmented<Access>
                  value={access}
                  onChange={changeAccess}
                  options={[
                    { value: "api", label: "API key" },
                    { value: "cli", label: "CLI" },
                  ]}
                />
              </div>
            )}
            {provider && resolved && <ProviderEditor key={resolved} settings={settings} name={resolved} onChange={reload} />}
          </Card>
        </div>
      </div>
    </div>
  );
}

/**
 * Shape carries "active vs configured" so the state survives with colour
 * perception removed: a filled dot is active, a hollow ring is merely
 * configured. Colour is the second signal - emerald when the active one can
 * actually run, amber when it can't (no key/CLI found yet), matching the
 * amber this page already uses for "Setup required" elsewhere.
 */
function VendorDot({ active, configured }: { active: boolean; configured: boolean }) {
  if (active) {
    return (
      <span
        title={configured ? "Active · configured" : "Active · needs setup"}
        aria-label={configured ? "Active, configured" : "Active, needs setup"}
        className={`h-1.5 w-1.5 shrink-0 rounded-full ${configured ? "bg-emerald-400" : "bg-amber-400"}`}
      />
    );
  }
  if (configured) {
    return (
      <span
        title="Configured"
        aria-label="Configured"
        className="h-1.5 w-1.5 shrink-0 rounded-full ring-1 ring-inset ring-slate-400"
      />
    );
  }
  return null;
}

function ReadinessBanner({ settings }: { settings: SettingsT }) {
  const { jadx_configured, ollama_configured, ready_for_analysis } = settings.status;
  if (ready_for_analysis)
    return (
      <div className="flex items-center gap-2 rounded-xl bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300 ring-1 ring-inset ring-emerald-500/20">
        <Check className="h-4 w-4" /> Everything is configured - you’re ready to scan.
      </div>
    );
  return (
    <div className="rounded-xl bg-amber-500/10 px-4 py-3 text-sm text-amber-300 ring-1 ring-inset ring-amber-500/20">
      <p className="font-medium">Setup required before scanning:</p>
      <ul className="mt-1 list-inside list-disc text-amber-300/80">
        {!jadx_configured && <li>Set a valid JADX executable path.</li>}
        {!ollama_configured && <li>Configure an API key, a CLI sign-in, or local mode for the active provider.</li>}
      </ul>
    </div>
  );
}

function GeneralCard({ settings, onChange }: { settings: SettingsT; onChange: () => Promise<void> }) {
  const [jadx, setJadx] = useState(settings.jadx_path);
  const [pdf, setPdf] = useState(settings.pdf_generation);
  const [autoResume, setAutoResume] = useState(settings.auto_resume);
  const [steps, setSteps] = useState(String(settings.agent_budget?.max_steps_per_region ?? 40));
  const [minutes, setMinutes] = useState(String(settings.agent_budget?.max_minutes ?? 45));
  const [saving, setSaving] = useState(false);
  const [budgetError, setBudgetError] = useState<string | null>(null);

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
            <optgroup label="API key">
              {settings.provider_order
                .filter((n) => !settings.providers[n].is_cli)
                .map((n) => <option key={n} value={n}>{settings.providers[n].display_name}</option>)}
            </optgroup>
            <optgroup label="Subscription CLI">
              {settings.provider_order
                .filter((n) => settings.providers[n].is_cli)
                .map((n) => <option key={n} value={n}>{settings.providers[n].display_name}</option>)}
            </optgroup>
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

        <Switch
          checked={pdf}
          onChange={(next) => { setPdf(next); save({ pdf_generation: next }); }}
          icon={<FileText className="h-4 w-4" />}
          label="Generate PDF reports"
        />

        <Switch
          checked={autoResume}
          onChange={(next) => { setAutoResume(next); save({ auto_resume: next }); }}
          icon={<RefreshCw className="h-4 w-4" />}
          label="Auto-resume interrupted scans"
        />

        {/* The AI phase is the expensive part of a scan. Left unbounded it runs
            until the provider's own account limit stops it, which on a large app
            means a spent quota and an unfinished report. */}
        <div>
          <label className="label flex items-center gap-1"><Gauge className="h-3 w-3" /> AI analysis budget</label>
          <div className="flex gap-2">
            <div className="flex-1">
              <input
                className="input text-xs"
                type="number"
                min={0}
                max={500}
                value={steps}
                onChange={(e) => setSteps(e.target.value)}
              />
              <p className="mt-1 text-[11px] text-slate-500">Model calls per code region</p>
            </div>
            <div className="flex-1">
              <input
                className="input text-xs"
                type="number"
                min={0}
                max={480}
                value={minutes}
                onChange={(e) => setMinutes(e.target.value)}
              />
              <p className="mt-1 text-[11px] text-slate-500">Minutes, whole scan</p>
            </div>
            <button
              className="btn-ghost mt-0.5 h-9 shrink-0"
              disabled={saving}
              onClick={async () => {
                setBudgetError(null);
                try {
                  await save({
                    agent_budget: {
                      max_steps_per_region: Number(steps),
                      max_minutes: Number(minutes),
                    },
                  });
                } catch (err) {
                  setBudgetError(err instanceof Error ? err.message : "Could not save the budget.");
                }
              }}
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            </button>
          </div>
          <p className={`mt-1 text-[11px] ${budgetError ? "text-rose-400" : "text-slate-500"}`}>
            {budgetError ??
              "0 in either field means no limit. Without a budget a large app can spend a whole provider quota and still not finish."}
          </p>
        </div>
      </div>
    </Card>
  );
}

function FrameworkToolsCard({ settings, onChange }: { settings: SettingsT; onChange: () => Promise<void> }) {
  const [blutter, setBlutter] = useState(settings.blutter_path);
  const [hermes, setHermes] = useState(settings.hermes_decomp_path);
  const [rnDecompiler, setRnDecompiler] = useState(settings.rn_decompiler_path);
  const [saving, setSaving] = useState<string | null>(null);

  async function save(key: string, payload: Record<string, unknown>) {
    setSaving(key);
    try {
      await api.updateSettings(payload);
      await onChange();
    } finally {
      setSaving(null);
    }
  }

  return (
    <Card>
      <SectionTitle>Framework decompilers</SectionTitle>
      <p className="mb-4 text-xs text-slate-500">
        Optional. Unlike JADX, none of these block scanning - a Flutter or React
        Native app scanned without its tool configured still gets a detection-only
        report instead of failing.
      </p>
      <div className="space-y-5">
        <PathField
          label="Blutter path"
          hint="For Flutter apps. Path to blutter.py from a Blutter checkout."
          placeholder="/opt/blutter/blutter.py"
          value={blutter}
          onChangeValue={setBlutter}
          configured={settings.status.blutter_configured}
          saving={saving === "blutter"}
          onSave={() => save("blutter", { blutter_path: blutter })}
        />
        <PathField
          label="hermes-decomp path"
          hint="For React Native apps with a Hermes-compiled bundle."
          placeholder="/usr/local/bin/hermes-decomp"
          value={hermes}
          onChangeValue={setHermes}
          configured={settings.status.hermes_decomp_configured}
          saving={saving === "hermes"}
          onSave={() => save("hermes", { hermes_decomp_path: hermes })}
        />
        <PathField
          label="RN decompiler path"
          hint="For React Native apps with a plain-JavaScript bundle (not Hermes)."
          placeholder="/usr/local/bin/react-native-decompiler"
          value={rnDecompiler}
          onChangeValue={setRnDecompiler}
          configured={settings.status.rn_decompiler_configured}
          saving={saving === "rn"}
          onSave={() => save("rn", { rn_decompiler_path: rnDecompiler })}
        />
      </div>
    </Card>
  );
}

function PathField({
  label, hint, placeholder, value, onChangeValue, configured, saving, onSave,
}: {
  label: string; hint: string; placeholder: string; value: string;
  onChangeValue: (v: string) => void; configured: boolean; saving: boolean;
  onSave: () => void;
}) {
  return (
    <div>
      <label className="label flex items-center gap-1"><Wrench className="h-3 w-3" /> {label}</label>
      <div className="flex gap-2">
        <input
          className="input font-mono text-xs"
          value={value}
          onChange={(e) => onChangeValue(e.target.value)}
          placeholder={placeholder}
        />
        <button className="btn-ghost shrink-0" disabled={saving} onClick={onSave}>
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
        </button>
      </div>
      <p className={`mt-1 text-[11px] ${configured ? "text-emerald-400" : "text-slate-500"}`}>
        {configured ? "Detected at this path." : hint}
      </p>
    </div>
  );
}

function StoredKeyRow({
  provider, keyInfo, isActive, onChange,
}: { provider: string; keyInfo: StoredApiKey; isActive: boolean; onChange: () => Promise<void> }) {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [copied, setCopied] = useState(false);

  async function toggleReveal() {
    if (revealed) {
      setRevealed(null);
      return;
    }
    setRevealing(true);
    try {
      const r = await api.revealCredential(provider, keyInfo.index);
      setRevealed(r.key);
    } finally {
      setRevealing(false);
    }
  }

  async function copy() {
    const text = revealed ?? (await api.revealCredential(provider, keyInfo.index)).key;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  async function remove() {
    setRemoving(true);
    try {
      await api.removeCredential(provider, keyInfo.index);
      await onChange();
    } finally {
      setRemoving(false);
    }
  }

  return (
    <div className="flex items-center gap-2 rounded-lg bg-ink-900/50 px-2.5 py-1.5">
      <span className={`truncate font-mono text-xs ${isActive ? "text-emerald-300" : "text-slate-300"}`}>
        {revealed ?? keyInfo.masked}
      </span>
      {isActive && (
        <span className="shrink-0 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[9px] text-emerald-300">
          active
        </span>
      )}
      <div className="ml-auto flex shrink-0 items-center gap-1">
        <button
          className="text-slate-500 hover:text-slate-300 disabled:opacity-50"
          disabled={revealing}
          onClick={toggleReveal}
          title={revealed ? "Hide" : "Reveal"}
        >
          {revealing ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : revealed ? (
            <EyeOff className="h-3.5 w-3.5" />
          ) : (
            <Eye className="h-3.5 w-3.5" />
          )}
        </button>
        <button className="text-slate-500 hover:text-slate-300" onClick={copy} title="Copy">
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
        <button
          className="text-slate-500 hover:text-rose-400 disabled:opacity-50"
          disabled={removing}
          onClick={remove}
          title="Remove this key"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

function ProviderEditor({ settings, name, onChange }: { settings: SettingsT; name: string; onChange: () => Promise<void> }) {
  const p = settings.providers[name];
  const [model, setModel] = useState(p.model);
  const [mode, setMode] = useState<"cloud" | "local">(p.mode === "local" ? "local" : "cloud");
  const [baseUrl, setBaseUrl] = useState(p.base_url || "");
  const [binaryPath, setBinaryPath] = useState(p.binary_path || "");
  const [maxConcurrent, setMaxConcurrent] = useState(String(p.max_concurrent_requests));
  const [models, setModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [savingCfg, setSavingCfg] = useState(false);
  const [savingKey, setSavingKey] = useState(false);
  const [test, setTest] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [cliStatus, setCliStatus] = useState<CliStatus | null>(null);
  const [loadingCliStatus, setLoadingCliStatus] = useState(false);

  async function loadModels() {
    setLoadingModels(true);
    try {
      const r = await api.listModels(name);
      setModels(r.models);
    } finally {
      setLoadingModels(false);
    }
  }

  async function loadCliStatus() {
    if (!p.is_cli) return;
    setLoadingCliStatus(true);
    try {
      setCliStatus(await api.getCliStatus(name));
    } catch {
      setCliStatus(null);
    } finally {
      setLoadingCliStatus(false);
    }
  }

  useEffect(() => {
    loadModels();
    loadCliStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  async function saveConfig() {
    setSavingCfg(true);
    try {
      const fields: Record<string, unknown> = { model };
      if (name === "ollama") fields.mode = mode;
      if (name === "custom") fields.base_url = baseUrl;
      if (p.is_cli) {
        fields.binary_path = binaryPath;
      } else {
        const concurrent = Number(maxConcurrent);
        if (Number.isFinite(concurrent)) fields.max_concurrent_requests = concurrent;
      }
      await api.updateSettings({ providers: { [name]: fields } });
      await onChange();
      await loadCliStatus();
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
          <Segmented<"cloud" | "local">
            value={mode}
            onChange={setMode}
            options={[
              { value: "cloud", label: "cloud" },
              { value: "local", label: "local" },
            ]}
          />
        </div>
      )}

      {name === "custom" && (
        <div>
          <label className="label">Base URL</label>
          {settings.custom_presets.length > 0 && (
            <div className="mb-2 flex flex-wrap gap-1.5">
              {settings.custom_presets.map((preset) => (
                <button
                  key={preset.label}
                  className="rounded-md bg-ink-800/60 px-2 py-1 text-[11px] text-slate-400 ring-1 ring-inset ring-ink-800 hover:text-slate-200"
                  title={`${preset.base_url} · no subscription required, just a free API key`}
                  onClick={() => {
                    setBaseUrl(preset.base_url);
                    setModel(preset.model);
                  }}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          )}
          <input className="input font-mono text-xs" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://10.0.0.5:1234/v1" />
        </div>
      )}

      {p.is_cli && (
        <CliStatusBlock
          provider={name}
          binaryPath={binaryPath}
          onBinaryPathChange={setBinaryPath}
          status={cliStatus}
          loading={loadingCliStatus}
          onRefresh={loadCliStatus}
          signinHint={p.signin_hint || ""}
          cliBinary={p.cli_binary || name}
        />
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

      {!p.is_cli && (
        <div>
          <label className="label flex items-center gap-1">
            <Gauge className="h-3 w-3" /> Max concurrent requests
          </label>
          <input
            className="input w-24"
            type="number"
            min={settings.max_concurrent_requests_range?.[0] ?? 1}
            max={settings.max_concurrent_requests_range?.[1] ?? 20}
            value={maxConcurrent}
            onChange={(e) => setMaxConcurrent(e.target.value)}
          />
          <p className="mt-1 text-[11px] text-slate-500">
            A scan runs one agent thread per code region against this provider. A call that
            runs unusually long used to let every other thread queue up behind it with no
            limit - this caps how many can be in flight at once instead.
          </p>
        </div>
      )}

      {p.needs_api_key && (
        <div>
          <label className="label flex items-center justify-between">
            <span className="flex items-center gap-1">
              <KeyRound className="h-3 w-3" /> API key{p.api_key_count > 1 ? "s" : ""}
            </span>
            {p.api_key_count > 0 && (
              <span className="text-[11px] text-slate-500">
                {p.api_key_count} stored
              </span>
            )}
          </label>

          {p.api_keys.length > 0 && (
            <div className="mb-2 space-y-1.5">
              {p.api_keys.map((k) => (
                <StoredKeyRow
                  key={k.index}
                  provider={name}
                  keyInfo={k}
                  isActive={k.index === 0}
                  onChange={onChange}
                />
              ))}
            </div>
          )}

          <div className="flex gap-2">
            <div className="relative flex-1">
              <input
                className="input pr-9"
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={name === "custom" ? "optional" : "Paste API key"}
              />
              <button className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300" onClick={() => setShowKey((s) => !s)}>
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <button className="btn-primary shrink-0" disabled={savingKey || !apiKey} onClick={() => saveKey(false)}>
              {savingKey ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
              {p.api_key_count > 0 ? "Add another" : "Save"}
            </button>
            {p.has_api_key && (
              <button className="btn-danger shrink-0" disabled={savingKey} onClick={() => saveKey(true)} title="Remove every stored key">
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
          <p className="mt-1 text-[11px] text-slate-500">
            {p.api_key_count > 1
              ? "Tried in the order listed above - a scan rolls to the next key when one runs out of quota."
              : "Stored in your OS keychain - never written to disk in plaintext."}
          </p>
        </div>
      )}

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

/**
 * Config block for a subscription-CLI-backed provider (Claude Code, Copilot,
 * Kimi, Codex, Antigravity - see ai/cli_provider.py). No API key: the
 * one-time sign-in is interactive and runs outside this tool, so this only
 * ever shows detection status and reports how to sign in.
 */
function CliStatusBlock({
  provider, binaryPath, onBinaryPathChange, status, loading, onRefresh, signinHint, cliBinary,
}: {
  provider: string;
  binaryPath: string;
  onBinaryPathChange: (v: string) => void;
  status: CliStatus | null;
  loading: boolean;
  onRefresh: () => Promise<void>;
  signinHint: string;
  cliBinary: string;
}) {
  const found = status?.cli_found ?? false;
  const signedIn = status?.signed_in ?? false;

  return (
    <div className="space-y-3">
      <div>
        <label className="label flex items-center justify-between">
          <span className="flex items-center gap-1">
            <Terminal className="h-3 w-3" /> {cliBinary} CLI status
          </span>
          <button
            onClick={() => onRefresh()}
            className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} /> refresh
          </button>
        </label>

        <div className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs ring-1 ring-inset ${
          signedIn
            ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
            : found
              ? "bg-amber-500/10 text-amber-300 ring-amber-500/30"
              : "bg-rose-500/10 text-rose-300 ring-rose-500/30"
        }`}>
          {loading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : signedIn ? (
            <Check className="h-3.5 w-3.5" />
          ) : (
            <X className="h-3.5 w-3.5" />
          )}
          <span>
            {loading
              ? "Checking…"
              : signedIn
                ? `Signed in${status?.cli_resolved_path ? ` · ${status.cli_resolved_path}` : ""}`
                : status?.detail || `${cliBinary} not found on PATH`}
          </span>
        </div>
      </div>

      <div>
        <label className="label">Binary path (optional)</label>
        <input
          className="input font-mono text-xs"
          value={binaryPath}
          onChange={(e) => onBinaryPathChange(e.target.value)}
          placeholder={`leave blank to resolve "${cliBinary}" from PATH`}
        />
      </div>

      {!signedIn && (
        <p className="rounded-lg bg-ink-800/60 px-3 py-2 text-[11px] text-slate-400">
          {signinHint || `Install and sign in to the ${cliBinary} CLI, then save this page.`}{" "}
          This is a one-time interactive step run outside this tool - it cannot sign you in.
        </p>
      )}
      <p className="text-[11px] text-slate-500">
        Billed against your {provider.replace("_cli", "")} subscription's own usage limits, not
        a metered API key. A large scan can exhaust a rolling-window quota - the scan pauses and
        resumes automatically once the window resets.
      </p>
    </div>
  );
}