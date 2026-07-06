import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { UploadCloud, FileUp, FolderInput, Loader2, AlertTriangle } from "lucide-react";
import { api, ApiError } from "../api";

export default function UploadCard({ ready }: { ready: boolean }) {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"upload" | "path">("upload");
  const [path, setPath] = useState("");

  async function start(promise: Promise<{ id: string }>) {
    setBusy(true);
    setError(null);
    try {
      const { id } = await promise;
      navigate(`/scans/${id}`);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to start scan";
      setError(msg);
      setBusy(false);
    }
  }

  function onFiles(files: FileList | null) {
    const file = files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      setError("Please choose an .apk file");
      return;
    }
    start(api.createScanUpload(file));
  }

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-2 border-b border-ink-800 px-5 py-3">
        <UploadCloud className="h-4 w-4 text-brand-400" />
        <h2 className="text-sm font-semibold text-slate-200">New scan</h2>
        <div className="ml-auto flex rounded-lg bg-ink-800/60 p-0.5 text-xs">
          <button
            className={`rounded-md px-2.5 py-1 font-medium ${mode === "upload" ? "bg-ink-700 text-white" : "text-slate-400"}`}
            onClick={() => setMode("upload")}
          >
            Upload
          </button>
          <button
            className={`rounded-md px-2.5 py-1 font-medium ${mode === "path" ? "bg-ink-700 text-white" : "text-slate-400"}`}
            onClick={() => setMode("path")}
          >
            Local path
          </button>
        </div>
      </div>

      <div className="p-5">
        {!ready && (
          <div className="mb-4 flex items-start gap-2 rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-300 ring-1 ring-inset ring-amber-500/20">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              JADX and an AI provider must be configured before scanning. Open{" "}
              <a href="/settings" className="underline">Settings</a> to finish setup.
            </span>
          </div>
        )}

        {mode === "upload" ? (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              onFiles(e.dataTransfer.files);
            }}
            onClick={() => !busy && inputRef.current?.click()}
            className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors ${
              dragOver ? "border-brand-500 bg-brand-500/5" : "border-ink-700 hover:border-ink-600 hover:bg-ink-800/30"
            } ${busy ? "pointer-events-none opacity-60" : ""}`}
          >
            <input ref={inputRef} type="file" accept=".apk" className="hidden" onChange={(e) => onFiles(e.target.files)} />
            {busy ? (
              <Loader2 className="h-7 w-7 animate-spin text-brand-400" />
            ) : (
              <FileUp className="h-7 w-7 text-slate-500" />
            )}
            <div>
              <p className="text-sm font-medium text-slate-200">
                {busy ? "Starting scan…" : "Drop an APK here, or click to browse"}
              </p>
              <p className="mt-1 text-xs text-slate-500">Android .apk files · analyzed locally on your machine</p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex gap-2">
              <input
                className="input"
                placeholder="/absolute/path/to/app.apk"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                disabled={busy}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && path.trim()) start(api.createScanPath(path.trim()));
                }}
              />
              <button
                className="btn-primary shrink-0"
                disabled={busy || !path.trim()}
                onClick={() => start(api.createScanPath(path.trim()))}
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FolderInput className="h-4 w-4" />}
                Scan
              </button>
            </div>
            <p className="text-xs text-slate-500">Point to an APK already on this machine — nothing is uploaded over the network.</p>
          </div>
        )}

        {error && <p className="mt-3 text-xs text-rose-400">{error}</p>}
      </div>
    </div>
  );
}