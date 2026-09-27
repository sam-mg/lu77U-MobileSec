import { UploadCloud, Terminal, ArrowUpRight } from "lucide-react";

declare const __APP_HOMEPAGE__: string;

/**
 * Static-demo replacement for `src/components/UploadCard.tsx`, swapped in by
 * the `resolve.alias` entry in `vite.config.demo.js`.
 *
 * The real card offers a file picker and a local-path field. Neither can work
 * on GitHub Pages: there is no server to receive an upload and no machine to
 * read a path from. Rather than let someone choose an APK and only then be
 * told it went nowhere, this says so before there is anything to click.
 */
export default function UploadCard(_: { ready: boolean }) {
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-2 border-b border-ink-800 px-5 py-3">
        <UploadCloud className="h-4 w-4 text-brand-400" />
        <h2 className="text-sm font-semibold text-slate-200">New scan</h2>
        <span className="ml-auto rounded-md bg-ink-800/60 px-2 py-1 text-[11px] font-medium text-slate-400">
          Unavailable in this demo
        </span>
      </div>

      <div className="p-5">
        <div className="rounded-xl border border-dashed border-ink-700 px-6 py-8 text-center">
          <Terminal className="mx-auto h-7 w-7 text-slate-500" />
          <p className="mt-3 text-sm font-medium text-slate-200">
            Scanning runs on your machine, not in this page
          </p>
          <p className="mx-auto mt-2 max-w-md text-xs leading-relaxed text-slate-500">
            This is a static demonstration hosted on GitHub Pages. It has no
            server, so no APK can be uploaded or analyzed here. Everything below
            is a real, pre-generated scan result you can click through.
          </p>

          <code className="mt-4 inline-block rounded-lg bg-ink-800/80 px-3 py-2 text-xs text-brand-300 ring-1 ring-inset ring-ink-700">
            pip install lu77U-MobileSec
          </code>

          <div className="mt-4">
            <a
              href={`${__APP_HOMEPAGE__}#installation`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-400 underline underline-offset-2 hover:text-brand-300"
            >
              Install and run it locally to analyze your own app
              <ArrowUpRight className="h-3.5 w-3.5 shrink-0" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
