import { useEffect, useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { DEMO_BLOCKED_EVENT, DEMO_MESSAGE } from "./mock-backend";

declare const __APP_HOMEPAGE__: string;

/**
 * The only visual addition to the real app: a slim banner pinned to the top of the viewport, plus a transient toast for blocked actions. The banner reports its own rendered height (it wraps to two lines on narrow viewports) through the `--app-banner-h` CSS variable, which Layout.tsx's fixed sidebar and sticky header read to offset themselves - without it, `fixed` positioning is anchored to the true viewport top regardless of this banner's place in the document flow, so the banner would render behind the sidebar instead of above it. The variable is scoped to this build only: Layout.tsx defaults it to `0px`, so the real app is unaffected. Both banner and toast reuse the amber alert treatment already used in UploadCard.tsx and Settings.tsx, so nothing new is introduced to the app's visual language.
 */
export default function DemoNotice() {
  return (
    <>
      <Banner />
      <Toast />
    </>
  );
}

function Banner() {
  const ref = useRef<HTMLDivElement>(null);

  // Measured, not assumed: the text wraps to a second line under ~640px, so a fixed pixel guess would either clip the banner on narrow screens or leave a gap under it on wide ones. ResizeObserver re-syncs on every width/wrap change, not just once at mount.
  //
  // The banner is `fixed`, not `sticky`, because index.css pins `#root` to `height: 100%`: a sticky child is released once its containing block scrolls past, so the banner would detach after roughly one viewport. Being out of flow, it no longer reserves its own space, so the same measured height is applied as padding on `#root` - the page starts below the banner and scrolls under it. Both properties are removed on unmount, and neither exists in the real app's build.
  useEffect(() => {
    const el = ref.current;
    if (!el) return () => {};
    const root = document.documentElement;
    const mount = document.getElementById("root");
    const sync = () => {
      const height = `${el.offsetHeight}px`;
      root.style.setProperty("--app-banner-h", height);
      mount?.style.setProperty("padding-top", height);
    };
    sync();
    const observer = new ResizeObserver(sync);
    observer.observe(el);
    return () => {
      observer.disconnect();
      root.style.removeProperty("--app-banner-h");
      mount?.style.removeProperty("padding-top");
    };
  }, []);

  return (
    <div
      ref={ref}
      className="fixed inset-x-0 top-0 z-40 flex flex-wrap items-center justify-center gap-x-2 gap-y-1 bg-amber-500/10 px-4 py-2 pt-[max(0.5rem,env(safe-area-inset-top))] text-center text-xs text-amber-300 ring-1 ring-inset ring-amber-500/20 backdrop-blur-xl"
    >
      <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
      <span>
         Static demo - this is showing pre-generated sample results, not a live scanner. 
      </span>
      <a
        href={`${__APP_HOMEPAGE__}#installation`}
        target="_blank"
        rel="noreferrer"
        className="font-medium underline underline-offset-2 hover:text-amber-200"
      >
        Install lu77U-MobileSec locally to analyze your own app
      </a>
      <span aria-hidden="true" className="hidden text-amber-500/50 sm:inline">·</span>
      <a
        href={`${__APP_HOMEPAGE__}/wiki/Benchmarks`}
        target="_blank"
        rel="noreferrer"
        className="font-medium underline underline-offset-2 hover:text-amber-200"
      >
        Ghera benchmark results
      </a>
    </div>
  );
}

function Toast() {
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const onBlocked = (e: Event) => {
      const detail = (e as CustomEvent<string>).detail || DEMO_MESSAGE;
      setMessage(detail);
      clearTimeout(timer);
      timer = setTimeout(() => setMessage(null), 4500);
    };
    window.addEventListener(DEMO_BLOCKED_EVENT, onBlocked);
    return () => {
      window.removeEventListener(DEMO_BLOCKED_EVENT, onBlocked);
      clearTimeout(timer);
    };
  }, []);

  if (!message) return null;

  return (
    <div
      role="status"
      className="fixed inset-x-4 bottom-4 z-50 mx-auto flex max-w-md items-start gap-2.5 rounded-xl bg-amber-500/10 px-4 py-3 text-sm text-amber-200 ring-1 ring-inset ring-amber-500/30 backdrop-blur-xl animate-fade-in sm:right-4 sm:left-auto"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
      <span className="leading-relaxed">{message}</span>
    </div>
  );
}
