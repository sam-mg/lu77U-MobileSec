import { useEffect, useRef, useState } from "react";
import { scanWsUrl, type ScanMeta, type ScanStatus } from "../api";

export interface LogLine {
  message: string;
  ts: string;
}

export interface StreamState {
  status?: ScanStatus;
  progress: { percent: number; phase: string; message: string };
  logs: LogLine[];
  error?: string | null;
}

export function useScanStream(
  id: string,
  enabled: boolean,
  onTerminal: (status: ScanStatus) => void,
): StreamState {
  const [state, setState] = useState<StreamState>({
    progress: { percent: 0, phase: "", message: "" },
    logs: [],
  });
  const firedRef = useRef(false);

  useEffect(() => {
    if (!enabled) return;
    firedRef.current = false;
    let closed = false;
    const ws = new WebSocket(scanWsUrl(id));

    ws.onmessage = (e) => {
      let ev: any;
      try {
        ev = JSON.parse(e.data);
      } catch {
        return;
      }
      setState((prev) => {
        const next = { ...prev };
        if (ev.type === "meta" && ev.meta) {
          const m: ScanMeta = ev.meta;
          next.status = m.status;
          next.progress = { percent: m.progress ?? 0, phase: m.phase ?? "", message: "" };
          next.error = m.error;
        } else if (ev.type === "progress") {
          next.progress = { percent: ev.percent ?? prev.progress.percent, phase: ev.phase ?? "", message: ev.message ?? "" };
        } else if (ev.type === "log") {
          next.logs = [...prev.logs, { message: ev.message, ts: ev.ts }].slice(-1500);
        } else if (ev.type === "status") {
          next.status = ev.status;
          if (ev.error) next.error = ev.error;
        }
        return next;
      });

      if (ev.type === "status" && (ev.status === "completed" || ev.status === "failed")) {
        if (!firedRef.current) {
          firedRef.current = true;
          // Let final progress/log events flush first.
          setTimeout(() => onTerminal(ev.status), 250);
        }
      }
    };

    ws.onerror = () => {};
    return () => {
      closed = true;
      try {
        ws.close();
      } catch {
        /* noop */
      }
      void closed;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, enabled]);

  return state;
}