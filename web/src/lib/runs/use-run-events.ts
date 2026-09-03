"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

export type ConnectionState = "live" | "reconnecting" | "terminal";

export interface SectionState {
  sectionId: string;
  status: "queued" | "running" | "completed" | "failed";
  checks: Array<{ checkId: string; setting: string; status: string; skipReason?: string }>;
  error?: string;
}

export interface UseRunEventsResult {
  connectionState: ConnectionState;
  sections: Record<string, SectionState>;
  elapsedMs: number;
}

const MAX_BACKOFF_MS = 10000;
const INITIAL_BACKOFF_MS = 1000;

export function useRunEvents(runId: string, startedAtIso: string, enabled: boolean): UseRunEventsResult {
  const router = useRouter();
  const [connectionState, setConnectionState] = useState<ConnectionState>(enabled ? "live" : "terminal");
  const [sections, setSections] = useState<Record<string, SectionState>>({});
  const [elapsedMs, setElapsedMs] = useState(0);
  const toastFiredRef = useRef(false);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);
  const esRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Elapsed timer ticking every second while live
  useEffect(() => {
    if (!enabled || connectionState === "terminal") return;
    const start = new Date(startedAtIso).getTime();
    const tick = () => setElapsedMs(Date.now() - start);
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAtIso, enabled, connectionState]);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    let currentEs: EventSource | null = null;

    function handleSnapshot(data: unknown) {
      try {
        const parsed = data as { rows?: Array<{ checkId: string; setting: string; status: string; sectionId: string; skipReason?: string }> };
        const rows = parsed.rows ?? [];
        const map: Record<string, SectionState> = {};
        for (const r of rows) {
          const sec = map[r.sectionId] ?? { sectionId: r.sectionId, status: "completed" as const, checks: [] as SectionState["checks"] };
          sec.checks.push({ checkId: r.checkId, setting: r.setting, status: r.status, skipReason: r.skipReason });
          map[r.sectionId] = sec;
        }
        setSections(map);
      } catch {}
    }

    function connect() {
      if (cancelled) return;
      const es = new EventSource(`/api/runs/${runId}/events`);
      currentEs = es;
      esRef.current = es;

      es.onopen = () => {
        setConnectionState("live");
        backoffRef.current = INITIAL_BACKOFF_MS;
      };

      es.addEventListener("snapshot", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data);
          handleSnapshot(data);
        } catch {}
      });

      es.addEventListener("section-started", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data) as { sectionId: string };
          setSections((prev) => {
            const next = { ...prev };
            const id = data.sectionId;
            next[id] = { sectionId: id, status: "running", checks: next[id]?.checks ?? [] };
            return next;
          });
        } catch {}
      });

      es.addEventListener("check-completed", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data) as { sectionId: string; row: { checkId: string; setting: string; status: string; skipReason?: string } };
          setSections((prev) => {
            const next = { ...prev };
            const id = data.sectionId;
            const sec = next[id] ?? { sectionId: id, status: "running" as const, checks: [] as SectionState["checks"] };
            sec.checks = [...sec.checks, { checkId: data.row.checkId, setting: data.row.setting, status: data.row.status, skipReason: data.row.skipReason }];
            next[id] = sec;
            return next;
          });
        } catch {}
      });

      es.addEventListener("section-error", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data) as { sectionId: string; error: string };
          setSections((prev) => {
            const next = { ...prev };
            const id = data.sectionId;
            const sec = next[id] ?? { sectionId: id, status: "failed" as const, checks: [] as SectionState["checks"] };
            sec.status = "failed";
            sec.error = data.error;
            next[id] = sec;
            return next;
          });
        } catch {}
      });

      es.addEventListener("section-finished", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data) as { sectionId: string };
          setSections((prev) => {
            const next = { ...prev };
            const id = data.sectionId;
            if (next[id]) next[id] = { ...next[id], status: "completed" };
            return next;
          });
        } catch {}
      });

      es.addEventListener("run-terminal", () => {
        setConnectionState("terminal");
        if (!toastFiredRef.current) {
          toastFiredRef.current = true;
          toast.success("Assessment complete — your report is ready.");
        }
        try {
          es.close();
        } catch {}
        // trigger server re-render to swap into completed mode (D-08)
        router.refresh();
      });

      es.onerror = () => {
        // Check terminal via ref to avoid stale closure
        if (cancelled) return;
        // non-terminal error → reconnecting state
        setConnectionState("reconnecting");
        try {
          es.close();
        } catch {}
        const delay = Math.min(backoffRef.current, MAX_BACKOFF_MS);
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = setTimeout(() => {
          if (!cancelled) connect();
        }, delay);
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      try {
        currentEs?.close();
      } catch {}
      if (esRef.current) {
        try {
          esRef.current.close();
        } catch {}
      }
    };
  }, [runId, enabled, router]);

  return { connectionState, sections, elapsedMs };
}
