import type { EngineEvent } from "@/engine/events/engine-events";

/**
 * In-memory per-run pub/sub for SSE fan-out (D-05).
 * One bus instance is shared between the executor (emit) and the SSE route (subscribe).
 * No dependencies — trivially unit-testable.
 */
export interface EventBus {
  subscribe(runId: string, fn: (event: EngineEvent) => void): () => void;
  emit(runId: string, event: EngineEvent): void;
  close(runId: string): void;
  subscriberCount(runId: string): number;
}

export function createEventBus(): EventBus {
  const subscribers = new Map<string, Set<(event: EngineEvent) => void>>();

  return {
    subscribe(runId: string, fn: (event: EngineEvent) => void): () => void {
      let set = subscribers.get(runId);
      if (!set) {
        set = new Set();
        subscribers.set(runId, set);
      }
      set.add(fn);
      return () => {
        const s = subscribers.get(runId);
        if (s) {
          s.delete(fn);
          if (s.size === 0) {
            subscribers.delete(runId);
          }
        }
      };
    },

    emit(runId: string, event: EngineEvent): void {
      const set = subscribers.get(runId);
      if (!set || set.size === 0) return;
      for (const fn of set) {
        try {
          fn(event);
        } catch {
          // Isolate per-subscriber failures — continue delivering to others
        }
      }
    },

    close(runId: string): void {
      subscribers.delete(runId);
    },

    subscriberCount(runId: string): number {
      return subscribers.get(runId)?.size ?? 0;
    },
  };
}
