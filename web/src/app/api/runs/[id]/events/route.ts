import { NextResponse, type NextRequest } from "next/server";

import { getSession } from "@/lib/auth/session";
import { getRun, listCheckRows } from "@/lib/runs/run-service";
import { getRunBus } from "@/lib/runs/run-executor";
import { db } from "@/db";

/**
 * GET /api/runs/[id]/events — SSE live progress stream (D-05/D-06/D-07).
 * Outcomes:
 *   200 text/event-stream — ownership-scoped replay-then-live stream
 *   401 { error: "unauthenticated" }
 *   404 { error: "not_found" } — unknown or cross-user run id (T-03-04b)
 *
 * Stream behavior:
 * - Replay-then-live (D-07): snapshot frame from persisted state before live bus subscription
 * - Live forwarding of every EngineEvent as SSE named after event.type
 * - Heartbeat `: ping` every 15s, cleared on cancel
 * - Terminal handling: run-finished → run-terminal then close
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> | { id: string } },
) {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const resolvedParams = await Promise.resolve(context.params as Promise<{ id: string }> | { id: string });
  const id = (resolvedParams as { id: string }).id;

  const run = getRun(user.id, id, db);
  if (!run) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      const enqueue = (eventName: string, data: unknown) => {
        try {
          const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
          controller.enqueue(encoder.encode(payload));
        } catch {
          // enqueue failure → stream will be closed by outer catch
        }
      };

      const sendPing = () => {
        try {
          controller.enqueue(encoder.encode(`: ping\n\n`));
        } catch {}
      };

      // Replay-then-live: snapshot before subscription (D-07) — test asserts ordering
      const rows = listCheckRows(id, db);
      enqueue("snapshot", {
        run: {
          id: run.id,
          status: run.status,
          tenantId: run.tenantId,
          startedAt: run.startedAt,
          finishedAt: run.finishedAt,
          error: run.error,
        },
        rows,
      });

      // Terminal stream: completed/failed snapshot → run-terminal then close
      if (run.status === "completed" || run.status === "failed") {
        enqueue("run-terminal", { status: run.status });
        try {
          controller.close();
        } catch {}
        return;
      }

      // Heartbeat every 15s
      const heartbeat = setInterval(sendPing, 15000);

      const unsubscribe = getRunBus().subscribe(id, (event) => {
        enqueue(event.type, event);
        if (event.type === "run-finished") {
          enqueue("run-terminal", { status: "completed" });
          clearInterval(heartbeat);
          // Grace tick before closing
          setTimeout(() => {
            try {
              controller.close();
            } catch {}
          }, 10);
        }
      });

      const cleanup = () => {
        clearInterval(heartbeat);
        try {
          unsubscribe();
        } catch {}
        try {
          controller.close();
        } catch {}
      };

      // Abort signal — client disconnect
      request.signal.addEventListener("abort", cleanup);

      // Store cleanup for cancel() path as well
      (controller as unknown as { _cleanup?: () => void })._cleanup = cleanup;
    },
    cancel() {
      // ReadableStream cancel is called when consumer cancels; ensure heartbeat cleared
      // The start's cleanup handles interval/unsubscribe; here we just ensure no leak
      try {
        // @ts-ignore — cleanup attached above if available
        (this as unknown as { _cleanup?: () => void })._cleanup?.();
      } catch {}
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
