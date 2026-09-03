import { describe, expect, it } from "vitest";
import { runEngine } from "./engine";
import type { SectionImplementation } from "./engine";
import type { EngineEvent, EngineEventSink } from "../events/engine-events";
import type { CheckRow, CheckRowInput } from "../results/row-contract";
import type { LicensingOverlay } from "../results/licensing-overlay";
import type { ControlRegistry } from "../registry/load-controls";
import { GraphTransport } from "../transport/graph-transport";
import type { GraphCallEvent } from "../transport/graph-transport";

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

function makeSink(): { events: EngineEvent[]; sink: EngineEventSink } {
  const events: EngineEvent[] = [];
  return { events, sink: { emit: (event) => events.push(event) } };
}

function input(checkId: string, psStatus: CheckRowInput["psStatus"] = "Pass"): CheckRowInput {
  return { category: "Test", setting: `Setting ${checkId}`, psStatus, checkId };
}

const FAKE_REGISTRY = {
  schemaVersion: "test",
  checks: [
    {
      checkId: "REMEDIATED-001",
      remediation: { notes: "Do the thing from the registry" },
    },
  ],
} as unknown as ControlRegistry;

const FAKE_OVERLAY: LicensingOverlay = {
  checks: { "LIC-GATED-001": ["AAD_PREMIUM_P2"] },
};

const fakeControls = { registry: FAKE_REGISTRY, overlay: FAKE_OVERLAY };

/** A transport stub — sections in these tests never call Graph directly. */
const stubTransport = {} as GraphTransport;

async function run(
  implementations: Record<string, SectionImplementation>,
  opts?: Partial<Parameters<typeof runEngine>[0]>,
): Promise<{ events: EngineEvent[]; result: Awaited<ReturnType<typeof runEngine>> }> {
  const { events, sink } = makeSink();
  const { transport, createTransport, ...rest } = opts ?? {};
  const result = await runEngine({
    tenantId: "11111111-1111-1111-1111-111111111111",
    sectionIds: Object.keys(implementations),
    sink,
    implementations,
    controls: fakeControls,
    // Default stub transport unless the caller overrides either channel.
    ...(createTransport ? { createTransport } : { transport: transport ?? stubTransport }),
    ...rest,
  });
  return { events, result };
}

function eventTypes(events: EngineEvent[]): string[] {
  return events.map((e) => e.type);
}

// ---------------------------------------------------------------------------
// ENG-04 / D-13: fail-soft section isolation
// ---------------------------------------------------------------------------

describe("runEngine section isolation", () => {
  it("keeps partial rows when a section throws mid-way and continues to later sections", async () => {
    const impls: Record<string, SectionImplementation> = {
      alpha: async (ctx) => {
        ctx.addRow(input("ALPHA-001", "Pass"));
        ctx.addRow(input("ALPHA-002", "Fail"));
        throw new Error("collector exploded\nwith a second line of detail");
      },
      beta: async (ctx) => {
        ctx.addRow(input("BETA-001", "Pass"));
      },
    };

    const { events, result } = await run(impls);

    // Partials preserved.
    expect(result.sections[0].rows.map((r) => r.checkId)).toEqual([
      "ALPHA-001.1",
      "ALPHA-002.1",
    ]);
    // Section-level error recorded, sanitized to one line.
    expect(result.sections[0].error).toBeDefined();
    expect(result.sections[0].error).not.toContain("\n");
    expect(result.sections[0].error).toContain("collector exploded");
    // Later sections unaffected.
    expect(result.sections[1].rows).toHaveLength(1);
    expect(result.sections[1].error).toBeUndefined();
    // Events: section-error then section-finished for alpha; run finished last.
    const errorIdx = events.findIndex(
      (e) => e.type === "section-error" && e.sectionId === "alpha",
    );
    const finishedIdx = events.findIndex(
      (e) => e.type === "section-finished" && e.sectionId === "alpha",
    );
    expect(errorIdx).toBeGreaterThan(-1);
    expect(finishedIdx).toBeGreaterThan(errorIdx);
    expect(events[events.length - 1].type).toBe("run-finished");
  });

  it("emits exactly the deterministic event order on the happy path (D-12)", async () => {
    const impls: Record<string, SectionImplementation> = {
      alpha: async (ctx) => {
        ctx.addRow(input("ALPHA-001"));
        ctx.addRow(input("ALPHA-002"));
      },
      beta: async (ctx) => {
        ctx.addRow(input("BETA-001"));
      },
    };

    const { events } = await run(impls);

    expect(eventTypes(events)).toEqual([
      "run-started",
      "section-started", // alpha
      "check-completed",
      "check-completed",
      "section-finished",
      "section-started", // beta
      "check-completed",
      "section-finished",
      "run-finished",
    ]);
    const started = events.filter((e) => e.type === "run-started")[0];
    if (started?.type === "run-started") {
      expect(started.tenantIds).toEqual(["11111111-1111-1111-1111-111111111111"]);
      expect(started.sections).toEqual(["alpha", "beta"]);
    }
  });

  it("maps an Error-status row through addRow to Skipped(graph_error) without throwing (D-16)", async () => {
    let captured: CheckRow | undefined;
    const impls: Record<string, SectionImplementation> = {
      alpha: async (ctx) => {
        captured = ctx.addRow(input("ERR-001", "Error"));
      },
    };

    const { result } = await run(impls);

    expect(captured?.status).toBe("Skipped");
    expect(captured?.skipReason).toBe("graph_error");
    expect(result.sections[0].rows[0].skipReason).toBe("graph_error");
  });

  it("treats an unported section as an explicit section-error and keeps running (D-10)", async () => {
    const impls: Record<string, SectionImplementation> = {
      beta: async (ctx) => {
        ctx.addRow(input("BETA-001"));
      },
    };
    // `unported` is requested but has no implementation injected.
    const { events, result } = await run(impls, {
      sectionIds: ["unported", "beta"],
    });

    expect(result.sections[0].sectionId).toBe("unported");
    expect(result.sections[0].rows).toEqual([]); // never fabricate results
    expect(result.sections[0].error).toContain("not implemented");
    const errEvent = events.find(
      (e) => e.type === "section-error" && e.sectionId === "unported",
    );
    expect(errEvent).toBeDefined();
    // Run continued to beta.
    expect(result.sections[1].rows).toHaveLength(1);
    expect(events[events.length - 1].type).toBe("run-finished");
  });
});

// ---------------------------------------------------------------------------
// D-19/Pitfall 5: fresh sub-numberer per section
// ---------------------------------------------------------------------------

describe("runEngine per-section isolation", () => {
  it("gives each section a FRESH sub-numberer — same base id yields .1 in both", async () => {
    const impls: Record<string, SectionImplementation> = {
      alpha: async (ctx) => {
        ctx.addRow(input("DUP-001"));
        ctx.addRow(input("DUP-001"));
      },
      beta: async (ctx) => {
        ctx.addRow(input("DUP-001"));
      },
    };

    const { result } = await run(impls);

    expect(result.sections[0].rows.map((r) => r.checkId)).toEqual([
      "DUP-001.1",
      "DUP-001.2",
    ]);
    expect(result.sections[1].rows[0].checkId).toBe("DUP-001.1");
  });

  it("falls back to registry remediation text when the collector omits it (D-22)", async () => {
    let captured: CheckRow | undefined;
    const impls: Record<string, SectionImplementation> = {
      alpha: async (ctx) => {
        captured = ctx.addRow(input("REMEDIATED-001"));
        ctx.addRow({ ...input("UNKNOWN-001"), remediation: "" });
      },
    };

    const { result } = await run(impls);

    expect(captured?.remediation).toContain("Do the thing from the registry");
    // Unknown base id → empty remediation stays empty (never fabricate text).
    expect(result.sections[0].rows[1].remediation).toBe("");
  });
});

// ---------------------------------------------------------------------------
// D-13 circuit breaker integration
// ---------------------------------------------------------------------------

describe("runEngine circuit breaker", () => {
  it(`stops emitting live rows after ${5} consecutive surfaced errors — subsequent addRow returns Skipped(circuit_broken)`, async () => {
    const collected: CheckRow[] = [];
    const impls: Record<string, SectionImplementation> = {
      flaky: async (ctx) => {
        for (let i = 1; i <= 5; i += 1) {
          collected.push(ctx.addRow(input(`FLK-${String(i).padStart(3, "0")}`, "Error")));
        }
        // Breaker has tripped by now — this row must NOT be evaluated.
        collected.push(ctx.addRow(input("FLK-006", "Pass")));
      },
    };

    const { events, result } = await run(impls);

    const statuses = result.sections[0].rows.map((r) => ({
      status: r.status,
      reason: r.skipReason,
    }));
    for (let i = 0; i < 5; i += 1) {
      expect(statuses[i]).toEqual({ status: "Skipped", reason: "graph_error" });
    }
    expect(statuses[5]).toEqual({ status: "Skipped", reason: "circuit_broken" });
    // The run itself was never killed (D-13): section finished, run finished.
    expect(events.some((e) => e.type === "section-finished")).toBe(true);
    expect(events[events.length - 1].type).toBe("run-finished");
  });
});

// ---------------------------------------------------------------------------
// D-20 licensing overlay post-processing
// ---------------------------------------------------------------------------

describe("runEngine licensing overlay post-processing", () => {
  const skuStates = [
    {
      skuId: "c7df2760-2c31-4fc6-b343-72a46becfa53",
      skuPartNumber: "ENTERPRISEPREMIUM",
      servicePlans: [
        {
          servicePlanId: "00000000-0000-0000-0000-000000000001",
          serviceName: "AAD_PREMIUM_P2",
          provisioningStatus: "PendingActivation",
        },
      ],
    },
  ];

  it("applies applyLicensingOverlay over all section rows when subscribedSkus were collected (D-20)", async () => {
    const impls: Record<string, SectionImplementation> = {
      licensing: async (ctx) => {
        ctx.shared.set("subscribedSkus", skuStates);
        ctx.addRow(input("LIC-GATED-001", "Fail"));
      },
      identity: async (ctx) => {
        ctx.addRow(input("IDENT-001", "Pass"));
      },
    };

    const { result } = await run(impls);

    const gated = result.sections[0].rows[0];
    expect(gated.status).toBe("Skipped");
    expect(gated.skipReason).toBe("not_licensed");
    // Untouched row passes through; non-gated checkIds are never rewritten.
    expect(result.sections[1].rows[0].status).toBe("Pass");
    expect(result.licensingOverlayApplied).toBe(true);
  });

  it("skips overlay application entirely when no subscribedSkus were collected — never guesses SKU state", async () => {
    const impls: Record<string, SectionImplementation> = {
      identity: async (ctx) => {
        ctx.addRow(input("LIC-GATED-001", "Fail"));
      },
    };

    const { result } = await run(impls);

    const row = result.sections[0].rows[0];
    expect(row.status).toBe("Fail");
    expect(row.skipReason).toBeUndefined();
    expect(result.licensingOverlayApplied).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// D-25/D-09: every Graph call appears in the event stream
// ---------------------------------------------------------------------------

describe("runEngine transport event wiring", () => {
  it("wires transport page calls into graph-call events via createTransport", async () => {
    const fetchCalls: string[] = [];
    const fetchImpl = (async (url: string | URL | Request) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ value: [{ id: "u1" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    const handlers: { onPage?: (e: GraphCallEvent) => void } = {};
    const factory = (h: { onPage(e: GraphCallEvent): void; onWarning(m: string): void }) => {
      handlers.onPage = h.onPage;
      return new GraphTransport({
        getToken: async () => "fake-token",
        fetchImpl,
        onPage: h.onPage,
        isRoleGranted: () => true,
      });
    };

    const { events } = await run(
      {
        alpha: async (ctx) => {
          await ctx.transport.getJson("/v1.0/users");
        },
      },
      { createTransport: factory },
    );
    void handlers;

    const call = events.find((e) => e.type === "graph-call");
    expect(call).toMatchObject({
      type: "graph-call",
      method: "GET",
      url: "https://graph.microsoft.com/v1.0/users",
      status: 200,
    });
    expect(fetchCalls).toHaveLength(1);
  });

  it("converts transport page-cap warnings into page-cap-warning events — truncation is never silent", async () => {
    let page = 0;
    const fetchImpl = (async () => {
      page += 1;
      const body =
        page === 1
          ? {
              value: [{ id: "u1" }],
              "@odata.nextLink":
                "https://graph.microsoft.com/v1.0/users?$skipToken=abc",
            }
          : { value: [{ id: "u2" }] };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    const factory = (h: { onPage(e: GraphCallEvent): void; onWarning(m: string): void }) =>
      new GraphTransport({
        getToken: async () => "fake-token",
        fetchImpl,
        onPage: h.onPage,
        onWarning: h.onWarning,
        isRoleGranted: () => true,
        maxPages: 1,
      });

    const { events } = await run(
      {
        alpha: async (ctx) => {
          await ctx.transport.getJson("/v1.0/users");
        },
      },
      { createTransport: factory },
    );

    const cap = events.find((e) => e.type === "page-cap-warning");
    expect(cap).toMatchObject({
      type: "page-cap-warning",
      url: "/v1.0/users",
      maxPages: 1,
    });
  });

  it("rejects options that provide neither or both of transport/createTransport", async () => {
    const { sink } = makeSink();
    const base = {
      tenantId: "11111111-1111-1111-1111-111111111111",
      sectionIds: [],
      sink,
      implementations: {},
      controls: fakeControls,
    };
    await expect(
      runEngine({ ...base, transport: stubTransport, createTransport: () => stubTransport }),
    ).rejects.toThrow();
    await expect(runEngine(base)).rejects.toThrow();
  });
});
