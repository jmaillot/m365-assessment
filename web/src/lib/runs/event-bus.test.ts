import { describe, it, expect } from "vitest";
import { createEventBus } from "./event-bus";
import type { EngineEvent } from "@/engine/events/engine-events";

function makeEvent(type: EngineEvent["type"]): EngineEvent {
  switch (type) {
    case "run-started":
      return { type: "run-started", tenantIds: ["tid"], sections: ["identity"] };
    case "section-started":
      return { type: "section-started", sectionId: "identity" };
    case "check-completed":
      return {
        type: "check-completed",
        sectionId: "identity",
        row: {
          category: "C",
          setting: "S",
          currentValue: "",
          recommendedValue: "",
          status: "Pass",
          checkId: "ENTRA-X-001.1",
          remediation: "",
          intentDesign: false,
        },
      };
    case "section-error":
      return { type: "section-error", sectionId: "identity", message: "boom" };
    case "section-finished":
      return { type: "section-finished", sectionId: "identity" };
    case "run-finished":
      return { type: "run-finished", result: { tenantId: "tid", sections: [] } };
    case "graph-call":
      return { type: "graph-call", method: "GET", url: "https://graph.microsoft.com/v1.0/test", status: 200 };
    case "page-cap-warning":
      return { type: "page-cap-warning", url: "https://graph.microsoft.com/v1.0/test", maxPages: 10 };
  }
}

describe("createEventBus", () => {
  it("subscribe returns unsubscribe; after calling it emit no longer reaches that subscriber", () => {
    const bus = createEventBus();
    const received: EngineEvent[] = [];
    const unsub = bus.subscribe("run1", (e) => received.push(e));
    bus.emit("run1", makeEvent("section-started"));
    expect(received).toHaveLength(1);
    unsub();
    bus.emit("run1", makeEvent("section-started"));
    expect(received).toHaveLength(1);
    expect(bus.subscriberCount("run1")).toBe(0);
  });

  it("emit delivers to every current subscriber of that runId; other runIds receive nothing", () => {
    const bus = createEventBus();
    const a: EngineEvent[] = [];
    const b: EngineEvent[] = [];
    const c: EngineEvent[] = [];
    bus.subscribe("run1", (e) => a.push(e));
    bus.subscribe("run1", (e) => b.push(e));
    bus.subscribe("run2", (e) => c.push(e));
    bus.emit("run1", makeEvent("section-started"));
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
    expect(c).toHaveLength(0);
    bus.emit("run2", makeEvent("section-started"));
    expect(c).toHaveLength(1);
    expect(a).toHaveLength(1);
  });

  it("a subscriber that throws does NOT prevent delivery to others and does NOT crash emit", () => {
    const bus = createEventBus();
    const good: EngineEvent[] = [];
    bus.subscribe("run1", () => {
      throw new Error("boom");
    });
    bus.subscribe("run1", (e) => good.push(e));
    expect(() => bus.emit("run1", makeEvent("section-started"))).not.toThrow();
    expect(good).toHaveLength(1);
  });

  it("close clears all subscribers; subsequent emits are silent no-ops", () => {
    const bus = createEventBus();
    const received: EngineEvent[] = [];
    bus.subscribe("run1", (e) => received.push(e));
    bus.subscribe("run1", (e) => received.push(e));
    expect(bus.subscriberCount("run1")).toBe(2);
    bus.close("run1");
    expect(bus.subscriberCount("run1")).toBe(0);
    bus.emit("run1", makeEvent("section-started"));
    expect(received).toHaveLength(0);
    // closing non-existent run is no-op
    expect(() => bus.close("run1")).not.toThrow();
    expect(() => bus.close("other")).not.toThrow();
  });

  it("subscriberCount reports current listener count", () => {
    const bus = createEventBus();
    expect(bus.subscriberCount("run1")).toBe(0);
    const u1 = bus.subscribe("run1", () => {});
    expect(bus.subscriberCount("run1")).toBe(1);
    const u2 = bus.subscribe("run1", () => {});
    expect(bus.subscriberCount("run1")).toBe(2);
    u1();
    expect(bus.subscriberCount("run1")).toBe(1);
    bus.subscribe("run2", () => {});
    expect(bus.subscriberCount("run2")).toBe(1);
    expect(bus.subscriberCount("run1")).toBe(1);
    u2();
    expect(bus.subscriberCount("run1")).toBe(0);
  });
});
