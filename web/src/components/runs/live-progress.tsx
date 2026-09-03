"use client";

import * as React from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "./status-badge";
import { useRunEvents } from "@/lib/runs/use-run-events";
import { Loader2, CheckCircle2, XCircle, ChevronDownIcon, ChevronUpIcon } from "lucide-react";

export interface LiveProgressProps {
  runId: string;
  startedAtIso: string;
  tenantDomain: string;
  initialSections: Record<string, { sectionId: string; rowCount: number; error?: string }>;
}

function formatElapsed(ms: number): string {
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

export function LiveProgress({ runId, startedAtIso, tenantDomain, initialSections }: LiveProgressProps) {
  const { connectionState, sections, elapsedMs } = useRunEvents(runId, startedAtIso, true);

  const mergedKeys = new Set([...Object.keys(initialSections), ...Object.keys(sections)]);
  const startDate = new Date(startedAtIso);

  // Collapsible finished sections — default collapsed for completed/failed, expanded for running/queued (UI-SPEC S2a)
  const [collapsed, setCollapsed] = React.useState<Set<string>>(new Set());
  const [manuallyToggled, setManuallyToggled] = React.useState<Set<string>>(new Set());

  // Sync collapsed defaults when sections change, but respect manual toggles
  React.useEffect(() => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      let changed = false;
      for (const key of Array.from(mergedKeys)) {
        if (manuallyToggled.has(key)) continue;
        const initial = initialSections[key];
        const live = sections[key];
        const status = live?.status ?? (initial ? "completed" : "queued");
        const shouldCollapsed = status === "completed" || status === "failed";
        if (shouldCollapsed && !next.has(key)) { next.add(key); changed = true; }
        if (!shouldCollapsed && next.has(key)) { next.delete(key); changed = true; }
      }
      return changed ? next : prev;
    });
  }, [sections, initialSections, manuallyToggled, mergedKeys]);

  function toggleCollapsed(key: string) {
    setManuallyToggled((prev) => {
      const n = new Set(prev);
      n.add(key);
      return n;
    });
    setCollapsed((prev) => {
      const n = new Set(prev);
      if (n.has(key)) n.delete(key); else n.add(key);
      return n;
    });
  }

  return (
    <div className="flex flex-col gap-xl">
      {/* Header Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-md">
            <CardTitle className="text-lg font-semibold">Entra ID assessment</CardTitle>
            <Badge variant="outline" className="border-primary text-primary bg-primary/10">
              In progress
            </Badge>
          </div>
          <div className="flex flex-col gap-sm2 text-sm text-muted-foreground">
            <span>{tenantDomain}</span>
            <span>{startDate.toLocaleString()} · elapsed {formatElapsed(elapsedMs)}</span>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-sm2">
            {connectionState === "reconnecting" ? (
              <>
                <span className="h-2 w-2 rounded-full bg-warning animate-pulse" />
                <span className="text-sm font-medium text-warning">Reconnecting…</span>
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                <span className="text-sm font-medium text-primary">Live</span>
              </>
            )}
          </div>
          {connectionState === "reconnecting" ? (
            <Alert className="mt-md">
              <AlertDescription>Lost live connection — reconnecting. Your run is still executing.</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      {/* Progress list — max-w-[42rem], fixed row height, no layout shift */}
      <div className="flex max-w-[42rem] flex-col gap-md">
        {Array.from(mergedKeys).length === 0 ? (
          <p className="text-sm text-muted-foreground">Preparing assessment…</p>
        ) : null}
        {Array.from(mergedKeys).map((key) => {
          const initial = initialSections[key];
          const live = sections[key];
          const status = live?.status ?? (initial ? "completed" : "queued");
          const checks = live?.checks ?? [];
          const count = checks.length;
          const total = initial?.rowCount;
          const error = live?.error ?? initial?.error;
          const isCollapsed = collapsed.has(key);
          const hasChecks = checks.length > 0;
          const collapsible = status === "completed" || status === "failed" || (status === "running" && hasChecks);

          return (
            <Card key={key} className="min-h-[56px]">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <button
                  type="button"
                  aria-label={`${isCollapsed ? "Expand" : "Collapse"} ${key} section`}
                  aria-expanded={!isCollapsed}
                  onClick={() => collapsible && toggleCollapsed(key)}
                  disabled={!collapsible}
                  className={`flex flex-1 items-center gap-sm2 text-left ${collapsible ? "cursor-pointer" : "cursor-default"} min-h-[44px]`}
                >
                  <span className="font-mono text-sm">{key}</span>
                  {collapsible ? (
                    isCollapsed ? (
                      <ChevronDownIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                    ) : (
                      <ChevronUpIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                    )
                  ) : null}
                </button>
                <span className="flex items-center gap-sm2 text-sm shrink-0">
                  {status === "queued" ? (
                    <Badge variant="secondary" className="bg-muted text-muted-foreground">Queued</Badge>
                  ) : status === "running" ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin text-primary" />
                      <Badge variant="outline" className="border-primary text-primary">Running</Badge>
                    </>
                  ) : status === "completed" ? (
                    <>
                      <CheckCircle2 className="h-4 w-4 text-success" />
                      <Badge variant="outline" className="border-success text-success">Completed</Badge>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-destructive" />
                      <Badge variant="destructive">Failed</Badge>
                    </>
                  )}
                  <span className="text-muted-foreground">
                    {total != null ? `${count} of ${total} checks` : `${count} checks`}
                  </span>
                </span>
              </CardHeader>
              {!isCollapsed && (status === "running" || status === "completed" || status === "failed") && hasChecks ? (
                <CardContent className="flex flex-col gap-sm2">
                  {checks.map((c) => (
                    <div key={c.checkId + c.setting} className="flex h-8 items-center justify-between gap-md text-sm">
                      <span className="flex items-center gap-md overflow-hidden">
                        <span className="font-mono text-xs shrink-0">{c.checkId}</span>
                        <span className="truncate">{c.setting}</span>
                      </span>
                      <StatusBadge status={c.status as "Pass" | "Fail" | "Warning" | "Review" | "Info" | "Skipped"} skipReason={c.skipReason as "not_licensed" | "not_applicable" | "graph_error" | "not_implemented" | "circuit_broken" | undefined} />
                    </div>
                  ))}
                  {status === "failed" && error ? (
                    <p className="text-sm text-destructive">This section couldn&apos;t complete: {error}. Other sections were unaffected.</p>
                  ) : null}
                </CardContent>
              ) : !isCollapsed && status === "failed" && error ? (
                <CardContent>
                  <p className="text-sm text-destructive">This section couldn&apos;t complete: {error}. Other sections were unaffected.</p>
                </CardContent>
              ) : isCollapsed && hasChecks ? (
                <CardContent className="pt-0">
                  <Button variant="ghost" size="sm" className="h-7 text-xs px-2" onClick={() => toggleCollapsed(key)}>
                    Show {count} checks
                  </Button>
                </CardContent>
              ) : null}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
