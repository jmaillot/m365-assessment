"use client";

import * as React from "react";
import { ChevronDown } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { StatusBadge } from "@/components/runs/status-badge";
import type { ReportData } from "@/report/build-report-data";

export function FrameworksTab({ data }: { data: ReportData }) {
  return (
    <div className="flex flex-col gap-md">
      {/* Persistent coverage notice — never unlabeled (D-15) */}
      <Alert>
        <AlertDescription>{data.coverage.label}</AlertDescription>
      </Alert>

      <div className="flex flex-col gap-sm2">
        {data.frameworks.map((fw) => (
          <div key={fw.id} className="rounded-md border bg-card">
            <details className="group">
              <summary className="flex min-h-[44px] cursor-pointer list-none items-center justify-between gap-md px-3 py-2">
                <div className="flex flex-col">
                  <span className="text-sm font-medium text-foreground">
                    {fw.name} <span className="font-mono text-xs text-muted-foreground">({fw.id})</span>
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {fw.controlsCovered} of {fw.controlsTotal} controls
                  </span>
                </div>
                <div className="flex items-center gap-md">
                  <span className="text-sm font-semibold text-foreground">{fw.scorePct}%</span>
                  <span
                    aria-label={`Expand ${fw.name} details`}
                    title={`Expand ${fw.name} details`}
                    className="inline-flex min-h-[44px] min-w-[44px] items-center justify-center rounded-md text-muted-foreground"
                  >
                    <ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" />
                  </span>
                </div>
              </summary>
              <div className="border-t px-3 py-2">
                {/* Per-row compact coverage indicator so no score can be read unlabeled */}
                <p className="mb-2 text-xs text-muted-foreground">{data.coverage.label}</p>
                {fw.checks.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No checks mapped to this framework in this run.</p>
                ) : (
                  <ul className="flex flex-col gap-sm2">
                    {fw.checks.map((c) => (
                      <li key={c.checkId + c.setting} className="flex items-center justify-between gap-md text-sm">
                        <span className="break-words">
                          <span className="font-mono text-xs">{c.checkId}</span> {c.setting}
                        </span>
                        <StatusBadge status={c.status} />
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </details>
          </div>
        ))}
      </div>
    </div>
  );
}
