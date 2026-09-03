"use client";

import Link from "next/link";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { buttonVariants } from "@/components/ui/button";
import { LiveProgress } from "./live-progress";

export interface RunPageViewProps {
  mode: "running" | "failed";
  // running mode
  runId?: string;
  startedAtIso?: string;
  tenantDomain?: string;
  initialSections?: Record<string, { sectionId: string; rowCount: number; error?: string }>;
  // failed mode
  reason?: string;
}

export function RunPageView({ mode, runId, startedAtIso, tenantDomain, initialSections, reason }: RunPageViewProps) {
  if (mode === "failed") {
    return (
      <div className="flex flex-col gap-md">
        <Alert variant="destructive">
          <AlertTitle>Assessment failed</AlertTitle>
          <AlertDescription>This assessment did not finish. {reason ?? "The assessment ended unexpectedly."} Start a new assessment when you&apos;re ready.</AlertDescription>
        </Alert>
        <Link href="/dashboard/tenant" className={buttonVariants({ variant: "default" })}>
          Run assessment
        </Link>
      </div>
    );
  }

  if (!runId || !startedAtIso) return null;

  return (
    <LiveProgress
      runId={runId}
      startedAtIso={startedAtIso}
      tenantDomain={tenantDomain ?? ""}
      initialSections={initialSections ?? {}}
    />
  );
}
