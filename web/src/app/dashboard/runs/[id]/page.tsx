import { redirect, notFound } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { getRun, listCheckRows } from "@/lib/runs/run-service";
import { getTenantStatus } from "@/lib/tenant/status";
import { buildReportData } from "@/report/build-report-data";
import { ReportView } from "@/components/report/report-view";
import { RunPageView } from "@/components/runs/run-page-view";
import { db } from "@/db";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DownloadIcon } from "lucide-react";

// Extend ParamMap for this new route so PageProps type resolves before next types regeneration
declare global {
  interface ParamMap {
    "/dashboard/runs/[id]": { id: string };
  }
}

export default async function RunPage({ params }: PageProps<"/dashboard/runs/[id]">) {
  const { user } = await getSession();
  if (!user) {
    redirect("/?notice=session_expired");
  }

  const { id } = (await params) as { id: string };
  const run = getRun(user.id, id, db);
  if (!run) {
    notFound();
  }

  const tenantStatus = await getTenantStatus(user.id);
  const tenantDomain = tenantStatus.tenant?.primaryDomain ?? tenantStatus.tenant?.id ?? "";

  if (run.status === "completed") {
    const rows = listCheckRows(run.id, db);
    const mapped = rows.map((r) => ({
      row: {
        category: r.category,
        setting: r.setting,
        currentValue: r.currentValue,
        recommendedValue: r.recommendedValue,
        status: r.status,
        skipReason: r.skipReason,
        checkId: r.checkId,
        remediation: r.remediation,
        intentDesign: r.intentDesign,
        observedValue: r.observedValue,
        expectedValue: r.evidenceSource ? r.expectedValue : r.expectedValue,
        evidenceSource: r.evidenceSource,
        evidenceTimestamp: r.evidenceTimestamp,
        collectionMethod: r.collectionMethod,
        permissionRequired: r.permissionRequired,
        confidence: r.confidence,
        limitations: r.limitations,
      },
      sectionId: r.sectionId,
    }));
    const reportData = buildReportData(mapped);

    return (
      <div className="flex flex-col gap-xl">
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between gap-md">
              <div className="flex flex-col gap-sm2">
                <CardTitle className="text-lg font-semibold">Entra ID assessment</CardTitle>
                <div className="flex flex-col gap-sm2 text-sm text-muted-foreground">
                  <span>{tenantDomain}</span>
                  <span>
                    {run.startedAt.toLocaleString()} {run.finishedAt ? `— ${run.finishedAt.toLocaleString()}` : ""}
                  </span>
                </div>
              </div>
              <a
                href={`/api/runs/${run.id}/export`}
                download
                className="inline-flex h-7 items-center justify-center gap-1.5 rounded-[min(var(--radius-md),12px)] border border-border bg-background px-2.5 text-[0.8rem] font-medium hover:bg-muted hover:text-foreground"
              >
                <DownloadIcon className="size-3.5" />
                Export HTML
              </a>
            </div>
          </CardHeader>
        </Card>
        <ReportView data={reportData} />
      </div>
    );
  }

  if (run.status === "failed") {
    return <RunPageView mode="failed" reason={run.error ?? "The assessment ended unexpectedly."} />;
  }

  // queued / running → live mode with real persisted snapshot (D-07)
  const rows = listCheckRows(run.id, db);
  const initialSections: Record<string, { sectionId: string; rowCount: number; error?: string }> = {};
  for (const r of rows) {
    const existing = initialSections[r.sectionId];
    if (existing) existing.rowCount += 1;
    else initialSections[r.sectionId] = { sectionId: r.sectionId, rowCount: 1 };
  }

  return (
    <RunPageView
      mode="running"
      runId={run.id}
      startedAtIso={run.startedAt.toISOString()}
      tenantDomain={tenantDomain}
      initialSections={initialSections}
    />
  );
}
