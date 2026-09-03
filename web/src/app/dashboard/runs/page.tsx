import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { getRunWithRows, listRunsForUser } from "@/lib/runs/run-service";
import { buildReportData } from "@/report/build-report-data";
import { RunsList, type RunsListItem } from "@/components/runs/runs-list";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { db } from "@/db";

declare global {
  interface ParamMap {
    "/dashboard/runs": Record<string, never>;
  }
}

export default async function RunsPage() {
  const { user } = await getSession();
  if (!user) {
    redirect("/?notice=session_expired");
  }

  const runs = listRunsForUser(user.id, db);

  // Enrich first 20 completed runs with passRate/domains for display — buildReportData is pure
  const enriched: RunsListItem[] = await Promise.all(
    runs.slice(0,20).map(async (r) => {
      if (r.status !== "completed") {
        return { id: r.id, status: r.status, startedAt: r.startedAt, finishedAt: r.finishedAt };
      }
      try {
        const withRows = getRunWithRows(r.id, user.id, db);
        if (!withRows) return { id: r.id, status: r.status, startedAt: r.startedAt, finishedAt: r.finishedAt };
        const mapped = withRows.rows.map((cr) => ({
          row: {
            category: cr.category,
            setting: cr.setting,
            currentValue: cr.currentValue,
            recommendedValue: cr.recommendedValue,
            status: cr.status,
            skipReason: cr.skipReason,
            checkId: cr.checkId,
            remediation: cr.remediation,
            intentDesign: cr.intentDesign,
            observedValue: cr.observedValue,
            expectedValue: cr.expectedValue,
            evidenceSource: cr.evidenceSource,
            evidenceTimestamp: cr.evidenceTimestamp,
            collectionMethod: cr.collectionMethod,
            permissionRequired: cr.permissionRequired,
            confidence: cr.confidence,
            limitations: cr.limitations,
          },
          sectionId: cr.sectionId,
        }));
        const report = buildReportData(mapped);
        return {
          id: r.id,
          status: r.status,
          startedAt: r.startedAt,
          finishedAt: r.finishedAt,
          passRatePct: report.summary.passRatePct,
          domainsPresent: report.coverage.domainsPresent,
          rowCount: report.summary.totalChecks,
        };
      } catch {
        return { id: r.id, status: r.status, startedAt: r.startedAt, finishedAt: r.finishedAt };
      }
    }),
  );

  // Remaining beyond 20 without enrichment
  const remaining = runs.slice(20).map((r) => ({ id: r.id, status: r.status, startedAt: r.startedAt, finishedAt: r.finishedAt }));
  const allItems = [...enriched, ...remaining];

  return (
    <div className="flex flex-col gap-xl max-w-[52rem]">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-semibold">Assessment history</CardTitle>
          <p className="text-sm text-muted-foreground">Past runs for this account — click any completed run to reopen its report.</p>
        </CardHeader>
        <CardContent>
          <RunsList runs={allItems} />
        </CardContent>
      </Card>
    </div>
  );
}
