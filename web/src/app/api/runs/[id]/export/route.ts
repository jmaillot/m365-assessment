import { NextResponse } from "next/server";
import { getSession } from "@/lib/auth/session";
import { getRun, listCheckRows } from "@/lib/runs/run-service";
import { getTenantStatus } from "@/lib/tenant/status";
import { buildReportData } from "@/report/build-report-data";
import { buildSelfContainedHtml } from "@/report/build-self-contained-html";
import { db } from "@/db";

export async function GET(
  _req: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { user } = await getSession();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }
  const { id } = await context.params;
  const run = getRun(user.id, id, db);
  if (!run) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  if (run.status !== "completed") {
    return NextResponse.json({ error: "Run not completed" }, { status: 400 });
  }
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
      expectedValue: r.expectedValue,
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
  const tenantStatus = await getTenantStatus(user.id);
  const tenantDomain = tenantStatus.tenant?.primaryDomain ?? tenantStatus.tenant?.id ?? "tenant";

  const html = buildSelfContainedHtml(reportData, {
    tenantDomain,
    runId: run.id,
    startedAt: run.startedAt.toISOString(),
    finishedAt: run.finishedAt?.toISOString(),
    title: `M365 Assessment — ${tenantDomain}`,
  });

  const filename = `_Assessment-Report_${tenantDomain}_${run.id.slice(0, 8)}.html`;
  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
