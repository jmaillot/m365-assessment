import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReportData } from "@/report/build-report-data";

export function OverviewTab({ data }: { data: ReportData }) {
  return (
    <div className="flex flex-col gap-xl">
      {/* Headline scorecard — Display role 28px semibold strict-rule Pass % */}
      <div className="flex flex-col gap-sm2">
        <p className="text-3xl font-semibold leading-none" style={{ fontSize: "28px" }}>
          <span className="text-success">{data.summary.passRatePct}%</span>
          <span className="ml-2 text-base font-normal text-muted-foreground">Pass rate</span>
        </p>
        <p className="text-sm text-muted-foreground">
          {data.summary.pass} of {data.summary.pass + data.summary.fail + data.summary.warning + data.summary.review} evaluated checks passed
        </p>
      </div>

      {/* Summary Card grid — one per bucket */}
      <div className="grid grid-cols-2 gap-md md:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Pass</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xl font-semibold text-success">{data.summary.pass}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Fail</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xl font-semibold text-destructive">{data.summary.fail}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Warning</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xl font-semibold text-foreground">{data.summary.warning}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Review</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xl font-semibold text-foreground">{data.summary.review}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Skipped / Info</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xl font-semibold text-foreground">{data.summary.infoAndSkipped}</p>
          </CardContent>
        </Card>
      </div>

      {/* Reviews need work — highlighted when >0, stays in score */}
      {data.summary.review > 0 ? (
        <Alert className="border-review/30 bg-review/10">
          <AlertTitle className="text-review">{data.summary.review} review{data.summary.review === 1 ? "" : "s"} need your attention</AlertTitle>
          <AlertDescription>
            Reviews count as not passing in the pass rate and framework scores — attested 100% requires 0 reviews. Open the Reviews tab to triage.
          </AlertDescription>
        </Alert>
      ) : null}

      {/* Persistent coverage Notice — D-15, unconditional */}
      <Alert>
        <AlertTitle>Coverage</AlertTitle>
        <AlertDescription>{data.coverage.label}</AlertDescription>
      </Alert>

      {/* Section-result strip — fail-soft visible */}
      <div className="flex flex-col gap-sm2">
        <h3 className="text-lg font-semibold leading-none">Sections</h3>
        {data.sections.map((s) => (
          <div key={s.sectionId} className="flex flex-col gap-sm2 rounded-md border bg-card px-3 py-2">
            <div className="flex items-center justify-between text-sm">
              <span className="font-mono text-sm">{s.sectionId}</span>
              <span className="text-muted-foreground">{s.rowCount} checks</span>
            </div>
            {s.error ? (
              <p className="text-sm text-destructive">This section couldn&apos;t complete: {s.error}. Other sections were unaffected.</p>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}
