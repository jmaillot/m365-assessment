import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { buttonVariants } from "@/components/ui/button";

export interface RunsListItem {
  id: string;
  status: string;
  startedAt: Date;
  finishedAt: Date | null;
  passRatePct?: number;
  domainsPresent?: string[];
  rowCount?: number;
}

export function RunsList({ runs }: { runs: RunsListItem[] }) {
  if (runs.length === 0) {
    return (
      <div className="flex flex-col gap-md rounded-md border bg-card p-6">
        <h3 className="text-lg font-semibold">No assessments yet</h3>
        <p className="text-sm text-muted-foreground">Run your first assessment to see how your tenant scores against security best practices and 15 compliance frameworks.</p>
        <Link href="/dashboard/tenant" className={buttonVariants({ variant: "default" }) + " self-start"}>
          Run assessment
        </Link>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Started</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Pass rate</TableHead>
          <TableHead>Domains</TableHead>
          <TableHead>Rows</TableHead>
          <TableHead></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {runs.map((r) => (
          <TableRow key={r.id}>
            <TableCell className="text-sm">{r.startedAt.toLocaleString()}</TableCell>
            <TableCell>
              <Badge variant={r.status === "completed" ? "default" : r.status === "failed" ? "destructive" : "secondary"} className="capitalize">
                {r.status}
              </Badge>
            </TableCell>
            <TableCell className="text-sm">{r.passRatePct != null ? `${r.passRatePct}%` : "—"}</TableCell>
            <TableCell className="text-sm">
              <span className="flex flex-wrap gap-1">
                {(r.domainsPresent ?? []).slice(0, 3).map((d) => (
                  <Badge key={d} variant="secondary" className="text-xs">
                    {d}
                  </Badge>
                ))}
                {(r.domainsPresent?.length ?? 0) > 3 ? <span className="text-xs text-muted-foreground">+{r.domainsPresent!.length - 3}</span> : null}
              </span>
            </TableCell>
            <TableCell className="text-sm">{r.rowCount ?? "—"}</TableCell>
            <TableCell className="text-sm">
              <Link
                href={`/dashboard/runs/${r.id}`}
                className={buttonVariants({ variant: "link" }) + " h-auto p-0 text-sm"}
              >
                {r.status === "completed" ? "View report" : r.status === "failed" ? "View error" : "View progress"}
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
