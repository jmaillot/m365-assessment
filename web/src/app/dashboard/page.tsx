import { redirect } from "next/navigation";
import { InfoIcon } from "lucide-react";

import { ConnectTenantButton } from "@/components/tenant/connect-button";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { CredentialStatusBanner } from "@/components/settings/credential-status-banner";
import { getSession } from "@/lib/auth/session";
import { getCredentialGate } from "@/app/api/tenant/connect-gate";
import { getTenantStatus } from "@/lib/tenant/status";

/**
 * S3 — Empty state: no tenant connected (UI-SPEC, ONB-01/D-05). Reads the
 * tenant status data source directly (no HTTP self-call). Users WITH a
 * connection are routed to S5 at /dashboard/tenant.
 *
 * ?cleanup=1 (set by the S6 disconnect flow) renders the optional-cleanup
 * info Alert: D-08 assigns removing the enterprise application object to
 * the customer, so we link them to the setup guide that shows how.
 */

const EMPTY_STATE_BODY =
  "Connect your Microsoft 365 tenant so M365-Assess can verify read-only access. This requires an admin consent from your organization's Entra ID.";

const CLEANUP_ALERT_COPY =
  "Optional cleanup: remove the M365-Assess enterprise app object from your Entra tenant.";

export default async function DashboardPage({
  searchParams,
}: PageProps<"/dashboard">) {
  const { user } = await getSession();
  if (!user) {
    redirect("/?notice=session_expired");
  }

  const status = await getTenantStatus(user.id);
  if (status.connected) {
    redirect("/dashboard/tenant");
  }

  const { cleanup } = await searchParams;

  // D-06 connect gate: while no operator credential is configured the
  // banner renders and Connect stays disabled — dashboard remains browsable.
  const { gated } = await getCredentialGate();

  return (
    <section className="flex flex-col gap-md">
      <h1 className="text-xl font-semibold">Dashboard</h1>
      <CredentialStatusBanner gated={gated} />
      {cleanup === "1" ? (
        <Alert className="max-w-[32rem]">
          <InfoIcon aria-hidden="true" />
          <AlertTitle>{CLEANUP_ALERT_COPY}</AlertTitle>
          <AlertDescription>
            Steps are in the{" "}
            <a
              href="/docs/web/APP-REGISTRATION-SETUP.md"
              className="underline underline-offset-3 hover:text-foreground"
            >
              setup docs
            </a>
            .
          </AlertDescription>
        </Alert>
      ) : null}
      <Card className="max-w-[32rem]">
        <CardHeader>
          <CardTitle>No tenant connected</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-lg">
          <p className="text-base leading-relaxed text-muted-foreground">
            {EMPTY_STATE_BODY}
          </p>
          <div>
            <ConnectTenantButton disabled={gated} />
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
