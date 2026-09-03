import { redirect } from "next/navigation";

import Link from "next/link";
import { HistoryIcon } from "lucide-react";

import { DisconnectTenantButton } from "@/components/tenant/disconnect-dialog";
import { VerificationView } from "@/components/tenant/verification-view";
import { RunTriggerCard } from "@/components/runs/run-trigger-card";
import { getCredentialGate } from "@/app/api/tenant/connect-gate";
import { getSession } from "@/lib/auth/session";
import { getTenantStatus } from "@/lib/tenant/status";
import { getActiveRunId } from "@/lib/runs/run-service";
import { db } from "@/db";

export const dynamic = "force-dynamic";

/**
 * S5 — Permission verification view route (UI-SPEC, ONB-02/D-07). Loads the
 * signed-in user's own connection status and renders it; users without a
 * connection land back on S3 at /dashboard.
 */
export default async function TenantConnectionPage({
  searchParams,
}: PageProps<"/dashboard/tenant">) {
  const { user } = await getSession();
  if (!user) {
    redirect("/?notice=session_expired");
  }

  const status = await getTenantStatus(user.id);
  if (!status.connected || !status.tenant) {
    redirect("/dashboard");
  }

  const { error } = await searchParams;

  // D-06 connect gate — applies to the reconnect CTA in VerificationView too.
  const { gated } = await getCredentialGate();

  const activeRunId = getActiveRunId(user.id, db);
  const permissionsMissing = !status.verification || status.verification.status !== "all_granted";

  return (
    <section className="flex flex-col gap-md">
      <h1 className="text-xl font-semibold">Tenant connection</h1>
      <VerificationView
        tenant={status.tenant}
        verification={status.verification}
        consentDeclined={error === "consent_declined"}
        connectGated={gated}
        actions={
          <DisconnectTenantButton
            domain={status.tenant.primaryDomain ?? status.tenant.id}
          />
        }
      />
      <RunTriggerCard gated={gated} permissionsMissing={permissionsMissing} activeRunId={activeRunId} />
      <Link
        href="/dashboard/runs"
        className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline underline-offset-4"
      >
        <HistoryIcon className="size-4 shrink-0" aria-hidden="true" />
        View assessment history
      </Link>
    </section>
  );
}
