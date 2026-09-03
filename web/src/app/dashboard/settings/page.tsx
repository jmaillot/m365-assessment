import { redirect } from "next/navigation";

import { OperatorCredentialWizard } from "@/components/settings/operator-credential-wizard";
import { getSession } from "@/lib/auth/session";
import { getOperatorCredentialStatus } from "@/lib/settings/operator-credential";

/**
 * Dashboard Settings (S2 nav) — operator credential management (D-02/D-05).
 *
 * Server component: the credential status is read DIRECTLY via
 * getOperatorCredentialStatus() (no HTTP self-call — established Phase 1
 * pattern). The wizard is a client component that receives the server-read
 * state as props; all mutations go through /api/settings/operator-credential,
 * whose session-gated first-use claim is the actual enforcement (the UI only
 * reflects server verdicts — T-02-11a).
 */
export default async function SettingsPage() {
  const { user } = await getSession();
  if (!user) {
    redirect("/?notice=session_expired");
  }
  const { isOperatorAdmin } = await import("@/lib/auth/allowlist");
  if (!isOperatorAdmin(user.email)) {
    redirect("/dashboard?notice=forbidden");
  }

  const status = await getOperatorCredentialStatus();

  return (
    <section className="flex flex-col gap-md">
      <h1 className="text-xl font-semibold">Settings</h1>
      <OperatorCredentialWizard
        initialConfigured={status.configured}
        initialConfiguredAt={status.configuredAt}
      />
    </section>
  );
}
