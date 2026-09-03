import { redirect } from "next/navigation";

import { Sidebar } from "@/components/dashboard/sidebar";
import { Topbar } from "@/components/dashboard/topbar";
import { getSession } from "@/lib/auth/session";
import { getTenantStatus } from "@/lib/tenant/status";

/**
 * Dashboard shell layout (UI-SPEC S2). Server component — full DB session
 * validation (layer 2 of defense in depth; proxy.ts only checks cookie
 * presence). Unauthenticated/expired requests land back on S1 with the
 * exact expiry notice.
 */
export default async function DashboardLayout({
  children,
}: LayoutProps<"/dashboard">) {
  const { user } = await getSession();
  if (!user) {
    redirect("/?notice=session_expired");
  }
  const tenantStatus = await getTenantStatus(user.id);

  return (
    <div className="flex min-h-screen flex-1">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          displayName={user.displayName}
          email={user.email}
          connected={tenantStatus.connected}
          tenantDomain={tenantStatus.tenant?.primaryDomain ?? undefined}
        />
        <main className="flex-1 bg-background p-lg">{children}</main>
      </div>
    </div>
  );
}
