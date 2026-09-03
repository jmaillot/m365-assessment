import { KeyRoundIcon } from "lucide-react";

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";

/**
 * D-06 gate banner — rendered while hasOperatorCredential() is false
 * (see connect-gate.ts). Informational, NOT navigation-blocking: the
 * dashboard stays fully browsable, but every tenant-connect action is
 * disabled until an administrator configures the operator credential in
 * Settings (first-use claim, D-02).
 */
export function CredentialStatusBanner({ gated }: { gated: boolean }) {
  if (!gated) return null;

  return (
    <Alert className="max-w-[32rem]" data-testid="credential-gate-banner">
      <KeyRoundIcon aria-hidden="true" />
      <AlertTitle>Assessments require an operator credential</AlertTitle>
      <AlertDescription>
        Configure it in{" "}
        <a
          href="/dashboard/settings"
          className="underline underline-offset-3 hover:text-foreground"
        >
          Settings
        </a>{" "}
        before connecting a tenant — tenant connect is unavailable until then.
      </AlertDescription>
    </Alert>
  );
}
