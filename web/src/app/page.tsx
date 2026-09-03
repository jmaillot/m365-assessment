import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * S1 — Sign-in screen (UI-SPEC): centered card on dominant background,
 * product name in Display role, single primary CTA "Sign in with Microsoft"
 * anchoring to /api/auth/signin, helper line, and inline rejection/notice
 * alerts driven by auth-redirect params.
 */

const SESSION_EXPIRED_COPY = "Your session ended. Please sign in again.";
const ACCOUNT_TYPE_COPY =
  "This app only supports work or school accounts. Please sign in with your organization's Entra ID account and try again.";
const HELPER_LINE =
  "Use your work or school account. Personal Microsoft accounts are not supported.";

/** Four-square Microsoft logo mark (inline SVG, no external fetch). */
function MicrosoftMark({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 21 21"
      role="img"
      aria-label="Microsoft"
      focusable="false"
    >
      <rect x="0" y="0" width="10" height="10" fill="#f25022" />
      <rect x="11" y="0" width="10" height="10" fill="#7fba00" />
      <rect x="0" y="11" width="10" height="10" fill="#00a4ef" />
      <rect x="11" y="11" width="10" height="10" fill="#ffb900" />
    </svg>
  );
}

export default async function Home({ searchParams }: PageProps<"/">) {
  const { notice, error } = await searchParams;
  const showSessionExpired = notice === "session_expired";
  const showAccountTypeError = error === "account_type";

  return (
    <main className="flex min-h-screen flex-1 flex-col items-center justify-center gap-md bg-background p-md">
      {showSessionExpired ? (
        <Alert className="w-full max-w-sm">
          <AlertTitle>Session ended</AlertTitle>
          <AlertDescription>{SESSION_EXPIRED_COPY}</AlertDescription>
        </Alert>
      ) : null}
      {showAccountTypeError ? (
        <Alert variant="destructive" className="w-full max-w-sm">
          <AlertTitle>Account type not supported</AlertTitle>
          <AlertDescription>{ACCOUNT_TYPE_COPY}</AlertDescription>
        </Alert>
      ) : null}

      <Card className="w-full max-w-sm">
        <CardHeader className="items-center gap-y-xs text-center">
          <CardTitle className="text-[28px] leading-tight font-semibold tracking-tight">
            M365-Assess
          </CardTitle>
          <CardDescription>
            Multi-tenant M365 security assessments
          </CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center">
          {/* Full-page redirect to Entra; the route owns the OIDC handshake. */}
          <a href="/api/auth/signin">
            <Button type="button" data-icon="inline-start">
              <MicrosoftMark className="size-4 shrink-0 rounded-[2px]" />
              Sign in with Microsoft
            </Button>
          </a>
        </CardContent>
        <CardFooter className="justify-center text-center">
          <p className="text-sm text-muted-foreground">{HELPER_LINE}</p>
        </CardFooter>
      </Card>
    </main>
  );
}
