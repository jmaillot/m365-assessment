"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  CircleCheckIcon,
  KeyRoundIcon,
  LoaderCircleIcon,
  LockIcon,
  RotateCwIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

/**
 * Operator credential setup wizard (D-02, D-05) — the human-facing half of
 * the operator credential model (plans 02-04 storage/API + this UI).
 *
 * FIRST-USE (D-02): while no credential is configured the wizard renders a
 * password-type entry form for the app registration's client secret and
 * POSTs it to /api/settings/operator-credential. The server owns the claim
 * (transactional INSERT-if-absent); a 409 `already_configured` — e.g. a
 * replay or a second administrator winning the race — flips the wizard to
 * the locked status card instead of overwriting anything.
 *
 * ROTATION (D-05 "wizard re-entry anytime"): when configured, the wizard
 * shows a status card (configuredAt + masked reference — NEVER the secret)
 * with an explicit Rotate affordance: confirm dialog → DELETE → entry form
 * for the new secret → POST. On DELETE 404 nothing was configured, so the
 * plain entry form is shown.
 *
 * Secret-handling discipline (T-02-11b): password-type input, value cleared
 * immediately after submit, never rendered, logged, or echoed anywhere.
 */

export interface OperatorCredentialWizardProps {
  /** Server-read initial state (getOperatorCredentialStatus). */
  initialConfigured: boolean;
  initialConfiguredAt?: number;
}

const SETUP_DOCS_HREF = "/docs/web/APP-REGISTRATION-SETUP.md";

const ENTRY_TITLE = "Operator credential";
const ENTRY_DESCRIPTION =
  "Paste the client secret of your app registration. M365-Assess encrypts it (AES-256-GCM) and uses it only to run read-only assessments against consented tenants.";
const LOCKED_COPY = "Credential already configured by another administrator";
const NETWORK_ERROR_COPY =
  "We couldn't reach the server. Check your connection and try again.";

function formatConfiguredAt(timestampMs: number): string {
  return new Date(timestampMs).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function OperatorCredentialWizard({
  initialConfigured,
  initialConfiguredAt,
}: OperatorCredentialWizardProps) {
  const router = useRouter();
  const [configured, setConfigured] = useState(initialConfigured);
  const [configuredAt, setConfiguredAt] = useState<number | undefined>(
    initialConfiguredAt,
  );
  const [justSaved, setJustSaved] = useState(false);
  const [secret, setSecret] = useState("");
  const [pending, setPending] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [rotatePending, setRotatePending] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (secret.trim().length === 0 || pending) return;

    setPending(true);
    try {
      const response = await fetch("/api/settings/operator-credential", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientSecret: secret }),
      });
      // Clear the secret immediately after submit — never echo it anywhere.
      setSecret("");

      if (response.status === 409) {
        // Lost the first-use claim (or replay): reflect the server verdict.
        toast.info(LOCKED_COPY);
        setJustSaved(false);
        setConfigured(true);
        router.refresh();
        return;
      }
      if (response.status === 401) {
        router.push("/?notice=session_expired");
        return;
      }
      if (!response.ok) {
        throw new Error(`save failed (${response.status})`);
      }

      setConfigured(true);
      setConfiguredAt(Date.now());
      setJustSaved(true);
      router.refresh();
    } catch {
      toast.error(NETWORK_ERROR_COPY);
    } finally {
      setPending(false);
    }
  }

  async function handleRotate() {
    setRotatePending(true);
    try {
      const response = await fetch("/api/settings/operator-credential", {
        method: "DELETE",
      });
      if (response.status === 401) {
        router.push("/?notice=session_expired");
        return;
      }
      if (!response.ok && response.status !== 404) {
        // 404 simply means nothing is configured anymore — fall through to
        // the plain entry form; anything else is a real failure.
        throw new Error(`delete failed (${response.status})`);
      }
      setRotateOpen(false);
      setConfigured(false);
      setConfiguredAt(undefined);
      setJustSaved(false);
      router.refresh();
    } catch {
      toast.error(NETWORK_ERROR_COPY);
    } finally {
      setRotatePending(false);
    }
  }

  if (!configured) {
    return (
      <Card className="max-w-[32rem]" data-testid="credential-entry-form">
        <CardHeader>
          <CardTitle className="flex items-center gap-sm">
            <KeyRoundIcon aria-hidden="true" />
            {ENTRY_TITLE}
          </CardTitle>
          <CardDescription>{ENTRY_DESCRIPTION}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col gap-lg">
            <div className="flex flex-col gap-xs">
              <label htmlFor="operator-client-secret" className="text-sm font-medium">
                Client secret
              </label>
              {/* Password-type input: the value is never displayed (T-02-11b). */}
              <Input
                id="operator-client-secret"
                type="password"
                name="clientSecret"
                autoComplete="off"
                autoFocus
                placeholder="Client secret value (shown only once in Entra)"
                value={secret}
                onChange={(event) => setSecret(event.target.value)}
                disabled={pending}
                required
              />
              <p className="text-sm text-muted-foreground">
                Need the secret? Steps are in the{" "}
                <a
                  href={SETUP_DOCS_HREF}
                  className="underline underline-offset-3 hover:text-foreground"
                >
                  setup docs
                </a>
                .
              </p>
            </div>
            <div>
              <Button type="submit" disabled={pending || secret.trim().length === 0}>
                {pending ? (
                  <LoaderCircleIcon className="animate-spin" aria-hidden="true" />
                ) : (
                  <KeyRoundIcon aria-hidden="true" />
                )}
                Save credential
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card className="max-w-[32rem]" data-testid="credential-status-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-sm">
            <KeyRoundIcon aria-hidden="true" />
            Operator credential
          </CardTitle>
          <CardDescription>
            An operator credential is configured. Assessments authenticate with
            its encrypted value — the secret itself is never shown again.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-lg">
          {justSaved ? (
            <div
              className="flex items-center gap-sm text-sm text-success"
              role="status"
              data-testid="credential-saved-indicator"
            >
              <CircleCheckIcon aria-hidden="true" />
              Credential saved.
            </div>
          ) : null}
          <dl className="flex flex-col gap-xs text-sm">
            <div className="flex items-center justify-between gap-md">
              <dt className="text-muted-foreground">Configured</dt>
              <dd>{configuredAt ? formatConfiguredAt(configuredAt) : "—"}</dd>
            </div>
            <div className="flex items-center justify-between gap-md">
              <dt className="text-muted-foreground">Secret</dt>
              {/* Masked reference only — the stored value is ciphertext. */}
              <dd className="font-mono" aria-label="Secret value hidden">
                ••••••••
              </dd>
            </div>
          </dl>
          <div>
            <Button variant="outline" onClick={() => setRotateOpen(true)}>
              <RotateCwIcon aria-hidden="true" />
              Rotate credential
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog open={rotateOpen} onOpenChange={setRotateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate operator credential?</DialogTitle>
            <DialogDescription>
              This deletes the stored secret and lets you enter a new one.
              Assessments cannot run until the replacement secret is saved.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            {/* Cancel default-focused: accidental Enter keeps the credential. */}
            <Button
              variant="outline"
              autoFocus
              disabled={rotatePending}
              onClick={() => setRotateOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={rotatePending}
              onClick={() => void handleRotate()}
            >
              {rotatePending ? (
                <LoaderCircleIcon className="animate-spin" aria-hidden="true" />
              ) : (
                <LockIcon aria-hidden="true" />
              )}
              Delete &amp; enter new secret
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
