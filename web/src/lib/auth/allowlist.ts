/**
 * Operator admin allowlist for sensitive settings (D-05 rotation).
 * Reads OPERATOR_ADMIN_EMAILS env var (comma/semicolon/space separated).
 * Case-insensitive, trimmed. Empty = no restriction (dev fallback).
 */
export function getOperatorAdminEmails(): Set<string> {
  const raw = process.env.OPERATOR_ADMIN_EMAILS ?? "";
  const parts = raw
    .split(/[,;\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return new Set(parts);
}

export function isOperatorAdmin(email?: string | null): boolean {
  const allow = getOperatorAdminEmails();
  if (allow.size === 0) return true; // no allowlist configured → allow (dev)
  if (!email) return false;
  return allow.has(email.trim().toLowerCase());
}
