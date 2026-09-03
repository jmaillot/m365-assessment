import {
  integer,
  sqliteTable,
  text,
} from "drizzle-orm/sqlite-core";

/**
 * D-10 storage schema (SQLite via Drizzle). Phase 1 tables:
 * users + sessions (Plan 01-03 auth) and tenant_connections (Plan 01-04
 * connect/verify). Phase 2 adds operator_credential (Plan 02-04).
 * Phase 3 adds runs + check_rows (03-CONTEXT D-03).
 */

export const users = sqliteTable("users", {
  id: text("id").primaryKey(), // uuid
  entraObjectId: text("entra_object_id").notNull().unique(),
  email: text("email").notNull(),
  displayName: text("display_name").notNull(),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export const sessions = sqliteTable("sessions", {
  id: text("id").primaryKey(), // random 32-byte hex
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export const tenantConnections = sqliteTable("tenant_connections", {
  id: text("id").primaryKey(),
  // D-06: one account : one tenant — UNIQUE FK enforces it at the DB level.
  userId: text("user_id")
    .notNull()
    .unique()
    .references(() => users.id, { onDelete: "cascade" }),
  tenantId: text("tenant_id").notNull(),
  tenantName: text("tenant_name"),
  primaryDomain: text("primary_domain"),
  // AES-256-GCM ciphertext produced by web/src/lib/crypto/encrypt.ts —
  // NEVER store the plaintext refresh token in this column.
  refreshTokenEnc: text("refresh_token_enc").notNull(),
  verificationJson: text("verification_json"), // VerificationResult JSON
  verifiedAt: integer("verified_at", { mode: "timestamp" }),
  connectedAt: integer("connected_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
});

export const operatorCredential = sqliteTable("operator_credential", {
  id: text("id").primaryKey(),
  // AES-256-GCM ciphertext produced by web/src/lib/crypto/encrypt.ts —
  // NEVER store the plaintext operator client secret in this column.
  secretEnc: text("secret_enc").notNull(),
  // D-01/D-02: exactly one operator-held secret for the whole deployment.
  configuredByAccountId: text("configured_by_account_id").notNull(),
  configuredAt: integer("configured_at")
    .notNull()
    .$defaultFn(() => Date.now()),
});

export const runs = sqliteTable("runs", {
  id: text("id").primaryKey(), // uuid
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  tenantId: text("tenant_id").notNull(), // Entra tenant GUID the run targets
  // D-01 lifecycle: "queued" | "running" | "completed" | "failed".
  // NOT a CHECK constraint — statuses are enforced in run-service so the
  // transition map lives in one place (03-CONTEXT D-03).
  status: text("status").notNull().default("queued"),
  startedAt: integer("started_at", { mode: "timestamp" })
    .notNull()
    .$defaultFn(() => new Date()),
  finishedAt: integer("finished_at", { mode: "timestamp" }), // null until terminal
  // D-04: sanitized reason sentence ONLY (safeErrorMessage output shape) —
  // never raw errors, tokens, or tenant content.
  error: text("error"),
});

export const checkRows = sqliteTable("check_rows", {
  id: text("id").primaryKey(), // uuid
  // D-03: full CheckRow per row, cascade-deleted with its run.
  runId: text("run_id")
    .notNull()
    .references(() => runs.id, { onDelete: "cascade" }),
  sectionId: text("section_id").notNull(),
  // Columns below mirror CheckRow (row-contract.ts) 1:1. All stringly-typed
  // values stay strings (PS AllowEmptyString parity).
  category: text("category").notNull(),
  setting: text("setting").notNull(),
  currentValue: text("current_value").notNull().default(""),
  recommendedValue: text("recommended_value").notNull().default(""),
  status: text("status").notNull(), // SaasStatus six-value vocabulary (D-23)
  skipReason: text("skip_reason"), // mandatory when status = "Skipped"
  checkId: text("check_id").notNull(), // sub-numbered, e.g. "ENTRA-X-001.3"
  remediation: text("remediation").notNull().default(""),
  intentDesign: integer("intent_design", { mode: "boolean" }).notNull().default(false),
  observedValue: text("observed_value"),
  expectedValue: text("expected_value"),
  evidenceSource: text("evidence_source"),
  evidenceTimestamp: text("evidence_timestamp"),
  collectionMethod: text("collection_method"),
  permissionRequired: text("permission_required"),
  confidence: integer("confidence"), // store round(confidence * 100); null = unspecified
  limitations: text("limitations"),
  rowOrder: integer("row_order").notNull(), // emission order within the run
});

export type User = typeof users.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type TenantConnection = typeof tenantConnections.$inferSelect;
export type OperatorCredential = typeof operatorCredential.$inferSelect;
export type Run = typeof runs.$inferSelect;
export type CheckRowRecord = typeof checkRows.$inferSelect;
