import crypto from "node:crypto";

import { cookies } from "next/headers";
import { and, eq, gt, lt } from "drizzle-orm";

import { db } from "@/db";
import { sessions, users } from "@/db/schema";
import { secureCookies } from "./entra-client";

/**
 * D-03: server-side SQLite-backed sessions referenced by an httpOnly,
 * SameSite=Lax, Secure-in-production cookie. No JWT ever reaches the browser.
 * Session ids are random 32-byte hex values — not derivable, not encrypted
 * (they are opaque references, not secrets needing reversibility).
 */

export const SESSION_COOKIE = "m365a_session";

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

export interface SessionUser {
  id: string;
  email: string;
  displayName: string;
}

export async function createSession(userId: string): Promise<void> {
  const id = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await db.insert(sessions).values({ id, userId, expiresAt });

  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE, id, {
    httpOnly: true,
    sameSite: "lax",
    secure: secureCookies(),
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

/** Resolve the current user from the session cookie; null on miss/expiry. */
export async function getSession(): Promise<{
  user: SessionUser | null;
}> {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  if (!sessionId) return { user: null };

  const rows = await db
    .select({
      userId: users.id,
      email: users.email,
      displayName: users.displayName,
      expiresAt: sessions.expiresAt,
    })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(and(eq(sessions.id, sessionId), gt(sessions.expiresAt, new Date())))
    .limit(1);

  const row = rows[0];
  if (!row) {
    // Lazily delete an expired row if one lingers past its expiry.
    await db.delete(sessions).where(
      and(eq(sessions.id, sessionId), lt(sessions.expiresAt, new Date())),
    );
    return { user: null };
  }

  return {
    user: {
      id: row.userId,
      email: row.email,
      displayName: row.displayName,
    },
  };
}

/** Delete the server session row and clear the cookie. */
export async function destroySession(): Promise<void> {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  if (sessionId) {
    await db.delete(sessions).where(eq(sessions.id, sessionId));
  }
  cookieStore.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: secureCookies(),
    path: "/",
    maxAge: 0,
  });
}
