import crypto from "node:crypto";

/**
 * AES-256-GCM application-layer encryption for tokens at rest (T-02-01).
 *
 * Ciphertext envelope format (versioned prefix for future key rotation):
 *   v1.<iv-base64>.<tag-base64>.<ciphertext-base64>
 *
 * Key material comes from the ENCRYPTION_KEY env var — hex or base64,
 * decoding to exactly 32 bytes. The key is never committed to the repo.
 */

const KEY_LENGTH = 32; // bytes — AES-256
const IV_LENGTH = 12; // bytes — GCM standard IV
const AUTH_TAG_LENGTH = 16; // bytes

function loadKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw || raw.length === 0) {
    throw new Error(
      "ENCRYPTION_KEY is not set. Generate one with: openssl rand -hex 32",
    );
  }

  let key: Buffer;
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length === KEY_LENGTH * 2) {
    key = Buffer.from(raw, "hex");
  } else {
    key = Buffer.from(raw, "base64");
  }

  if (key.length !== KEY_LENGTH) {
    throw new Error(
      `ENCRYPTION_KEY must decode to exactly ${KEY_LENGTH} bytes (got ${key.length}). Generate one with: openssl rand -hex 32`,
    );
  }
  return key;
}

export function encryptString(plaintext: string): string {
  const key = loadKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [
    "v1",
    iv.toString("base64"),
    tag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(".");
}

export function decryptString(envelope: string): string {
  const key = loadKey();
  const parts = envelope.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error(
      'Invalid ciphertext envelope: expected format "v1.<iv>.<tag>.<ciphertext>"',
    );
  }
  try {
    const iv = Buffer.from(parts[1], "base64");
    const tag = Buffer.from(parts[2], "base64");
    const ciphertext = Buffer.from(parts[3], "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
  } catch (err) {
    throw new Error(
      "Decryption failed: wrong key or tampered ciphertext (GCM auth failure)",
      { cause: err },
    );
  }
}
