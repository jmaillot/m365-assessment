import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { encryptString, decryptString } from "./encrypt";

// 32 bytes of key material as hex (AES-256 requires exactly 32 bytes)
const KEY_HEX = "a".repeat(64);
const KEY_B64 = Buffer.alloc(32, 7).toString("base64");

describe("encryptString / decryptString", () => {
  beforeEach(() => {
    process.env.ENCRYPTION_KEY = KEY_HEX;
  });

  afterEach(() => {
    delete process.env.ENCRYPTION_KEY;
  });

  it("round-trips: decryptString(encryptString(plaintext)) === plaintext", () => {
    const plaintext =
      "M.C5xx-very-long-oauth-refresh-token!with~special$chars & symbols=+/=";
    const ciphertext = encryptString(plaintext);
    expect(ciphertext).not.toContain(plaintext);
    expect(decryptString(ciphertext)).toBe(plaintext);
  });

  it("round-trips empty string", () => {
    const ciphertext = encryptString("");
    expect(decryptString(ciphertext)).toBe("");
  });

  it("produces different ciphertexts for the same plaintext (random IV)", () => {
    const plaintext = "same-refresh-token";
    const a = encryptString(plaintext);
    const b = encryptString(plaintext);
    expect(a).not.toBe(b);
    // both must still decrypt back
    expect(decryptString(a)).toBe(plaintext);
    expect(decryptString(b)).toBe(plaintext);
  });

  it("throws when decrypted with the wrong key (GCM auth failure)", () => {
    const ciphertext = encryptString("secret-token");
    process.env.ENCRYPTION_KEY = "b".repeat(64); // different valid-size key
    expect(() => decryptString(ciphertext)).toThrow();
  });

  it("ciphertext uses the versioned v1 envelope format", () => {
    const ciphertext = encryptString("payload");
    const parts = ciphertext.split(".");
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe("v1");
    // iv and tag must be valid base64
    expect(Buffer.from(parts[1], "base64")).toHaveLength(12); // GCM standard IV
    expect(Buffer.from(parts[2], "base64")).toHaveLength(16); // GCM auth tag
  });

  it("accepts a base64-encoded 32-byte ENCRYPTION_KEY", () => {
    process.env.ENCRYPTION_KEY = KEY_B64;
    const ciphertext = encryptString("b64-key-secret");
    expect(decryptString(ciphertext)).toBe("b64-key-secret");
  });

  it("throws a descriptive error when ENCRYPTION_KEY is absent", () => {
    delete process.env.ENCRYPTION_KEY;
    expect(() => encryptString("x")).toThrow(/ENCRYPTION_KEY/);
  });

  it("throws when ENCRYPTION_KEY is not 32 bytes", () => {
    process.env.ENCRYPTION_KEY = "tooshort";
    expect(() => encryptString("x")).toThrow(/32 bytes/);
  });
});
