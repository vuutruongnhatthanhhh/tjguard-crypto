import { argon2id as argon2idHash } from "hash-wasm";

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToB64url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);

  const b64 =
    typeof window === "undefined"
      ? Buffer.from(bin, "binary").toString("base64")
      : btoa(bin);

  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function b64urlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? 4 - (b64.length % 4) : 0;

  const bin =
    typeof window === "undefined"
      ? Buffer.from(b64 + "=".repeat(pad), "base64").toString("binary")
      : atob(b64 + "=".repeat(pad));

  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export async function deriveKEK(
  masterPassword: string,
  kdfSaltB64url: string,
): Promise<Uint8Array> {
  const salt = b64urlToBytes(kdfSaltB64url);

  const res = await argon2idHash({
    password: utf8(masterPassword),
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 128 * 1024,
    hashLength: 32,
    outputType: "binary",
  });

  return res as Uint8Array;
}

export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  len = 32,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    ikm as unknown as ArrayBuffer,
    "HKDF",
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as unknown as ArrayBuffer,
      info: info as unknown as ArrayBuffer,
    },
    baseKey,
    len * 8,
  );

  return new Uint8Array(bits);
}
