import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import nacl from "tweetnacl";
import { utf8, bytesToB64url, b64urlToBytes, randomBytes } from "./helpers";
/**
 * Seal itemKey for a recipient using their X25519 public key.
 * Wire format: ephemeralPublicKey (32) | nonce (24) | NaCl-box ciphertext
 */
export function sealItemKeyForRecipient(itemKey, recipientPublicKey) {
    const eph = nacl.box.keyPair();
    const nonce = randomBytes(nacl.box.nonceLength); // 24 bytes
    const cipher = nacl.box(itemKey, nonce, recipientPublicKey, eph.secretKey);
    const packed = new Uint8Array(eph.publicKey.length + nonce.length + cipher.length);
    packed.set(eph.publicKey, 0);
    packed.set(nonce, eph.publicKey.length);
    packed.set(cipher, eph.publicKey.length + nonce.length);
    return bytesToB64url(packed);
}
/**
 * Unseal (unwrap) itemKey using the recipient's X25519 private key.
 */
export function unsealItemKey(wrappedItemKey_b64, recipientPrivateKey) {
    const packed = b64urlToBytes(wrappedItemKey_b64);
    const pubLen = nacl.box.publicKeyLength; // 32
    const nonceLen = nacl.box.nonceLength; // 24
    if (packed.length <= pubLen + nonceLen)
        throw new Error("WRAPPED_ITEM_KEY_INVALID");
    const ephPub = packed.slice(0, pubLen);
    const nonce = packed.slice(pubLen, pubLen + nonceLen);
    const cipher = packed.slice(pubLen + nonceLen);
    const itemKey = nacl.box.open(cipher, nonce, ephPub, recipientPrivateKey);
    if (!itemKey)
        throw new Error("UNWRAP_ITEM_KEY_FAILED");
    return itemKey;
}
/**
 * Encrypt shared vault content with itemKey.
 * aad = UTF-8 of the owner's email (stays consistent across edits).
 */
export function encryptWithItemKey(itemKey, aad, content) {
    const aead = new XChaCha20Poly1305(itemKey);
    const nonce = randomBytes(24);
    const ct = aead.seal(nonce, utf8(JSON.stringify(content)), aad);
    return {
        nonce: bytesToB64url(nonce),
        ciphertext: bytesToB64url(ct),
    };
}
/**
 * Decrypt shared vault content with itemKey.
 */
export function decryptWithItemKey(itemKey, aad, item) {
    const aead = new XChaCha20Poly1305(itemKey);
    const pt = aead.open(b64urlToBytes(item.nonce), b64urlToBytes(item.ciphertext), aad);
    if (!pt)
        throw new Error("DECRYPT_FAIL");
    return JSON.parse(new TextDecoder().decode(pt));
}
