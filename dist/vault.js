import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import { utf8, bytesToB64url, b64urlToBytes, randomBytes, hkdfSha256, } from "./helpers";
const ITEM_INFO_V1 = utf8("tjguard:item:v1");
/**
 * Encrypt vault content with the account key.
 * aad = UTF-8 of the owner's email.
 * Returns encrypted blobs + itemKey (needed if you'll share this item).
 */
export async function encryptItem(accountKey, aad, content) {
    const hkdfSalt = randomBytes(16);
    const itemKey = await hkdfSha256(accountKey, hkdfSalt, ITEM_INFO_V1, 32);
    const aead = new XChaCha20Poly1305(itemKey);
    const nonce = randomBytes(24);
    const ct = aead.seal(nonce, utf8(JSON.stringify(content)), aad);
    return {
        hkdf_salt: bytesToB64url(hkdfSalt),
        nonce: bytesToB64url(nonce),
        ciphertext: bytesToB64url(ct),
        itemKey,
    };
}
/**
 * Decrypt vault content with the account key.
 * aad must match exactly what was used during encryption.
 */
export async function decryptItem(accountKey, aad, item) {
    const itemKey = await hkdfSha256(accountKey, b64urlToBytes(item.hkdf_salt), ITEM_INFO_V1, 32);
    const aead = new XChaCha20Poly1305(itemKey);
    const pt = aead.open(b64urlToBytes(item.nonce), b64urlToBytes(item.ciphertext), aad);
    if (!pt)
        throw new Error("DECRYPT_FAIL");
    return JSON.parse(new TextDecoder().decode(pt));
}
/**
 * Re-derive itemKey from accountKey + stored hkdf_salt.
 * Used when editing a shared item (salt must stay the same).
 */
export async function deriveItemKey(accountKey, hkdf_salt_b64) {
    return hkdfSha256(accountKey, b64urlToBytes(hkdf_salt_b64), ITEM_INFO_V1, 32);
}
/**
 * Re-encrypt content for a shared item edit.
 * hkdf_salt stays unchanged so existing wrapped_item_keys remain valid.
 */
export function reEncryptSharedItem(itemKey, aad, content) {
    const aead = new XChaCha20Poly1305(itemKey);
    const nonce = randomBytes(24);
    const ct = aead.seal(nonce, utf8(JSON.stringify(content)), aad);
    return {
        nonce: bytesToB64url(nonce),
        ciphertext: bytesToB64url(ct),
    };
}
