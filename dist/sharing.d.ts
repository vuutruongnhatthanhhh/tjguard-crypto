export type SharedContent = {
    username?: string;
    password?: string;
    website?: string;
    notes?: string;
};
export type SharedEncryptedItem = {
    nonce: string;
    ciphertext: string;
};
/**
 * Seal itemKey for a recipient using their X25519 public key.
 * Wire format: ephemeralPublicKey (32) | nonce (24) | NaCl-box ciphertext
 */
export declare function sealItemKeyForRecipient(itemKey: Uint8Array, recipientPublicKey: Uint8Array): string;
/**
 * Unseal (unwrap) itemKey using the recipient's X25519 private key.
 */
export declare function unsealItemKey(wrappedItemKey_b64: string, recipientPrivateKey: Uint8Array): Uint8Array;
/**
 * Encrypt shared vault content with itemKey.
 * aad = UTF-8 of the owner's email (stays consistent across edits).
 */
export declare function encryptWithItemKey(itemKey: Uint8Array, aad: Uint8Array, content: SharedContent): SharedEncryptedItem;
/**
 * Decrypt shared vault content with itemKey.
 */
export declare function decryptWithItemKey(itemKey: Uint8Array, aad: Uint8Array, item: SharedEncryptedItem): SharedContent;
//# sourceMappingURL=sharing.d.ts.map