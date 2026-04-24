export type VaultContent = {
    username?: string;
    password?: string;
    website?: string;
    notes?: string;
};
export type EncryptedItem = {
    hkdf_salt: string;
    nonce: string;
    ciphertext: string;
};
/**
 * Encrypt vault content with the account key.
 * aad = UTF-8 of the owner's email.
 * Returns encrypted blobs + itemKey (needed if you'll share this item).
 */
export declare function encryptItem(accountKey: Uint8Array, aad: Uint8Array, content: VaultContent): Promise<EncryptedItem & {
    itemKey: Uint8Array;
}>;
/**
 * Decrypt vault content with the account key.
 * aad must match exactly what was used during encryption.
 */
export declare function decryptItem(accountKey: Uint8Array, aad: Uint8Array, item: EncryptedItem): Promise<VaultContent>;
/**
 * Re-derive itemKey from accountKey + stored hkdf_salt.
 * Used when editing a shared item (salt must stay the same).
 */
export declare function deriveItemKey(accountKey: Uint8Array, hkdf_salt_b64: string): Promise<Uint8Array>;
/**
 * Re-encrypt content for a shared item edit.
 * hkdf_salt stays unchanged so existing wrapped_item_keys remain valid.
 */
export declare function reEncryptSharedItem(itemKey: Uint8Array, aad: Uint8Array, content: VaultContent): {
    nonce: string;
    ciphertext: string;
};
//# sourceMappingURL=vault.d.ts.map