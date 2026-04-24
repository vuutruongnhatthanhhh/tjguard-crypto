export declare function utf8(s: string): Uint8Array;
export declare function bytesToB64url(bytes: Uint8Array): string;
export declare function b64urlToBytes(b64url: string): Uint8Array;
export declare function randomBytes(n: number): Uint8Array;
export declare function deriveKEK(masterPassword: string, kdfSaltB64url: string): Promise<Uint8Array>;
export declare function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len?: number): Promise<Uint8Array>;
//# sourceMappingURL=helpers.d.ts.map