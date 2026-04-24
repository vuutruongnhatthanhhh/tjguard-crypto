# TJGuard Crypto Specification

This document describes the end-to-end encryption scheme used by TJGuard.
All cryptographic operations run entirely on the client — the server never
sees plaintext passwords or raw keys.

---

## 1. Primitives

| Primitive          | Purpose                                   |
| ------------------ | ----------------------------------------- |
| Argon2id           | Master password → KEK derivation          |
| HKDF-SHA-256       | Account key → per-item key derivation     |
| XChaCha20-Poly1305 | Authenticated encryption of vault content |
| X25519 + NaCl box  | Key wrapping for vault sharing            |

---

## 2. Key Hierarchy

```
Master Password + KDF Salt
        │  Argon2id (t=3, m=128MB, p=1)
        ▼
      KEK (32 bytes)
        │  unwrap (AES-256-GCM, stored server-side)
        ▼
   Account Key (32 bytes)  ─────────────────────────────┐
        │  HKDF-SHA-256                                  │
        │  ikm = accountKey                              │
        │  salt = random 16 bytes (hkdf_salt)            │
        │  info = "tjguard:item:v1"                      │
        ▼                                                │
   Item Key (32 bytes)                           NaCl box keypair
        │  XChaCha20-Poly1305                   (X25519, derived
        ▼  nonce=24 bytes, AAD=owner email)      from accountKey)
   Ciphertext
```

---

## 3. Vault Item Encryption (v1 — owner only)

1. Generate random `hkdf_salt` (16 bytes).
2. Derive `itemKey = HKDF-SHA-256(accountKey, hkdf_salt, "tjguard:item:v1")`.
3. Serialize content as JSON: `{ username, password, website, notes }`.
4. Encrypt: `ciphertext = XChaCha20-Poly1305(itemKey, nonce, plaintext, AAD=email)`.
5. Store on server: `{ hkdf_salt, nonce, ciphertext }` — all base64url encoded.

---

## 4. Vault Item Sharing (v2 — multi-recipient)

Sharing introduces a `wrapped_item_key` per recipient so each member can
independently decrypt using only their own X25519 private key.

### Wrap (owner side)

1. Derive `itemKey` as above.
2. For each recipient (including owner themselves):
   - Generate ephemeral X25519 keypair.
   - `wrapped = NaCl.box(itemKey, nonce, recipientPublicKey, ephSecretKey)`.
   - Wire format: `ephPublicKey (32) | nonce (24) | ciphertext` → base64url.
3. Store a `vault_members` row per recipient with their `wrapped_item_key`.

### Unwrap (recipient side)

1. Fetch `wrapped_item_key` from their `vault_members` row.
2. `itemKey = NaCl.box.open(cipher, nonce, ephPublicKey, recipientPrivateKey)`.
3. Decrypt ciphertext using `itemKey` + AAD = owner's email.

### Shared Edit

When a member (editor) updates content:

- `hkdf_salt` stays **unchanged** — so all `wrapped_item_key` values remain valid.
- Only `nonce` and `ciphertext` are replaced.
- AAD is always the **owner's email**, never the editor's.

---

## 5. Encoding

All binary values are encoded as **base64url** (RFC 4648 §5, no padding).

---

## 6. Parameter Choices

| Parameter           | Value               | Reason                                        |
| ------------------- | ------------------- | --------------------------------------------- |
| Argon2id memory     | 128 MB              | OWASP recommendation for interactive logins   |
| Argon2id iterations | 3                   | Balance of security and UX on low-end devices |
| HKDF info           | `"tjguard:item:v1"` | Domain separation, versioned                  |
| XChaCha20 nonce     | 24 bytes random     | Large nonce space, safe for random generation |
| NaCl box nonce      | 24 bytes random     | Standard TweetNaCl parameter                  |
