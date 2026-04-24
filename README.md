# tjguard-crypto

Cryptographic primitives powering [TJGuard](https://tjguard.com) — a zero-knowledge password manager.

All operations run entirely on the client. The server stores only ciphertext and never sees plaintext passwords or raw keys.

---

## Scheme overview

```
Master Password
    │  Argon2id (t=3, m=128MB, p=1)
    ▼
  KEK (32 bytes)
    │  unwrap
    ▼
Account Key (32 bytes)
    │  HKDF-SHA-256  (info = "tjguard:item:v1")
    ▼
Item Key (32 bytes)
    │  XChaCha20-Poly1305  (AAD = owner email)
    ▼
Ciphertext
```

For vault sharing, item keys are wrapped per-recipient using **X25519 + NaCl box** so each member decrypts independently with their own private key.

Full specification: [SPEC.md](./SPEC.md)

---

## Install

```bash
npm install tjguard-crypto
```

---

## Usage

### Derive KEK from master password

```ts
import { deriveKEK } from "tjguard-crypto";

const kek = await deriveKEK(masterPassword, kdfSaltB64url);
```

### Encrypt / decrypt a vault item

```ts
import { encryptItem, decryptItem, utf8 } from "tjguard-crypto";

const aad = utf8(ownerEmail);

const encrypted = await encryptItem(accountKey, aad, {
  username: "alice",
  password: "hunter2",
  website: "https://example.com",
});
// encrypted.hkdf_salt, encrypted.nonce, encrypted.ciphertext → store on server
// encrypted.itemKey → use if sharing this item

const content = await decryptItem(accountKey, aad, encrypted);
// { username: "alice", password: "hunter2", ... }
```

### Share a vault item

```ts
import {
  sealItemKeyForRecipient,
  unsealItemKey,
  decryptWithItemKey,
} from "tjguard-crypto";

// Owner: wrap itemKey for each recipient
const wrapped = sealItemKeyForRecipient(itemKey, recipientPublicKey);
// store `wrapped` in vault_members row for that recipient

// Recipient: unwrap and decrypt
const itemKey = unsealItemKey(wrappedItemKeyB64url, myPrivateKey);
const content = decryptWithItemKey(itemKey, utf8(ownerEmail), {
  nonce,
  ciphertext,
});
```

### Generate a password

```ts
import { generatePassword } from "tjguard-crypto";

const password = generatePassword(20);
// e.g. "aB3!xK9@mQr#vT6&nYwZ"
```

---

## API

### `helpers.ts`

| Function                                   | Description                       |
| ------------------------------------------ | --------------------------------- |
| `deriveKEK(masterPassword, kdfSaltB64url)` | Argon2id derivation → 32-byte KEK |
| `hkdfSha256(ikm, salt, info, len?)`        | HKDF-SHA-256 key derivation       |
| `randomBytes(n)`                           | Cryptographically random bytes    |
| `utf8(s)`                                  | String → Uint8Array               |
| `bytesToB64url(bytes)`                     | Uint8Array → base64url string     |
| `b64urlToBytes(b64url)`                    | base64url string → Uint8Array     |

### `vault.ts`

| Function                                     | Description                                         |
| -------------------------------------------- | --------------------------------------------------- |
| `encryptItem(accountKey, aad, content)`      | Encrypt vault content, returns ciphertext + itemKey |
| `decryptItem(accountKey, aad, item)`         | Decrypt vault content                               |
| `deriveItemKey(accountKey, hkdf_salt_b64)`   | Re-derive itemKey from stored salt                  |
| `reEncryptSharedItem(itemKey, aad, content)` | Re-encrypt for shared item edit (salt unchanged)    |

### `sharing.ts`

| Function                                               | Description                                      |
| ------------------------------------------------------ | ------------------------------------------------ |
| `sealItemKeyForRecipient(itemKey, recipientPublicKey)` | Wrap itemKey for a recipient (X25519 + NaCl box) |
| `unsealItemKey(wrapped_b64, recipientPrivateKey)`      | Unwrap itemKey                                   |
| `encryptWithItemKey(itemKey, aad, content)`            | Encrypt with unwrapped itemKey                   |
| `decryptWithItemKey(itemKey, aad, item)`               | Decrypt with unwrapped itemKey                   |

### `password.ts`

| Function                                               | Description                                   |
| ------------------------------------------------------ | --------------------------------------------- |
| `generatePassword(length?)`                            | Generate a random password (default 12 chars) |
| `hasLower / hasUpper / hasDigit / hasSpecial / minLen` | Password strength validators                  |

---

## Dependencies

| Package                                                                  | Purpose                        |
| ------------------------------------------------------------------------ | ------------------------------ |
| [`hash-wasm`](https://github.com/nicktindall/hash-wasm)                  | Argon2id via WebAssembly       |
| [`@stablelib/xchacha20poly1305`](https://github.com/StableLib/stablelib) | XChaCha20-Poly1305 AEAD        |
| [`tweetnacl`](https://github.com/dchest/tweetnacl-js)                    | X25519 key exchange + NaCl box |

---

## License

MIT © [TJGuard](https://tjguard.com)
