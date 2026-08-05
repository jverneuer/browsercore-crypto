/**
 * AEAD encryption/decryption backed by node:crypto's GCM/ChaCha20-Poly1305 ciphers.
 *
 * Ciphertext is returned with the 16-byte authentication tag appended, matching the
 * CryptoProvider contract. These primitives are shared by the NodeCryptoProvider
 * methods and the concrete AeadCipher descriptors in ciphers.ts, so neither module
 * imports node:crypto directly for AEAD.
 */
import { type SymmetricCipherId } from "./types.js";
/**
 * AEAD-encrypt with a node:crypto cipher. Returns ciphertext with the 16-byte
 * authentication tag appended, matching the CryptoProvider contract.
 *
 * The options argument is passed conditionally: AES-CCM requires an explicit
 * `authTagLength`, while GCM and ChaCha20-Poly1305 use node's default. Passing
 * `undefined` explicitly trips up TypeScript's overload resolution for
 * `createCipheriv`, so we branch on the options presence instead.
 */
export declare function aeadEncrypt(cipher: SymmetricCipherId, key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array;
/**
 * AEAD-decrypt with a node:crypto cipher. Expects ciphertext with the 16-byte
 * tag appended. Throws {@link DecryptError} on authentication failure.
 */
export declare function aeadDecrypt(cipher: SymmetricCipherId, key: Uint8Array, nonce: Uint8Array, ciphertextAndTag: Uint8Array, aad: Uint8Array): Uint8Array;
//# sourceMappingURL=aead.d.ts.map