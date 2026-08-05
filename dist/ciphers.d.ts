/**
 * Concrete {@link AeadCipher} descriptors for @browsercore/crypto.
 *
 * These are thin wrappers over the node:crypto AEAD primitives (imported from
 * `crypto.ts` — this file does NOT import `node:crypto` itself). Higher layers
 * size buffers from `keySize`/`nonceSize`/`tagSize` instead of hard-coding the
 * NIST/IETF constants.
 *
 * Constants used here are the standard, fixed values for these ciphers:
 *  - AES (FIPS 197 / NIST SP 800-38D): 128-bit key = 16 bytes, 256-bit key =
 *    32 bytes; GCM nonce = 12 bytes (96-bit, the recommended/IV length); GCM tag
 *    = 16 bytes (the maximum, and what node:crypto always emits).
 *  - AES-128-CCM (RFC 6655 / NIST SP 800-38C): key = 16 bytes; nonce = 12 bytes
 *    (the TLS 1.3 write_iv length — node:crypto accepts 7-13); tag = 16 bytes
 *    (the full-length tag TLS 1.3 uses).
 *  - ChaCha20-Poly1305 (RFC 8439): key = 32 bytes (256-bit); nonce = 12 bytes
 *    (96-bit IETF variant); Poly1305 tag = 16 bytes.
 */
import { type AeadCipher } from "./types.js";
/** AES-128-GCM: 16-byte key, 12-byte nonce, 16-byte tag (NIST SP 800-38D). */
export declare const aes128Gcm: AeadCipher;
/** AES-256-GCM: 32-byte key, 12-byte nonce, 16-byte tag (NIST SP 800-38D). */
export declare const aes256Gcm: AeadCipher;
/** AES-128-CCM: 16-byte key, 12-byte nonce, 16-byte tag (RFC 6655 / NIST SP 800-38C). */
export declare const aes128Ccm: AeadCipher;
/** ChaCha20-Poly1305: 32-byte key, 12-byte nonce, 16-byte tag (RFC 8439). */
export declare const chacha20Poly1305: AeadCipher;
/**
 * Every supported {@link AeadCipher}, indexed by {@link SymmetricCipherId}.
 * `satisfies` checks that every branded id maps to a descriptor (so adding a
 * cipher forces an entry here) while preserving the literal key types.
 */
export declare const CIPHER_BY_ID: {
    [x: string]: AeadCipher;
};
//# sourceMappingURL=ciphers.d.ts.map