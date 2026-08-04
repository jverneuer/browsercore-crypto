/**
 * Domain types for @browsercore/crypto.
 *
 * This package owns NO knowledge of TLS handshakes, key schedules, or wire formats.
 * It is a pure cryptographic primitive abstraction — randomness, hashing, key
 * derivation, AEAD, and key exchange. Higher layers (tls) compose exclusively
 * through these exports.
 */
import { createId } from "./utils.js";
/** Build a {@link CryptoSessionId} from a unique seed. */
export function createCryptoSessionId() {
    return createId("csid");
}
/** Canonical string literal for each AES-128-GCM usage. */
export const AES_128_GCM = "AES-128-GCM";
/** Canonical string literal for each AES-256-GCM usage. */
export const AES_256_GCM = "AES-256-GCM";
/** Canonical string literal for each AES-128-CCM usage. */
export const AES_128_CCM = "AES-128-CCM";
/** Canonical string literal for each ChaCha20-Poly1305 usage. */
export const CHACHA20_POLY1305 = "ChaCha20-Poly1305";
/** Canonical string literal for each SHA-256 usage. */
export const SHA_256 = "SHA-256";
/** Canonical string literal for each SHA-384 usage. */
export const SHA_384 = "SHA-384";
/** Canonical string literal for each X25519 usage. */
export const X25519 = "X25519";
//# sourceMappingURL=types.js.map