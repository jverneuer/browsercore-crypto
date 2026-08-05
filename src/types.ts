/**
 * Domain types for @browsercore/crypto.
 *
 * This package owns NO knowledge of TLS handshakes, key schedules, or wire formats.
 * It is a pure cryptographic primitive abstraction — randomness, hashing, key
 * derivation, AEAD, and key exchange. Higher layers (tls) compose exclusively
 * through these exports.
 *
 * @module
 * @since 0.1.0
 */

import { createId } from "./utils.js";

/**
 * Branded identifier for a derived cryptographic session (e.g. a TLS 1.3 session).
 *
 * The brand prevents accidental assignment of arbitrary strings where a
 * session-scoped identifier is required.
 *
 * @since 0.1.0
 */
export type CryptoSessionId = string & { __brand: "CryptoSessionId" };

/**
 * Build a {@link CryptoSessionId} from a unique seed.
 *
 * Combines a millisecond timestamp and a random suffix to produce a
 * collision-resistant identifier without requiring a CSPRNG.
 *
 * @returns A fresh branded session identifier.
 *
 * @example
 * ```ts
 * const sessionId = createCryptoSessionId();
 * // => "csid_l4k3x2_1a2b3c"
 * ```
 *
 * @since 0.1.0
 */
export function createCryptoSessionId(): CryptoSessionId {
    return createId("csid") as CryptoSessionId;
}

// ---------------------------------------------------------------------------
// Symmetric cipher identifiers — discriminated union.
// ---------------------------------------------------------------------------

/** Branded identifier for the AES-128-GCM cipher. */
export type Aes128GcmId = "AES-128-GCM" & { __brand: "Aes128GcmId" };
/** Branded identifier for the AES-256-GCM cipher. */
export type Aes256GcmId = "AES-256-GCM" & { __brand: "Aes256GcmId" };
/** Branded identifier for the AES-128-CCM cipher. */
export type Aes128CcmId = "AES-128-CCM" & { __brand: "Aes128CcmId" };
/** Branded identifier for the ChaCha20-Poly1305 cipher. */
export type ChaCha20Poly1305Id = "ChaCha20-Poly1305" & { __brand: "ChaCha20Poly1305Id" };

/**
 * Every symmetric AEAD cipher this provider supports.
 *
 * Used to select the algorithm at the {@link CryptoProvider} boundary while
 * preserving exhaustiveness checks in downstream `switch` statements.
 *
 * @since 0.1.0
 */
export type SymmetricCipherId =
    | Aes128GcmId
    | Aes256GcmId
    | Aes128CcmId
    | ChaCha20Poly1305Id;

/**
 * Canonical string literal for each AES-128-GCM usage.
 *
 * Use this constant instead of a raw string literal so that the branded
 * type catches accidental misuse at compile time.
 *
 * @since 0.1.0
 */
export const AES_128_GCM: Aes128GcmId = "AES-128-GCM" as Aes128GcmId;
/**
 * Canonical string literal for each AES-256-GCM usage.
 *
 * @since 0.1.0
 */
export const AES_256_GCM: Aes256GcmId = "AES-256-GCM" as Aes256GcmId;
/**
 * Canonical string literal for each AES-128-CCM usage.
 *
 * @since 0.1.0
 */
export const AES_128_CCM: Aes128CcmId = "AES-128-CCM" as Aes128CcmId;
/**
 * Canonical string literal for each ChaCha20-Poly1305 usage.
 *
 * @since 0.1.0
 */
export const CHACHA20_POLY1305: ChaCha20Poly1305Id = "ChaCha20-Poly1305" as ChaCha20Poly1305Id;

// ---------------------------------------------------------------------------
// Hash identifiers — discriminated union.
// ---------------------------------------------------------------------------

/** Branded identifier for the SHA-256 hash function. */
export type Sha256Id = "SHA-256" & { __brand: "Sha256Id" };
/** Branded identifier for the SHA-384 hash function. */
export type Sha384Id = "SHA-384" & { __brand: "Sha384Id" };

/**
 * Every hash function this provider supports.
 *
 * Passed to {@link CryptoProvider.hkdf} and {@link CryptoProvider.hmac}
 * to select the digest algorithm.
 *
 * @since 0.1.0
 */
export type HashId = Sha256Id | Sha384Id;

/**
 * Canonical string literal for each SHA-256 usage.
 *
 * @since 0.1.0
 */
export const SHA_256: Sha256Id = "SHA-256" as Sha256Id;
/**
 * Canonical string literal for each SHA-384 usage.
 *
 * @since 0.1.0
 */
export const SHA_384: Sha384Id = "SHA-384" as Sha384Id;

// ---------------------------------------------------------------------------
// Key exchange identifiers — discriminated union.
// ---------------------------------------------------------------------------

/** Branded identifier for the X25519 key exchange mechanism. */
export type X25519Id = "X25519" & { __brand: "X25519Id" };

/**
 * Every key exchange mechanism this provider supports.
 *
 * Currently only {@link X25519Id} — the union exists so future post-quantum
 * additions don't ripple through every consumer.
 *
 * @since 0.1.0
 */
export type KeyExchangeId = X25519Id;

/**
 * Canonical string literal for each X25519 usage.
 *
 * @since 0.1.0
 */
export const X25519: X25519Id = "X25519" as X25519Id;

// ---------------------------------------------------------------------------
// ECDH (named-curve) key exchange identifiers.
// ---------------------------------------------------------------------------

/**
 * Named ECDH curves for TLS 1.3 key share.
 *
 * Plain string-literal union (not branded) so it interops cleanly with
 * `@browsercore/tls`'s `NamedGroup` and `KeyPair.algorithm`, which are
 * also plain string unions.
 *
 * @since 0.1.0
 */
export type EcdhCurve = "secp256r1" | "secp384r1";

/**
 * An ECDH key pair on a named curve.
 *
 * Returned by {@link CryptoProvider.ecdhGenerateKeyPair}. The layout
 * matches what TLS 1.3 KeyShareEntry expects on the wire.
 *
 * @since 0.1.0
 */
export interface EcdhKeyPair {
    /** The curve this key pair was generated on. */
    readonly curve: EcdhCurve;
    /**
     * Public key bytes in uncompressed form: `0x04 || x || y`.
     *
     * - secp256r1 → 65 bytes
     * - secp384r1 → 97 bytes
     */
    readonly publicKey: Uint8Array;
    /**
     * Private key bytes (raw scalar, big-endian, curve-fixed length).
     *
     * Left-padded with zero bytes to the curve's canonical length
     * (32 for secp256r1, 48 for secp384r1).
     */
    readonly secretKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// AEAD cipher descriptor — describes the static parameters of a cipher.
// ---------------------------------------------------------------------------

/**
 * Static description of an AEAD cipher's parameters.
 *
 * Concrete ciphers expose this so higher layers can size buffers without
 * hard-coding NIST/IETF constants. Instances are defined in `ciphers.ts`
 * and indexed by {@link SymmetricCipherId} in {@link CIPHER_BY_ID}.
 *
 * @see {@link CIPHER_BY_ID} for the complete cipher table.
 * @since 0.1.0
 */
export interface AeadCipher {
    /** Identifier for this cipher. */
    readonly id: SymmetricCipherId;
    /** Key size in bytes. */
    readonly keySize: number;
    /** Nonce (IV) size in bytes. */
    readonly nonceSize: number;
    /** Authentication tag size in bytes. */
    readonly tagSize: number;
    /**
     * Encrypt `plaintext` under `key`/`nonce`, authenticating `aad`.
     *
     * @param key       Symmetric key — must be exactly {@link keySize} bytes.
     * @param nonce     Initialization vector — must be exactly {@link nonceSize} bytes.
     * @param plaintext Data to encrypt.
     * @param aad       Additional authenticated data (authenticated but not encrypted).
     * @returns Ciphertext with the {@link tagSize}-byte authentication tag appended.
     */
    readonly encrypt: (
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ) => Uint8Array;
    /**
     * Decrypt `ciphertext` (with appended tag) under `key`/`nonce`, verifying `aad`.
     *
     * @param key       Symmetric key — must be exactly {@link keySize} bytes.
     * @param nonce     Initialization vector — must be exactly {@link nonceSize} bytes.
     * @param ciphertext Ciphertext with the {@link tagSize}-byte tag appended.
     * @param aad       Additional authenticated data that was passed to encrypt.
     * @returns Decrypted plaintext.
     * @throws {@link DecryptError} on authentication failure (wrong key, tampered ciphertext, or corrupt tag).
     */
    readonly decrypt: (
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ) => Uint8Array;
}

/**
 * An X25519 key pair.
 *
 * Returned by {@link CryptoProvider.x25519GenerateKeyPair}. The secret key
 * MUST be zeroed after use by the caller to prevent leakage.
 *
 * @since 0.1.0
 */
export interface X25519KeyPair {
    /** Public key — 32 bytes. */
    readonly publicKey: Uint8Array;
    /** Secret key — 32 bytes. Zero after use. */
    readonly secretKey: Uint8Array;
}
