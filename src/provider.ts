/**
 * The cryptographic provider contract for @browsercore/crypto.
 *
 * Higher layers depend on this interface — never on a concrete provider — so the
 * backend is replaceable (WebCrypto, HSM, test double). The TLS implementation
 * calls these methods, never `node:crypto` directly.
 *
 * @module
 * @since 0.1.0
 */

import type { EcdhCurve, EcdhKeyPair, HashId, X25519KeyPair } from "./types.js";

/**
 * Pure cryptographic primitive abstraction.
 *
 * Higher layers depend on this interface — never on a concrete provider.
 * Implementations must be side-effect free (no I/O, no global state) so they
 * are unit-testable against synthetic byte streams.
 *
 * @remarks
 * The provider pattern decouples protocol logic from platform I/O. This is
 * what keeps the TLS engine's ClientHello construction purely a function of
 * profile data, not of any backend implementation.
 *
 * @see {@link NodeCryptoProvider} for the default `node:crypto` backend.
 * @since 0.1.0
 */
export interface CryptoProvider {
    /**
     * Generate `length` cryptographically-strong random bytes.
     *
     * @param length Number of random bytes to generate.
     * @returns A fresh `Uint8Array` of the requested length.
     *
     * @example
     * ```ts
     * const nonce = crypto.randomBytes(12);
     * ```
     */
    randomBytes(length: number): Uint8Array;

    /**
     * Compute the SHA-256 digest of `data`.
     *
     * @param data Input bytes to digest.
     * @returns 32-byte SHA-256 digest.
     */
    sha256(data: Uint8Array): Uint8Array;

    /**
     * Compute the SHA-384 digest of `data`.
     *
     * @param data Input bytes to digest.
     * @returns 48-byte SHA-384 digest.
     */
    sha384(data: Uint8Array): Uint8Array;

    /**
     * HKDF extract+expand per RFC 5869, using the given hash.
     *
     * Combines the extract and expand steps into a single call that returns
     * exactly `length` bytes of key material. Used throughout TLS 1.3 for
     * traffic-secret derivation.
     *
     * @param hash   Hash algorithm to use (SHA-256 or SHA-384).
     * @param salt   Optional salt for the extract step — pass an empty array if unused.
     * @param ikm    Input keying material.
     * @param info   Context-specific binding info (e.g. a TLS 1.3 label).
     * @param length Desired output length in bytes.
     * @returns Exactly `length` bytes of derived key material.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc5869 RFC 5869
     */
    hkdf(
        hash: HashId,
        salt: Uint8Array,
        ikm: Uint8Array,
        info: Uint8Array,
        length: number,
    ): Uint8Array;

    /**
     * Compute the HMAC of `data` under `key` using the given hash.
     *
     * @param hash Hash algorithm to use.
     * @param key  Secret key.
     * @param data Data to authenticate.
     * @returns HMAC digest (32 bytes for SHA-256, 48 for SHA-384).
     */
    hmac(hash: HashId, key: Uint8Array, data: Uint8Array): Uint8Array;

    /**
     * AEAD-encrypt with AES-128-GCM.
     *
     * @param key       16-byte AES key.
     * @param nonce     12-byte initialization vector.
     * @param plaintext Data to encrypt.
     * @param aad       Additional authenticated data (not encrypted).
     * @returns Ciphertext with the 16-byte tag appended.
     */
    aes128GcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-decrypt with AES-128-GCM.
     *
     * @param key       16-byte AES key.
     * @param nonce     12-byte initialization vector.
     * @param ciphertext Ciphertext with the 16-byte tag appended.
     * @param aad       Additional authenticated data that was passed to encrypt.
     * @returns Decrypted plaintext.
     * @throws {@link DecryptError} on authentication failure.
     */
    aes128GcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-encrypt with AES-256-GCM.
     *
     * @param key       32-byte AES key.
     * @param nonce     12-byte initialization vector.
     * @param plaintext Data to encrypt.
     * @param aad       Additional authenticated data (not encrypted).
     * @returns Ciphertext with the 16-byte tag appended.
     */
    aes256GcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-decrypt with AES-256-GCM.
     *
     * @param key       32-byte AES key.
     * @param nonce     12-byte initialization vector.
     * @param ciphertext Ciphertext with the 16-byte tag appended.
     * @param aad       Additional authenticated data that was passed to encrypt.
     * @returns Decrypted plaintext.
     * @throws {@link DecryptError} on authentication failure.
     */
    aes256GcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-encrypt with AES-128-CCM.
     *
     * CCM uses the full 16-byte tag in TLS 1.3 (set explicitly at the
     * `node:crypto` options layer).
     *
     * @param key       16-byte AES key.
     * @param nonce     12-byte initialization vector.
     * @param plaintext Data to encrypt.
     * @param aad       Additional authenticated data (not encrypted).
     * @returns Ciphertext with the 16-byte tag appended.
     */
    aes128CcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-decrypt with AES-128-CCM.
     *
     * @param key       16-byte AES key.
     * @param nonce     12-byte initialization vector.
     * @param ciphertext Ciphertext with the 16-byte tag appended.
     * @param aad       Additional authenticated data that was passed to encrypt.
     * @returns Decrypted plaintext.
     * @throws {@link DecryptError} on authentication failure.
     */
    aes128CcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-encrypt with ChaCha20-Poly1305.
     *
     * @param key       32-byte ChaCha20 key.
     * @param nonce     12-byte initialization vector.
     * @param plaintext Data to encrypt.
     * @param aad       Additional authenticated data (not encrypted).
     * @returns Ciphertext with the 16-byte Poly1305 tag appended.
     */
    chacha20Poly1305Encrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * AEAD-decrypt with ChaCha20-Poly1305.
     *
     * @param key       32-byte ChaCha20 key.
     * @param nonce     12-byte initialization vector.
     * @param ciphertext Ciphertext with the 16-byte Poly1305 tag appended.
     * @param aad       Additional authenticated data that was passed to encrypt.
     * @returns Decrypted plaintext.
     * @throws {@link DecryptError} on authentication failure.
     */
    chacha20Poly1305Decrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /**
     * Generate an X25519 key pair.
     *
     * Both coordinates are exactly 32 bytes. The returned secret key MUST be
     * zeroed after use by the caller to prevent leakage.
     *
     * @returns A fresh X25519 key pair.
     *
     * @example
     * ```ts
     * const kp = crypto.x25519GenerateKeyPair();
     * // kp.publicKey.length === 32, kp.secretKey.length === 32
     * ```
     */
    x25519GenerateKeyPair(): X25519KeyPair;

    /**
     * Compute the X25519 shared secret between `secretKey` and `peerPublicKey`.
     *
     * Implements RFC 7748 §5: a degenerate / small-order public key yields
     * the all-zero shared secret rather than throwing.
     *
     * @param secretKey     32-byte local private key.
     * @param peerPublicKey 32-byte remote public key.
     * @returns 32-byte shared secret.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7748 RFC 7748
     */
    x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;

    /**
     * Generate an ECDH key pair on the given named curve.
     *
     * The public key is returned in uncompressed form (`0x04 || x || y`)
     * — exactly the layout TLS 1.3 KeyShareEntry expects.
     *
     * @param curve The named curve to generate on.
     * @returns A fresh ECDH key pair.
     */
    ecdhGenerateKeyPair(curve: EcdhCurve): EcdhKeyPair;

    /**
     * Compute the ECDH shared secret on the given named curve.
     *
     * Returns the x-coordinate of the shared point (32 bytes for secp256r1,
     * 48 for secp384r1) — the raw output that TLS feeds into the key schedule.
     *
     * @param curve         The named curve to compute on.
     * @param secretKey     Local private key (raw scalar, curve-fixed length).
     * @param peerPublicKey Remote public key in uncompressed form (`0x04 || x || y`).
     * @returns The x-coordinate of the shared point.
     */
    ecdhSharedSecret(curve: EcdhCurve, secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;

    /**
     * Verify a digital signature over `data` using the given scheme and public key.
     *
     * The `data` is the raw message bytes that the signature covers (e.g. the
     * TBSCertificate DER for X.509 chain verification, or the TLS 1.3
     * CertificateVerify signed content). The hash step is performed internally
     * by the backend according to `scheme` — callers pass the pre-hash message,
     * never a digest.
     *
     * @param scheme     Signature scheme name (e.g. `"ecdsa_secp256r1_sha256"`,
     *                   `"rsa_pss_rsae_sha256"`, `"rsa_pkcs1_sha256"`).
     * @param publicKey  DER-encoded SubjectPublicKeyInfo of the signer.
     * @param signature  Signature bytes (DER for ECDSA, raw for RSA-PSS/PKCS1).
     * @param data       The message the signature covers (NOT a digest).
     * @returns `true` if the signature is valid, `false` otherwise.
     * @throws {@link UnsupportedAlgorithmError} if the scheme is not recognized.
     *
     * @example
     * ```ts
     * const valid = crypto.verifySignature(
     *   "ecdsa_secp256r1_sha256",
     *   spkiDer,
     *   signature,
     *   tbsCertificate
     * );
     * ```
     */
    verifySignature(
        scheme: string,
        publicKey: Uint8Array,
        signature: Uint8Array,
        data: Uint8Array,
    ): boolean;

    /**
     * AES-ECB encrypt a single 16-byte block.
     *
     * Used by QUIC header protection (RFC 9001 §5.4.1) —
     * `aesEcbEncrypt(hp_key, sample)` produces the 5-byte mask applied to
     * the packet number length and first byte of the header.
     *
     * @remarks
     * Only the AES-128 and AES-256 key sizes (16/32 bytes) are valid; the
     * input block is always 16 bytes and the output is always 16 bytes.
     *
     * @param key   16-byte (AES-128) or 32-byte (AES-256) key.
     * @param block 16-byte input block.
     * @returns 16-byte encrypted block.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc9001 RFC 9001 §5.4.1
     * @since 0.2.0
     */
    aesEcbEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array;
}
