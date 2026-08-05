/**
 * The cryptographic provider contract for @browsercore/crypto.
 *
 * Higher layers depend on this interface — never on a concrete provider — so the
 * backend is replaceable (WebCrypto, HSM, test double). The TLS implementation
 * calls these methods, never `node:crypto` directly.
 */

import type { EcdhCurve, EcdhKeyPair, HashId, X25519KeyPair } from "./types.js";

/**
 * Pure cryptographic primitive abstraction. Higher layers depend on this
 * interface — never on a concrete provider.
 */
export interface CryptoProvider {
    /** Generate `length` cryptographically-strong random bytes. */
    randomBytes(length: number): Uint8Array;

    /** Compute the SHA-256 digest of `data`. */
    sha256(data: Uint8Array): Uint8Array;

    /** Compute the SHA-384 digest of `data`. */
    sha384(data: Uint8Array): Uint8Array;

    /**
     * HKDF extract+expand per RFC 5869, using the given hash. Returns exactly
     * `length` bytes of key material.
     */
    hkdf(
        hash: HashId,
        salt: Uint8Array,
        ikm: Uint8Array,
        info: Uint8Array,
        length: number,
    ): Uint8Array;

    /** Compute the HMAC of `data` under `key` using the given hash. */
    hmac(hash: HashId, key: Uint8Array, data: Uint8Array): Uint8Array;

    /** AEAD-encrypt with AES-128-GCM. Ciphertext has the tag appended. */
    aes128GcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-decrypt with AES-128-GCM. Throws {@link DecryptError} on auth failure. */
    aes128GcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-encrypt with AES-256-GCM. Ciphertext has the tag appended. */
    aes256GcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-decrypt with AES-256-GCM. Throws {@link DecryptError} on auth failure. */
    aes256GcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-encrypt with AES-128-CCM. Ciphertext has the tag appended. */
    aes128CcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-decrypt with AES-128-CCM. Throws {@link DecryptError} on auth failure. */
    aes128CcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-encrypt with ChaCha20-Poly1305. Ciphertext has the tag appended. */
    chacha20Poly1305Encrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** AEAD-decrypt with ChaCha20-Poly1305. Throws {@link DecryptError} on auth failure. */
    chacha20Poly1305Decrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array;

    /** Generate an X25519 key pair (32-byte keys). */
    x25519GenerateKeyPair(): X25519KeyPair;

    /**
     * Compute the X25519 shared secret between `secretKey` and `peerPublicKey`.
     * Returns 32 bytes.
     */
    x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;

    /** Generate an ECDH key pair on the given named curve. */
    ecdhGenerateKeyPair(curve: EcdhCurve): EcdhKeyPair;

    /**
     * Compute the ECDH shared secret on the given named curve between `secretKey`
     * and `peerPublicKey` (uncompressed form, 0x04 || x || y). Returns the
     * x-coordinate of the shared point (32 bytes for secp256r1, 48 for secp384r1).
     */
    ecdhSharedSecret(curve: EcdhCurve, secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;

    /**
     * Verify a digital signature over `data` using the given scheme and public key.
     *
     * The `data` is the raw message bytes that the signature covers (e.g. the
     * TBSCertificate DER for X.509 chain verification, or the TLS 1.3
     * CertificateVerify signed content). The hash step is performed internally
     * by node:crypto according to `scheme` — callers pass the pre-hash message,
     * never a digest.
     *
     * @param scheme     Signature scheme name (e.g. "ecdsa_secp256r1_sha256",
     *                   "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256").
     * @param publicKey  DER-encoded SubjectPublicKeyInfo of the signer.
     * @param signature  Signature bytes (DER for ECDSA, raw for RSA-PSS/PKCS1).
     * @param data       The message the signature covers (NOT a digest).
     * @returns true if the signature is valid.
     * @throws UnsupportedAlgorithmError if the scheme is not recognized.
     */
    verifySignature(
        scheme: string,
        publicKey: Uint8Array,
        signature: Uint8Array,
        data: Uint8Array,
    ): boolean;

    /**
     * AES-ECB encrypt a single 16-byte block. Used by QUIC header protection
     * (RFC 9001 §5.4.1) — `aesEcbEncrypt(hp_key, sample)` produces the 5-byte
     * mask applied to the packet number length and first byte of the header.
     *
     * Only the AES-128 and AES-256 key sizes (16/32 bytes) are valid; the
     * input block is always 16 bytes and the output is always 16 bytes.
     */
    aesEcbEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array;
}
