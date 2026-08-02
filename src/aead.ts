/**
 * AEAD encryption/decryption backed by node:crypto's GCM/ChaCha20-Poly1305 ciphers.
 *
 * Ciphertext is returned with the 16-byte authentication tag appended, matching the
 * CryptoProvider contract. These primitives are shared by the NodeCryptoProvider
 * methods and the concrete AeadCipher descriptors in ciphers.ts, so neither module
 * imports node:crypto directly for AEAD.
 */

import { createCipheriv, createDecipheriv, type CipherGCM, type DecipherGCM } from "node:crypto";

import { type SymmetricCipherId } from "./types.js";
import { DecryptError } from "./errors.js";
import { assertNever } from "./utils.js";

/** AEAD tag length for the ciphers this provider supports (bytes). */
const AEAD_TAG_LENGTH = 16;

/** Map a branded {@link SymmetricCipherId} to the algorithm string node:crypto expects. */
function aeadAlgorithmName(cipher: SymmetricCipherId): string {
    switch (cipher) {
        case "AES-128-GCM":
            return "aes-128-gcm";
        case "AES-256-GCM":
            return "aes-256-gcm";
        case "ChaCha20-Poly1305":
            return "chacha20-poly1305";
        default:
            return assertNever(cipher);
    }
}

/**
 * AEAD-encrypt with a node:crypto cipher. Returns ciphertext with the 16-byte
 * authentication tag appended, matching the CryptoProvider contract.
 */
export function aeadEncrypt(
    cipher: SymmetricCipherId,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    const algorithm = aeadAlgorithmName(cipher);
    const enc = createCipheriv(algorithm, key, nonce) as CipherGCM;
    enc.setAAD(aad);
    // Copy each piece into a fresh, exactly-sized buffer: node:crypto returns
    // Buffers that may be views over an internal pool, so a standalone copy keeps
    // the result correctly sized and safe to hold alongside later crypto calls.
    const ciphertext = new Uint8Array(enc.update(plaintext));
    const final = new Uint8Array(enc.final());
    const tag = new Uint8Array(enc.getAuthTag());
    const out = new Uint8Array(ciphertext.length + final.length + tag.length);
    out.set(ciphertext, 0);
    out.set(final, ciphertext.length);
    out.set(tag, ciphertext.length + final.length);
    return out;
}

/**
 * AEAD-decrypt with a node:crypto cipher. Expects ciphertext with the 16-byte
 * tag appended. Throws {@link DecryptError} on authentication failure.
 */
export function aeadDecrypt(
    cipher: SymmetricCipherId,
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertextAndTag: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    if (ciphertextAndTag.length < AEAD_TAG_LENGTH) {
        throw new DecryptError(cipher);
    }
    const algorithm = aeadAlgorithmName(cipher);
    const tagStart = ciphertextAndTag.length - AEAD_TAG_LENGTH;
    const ciphertext = ciphertextAndTag.subarray(0, tagStart);
    const tag = ciphertextAndTag.subarray(tagStart);
    const dec = createDecipheriv(algorithm, key, nonce) as DecipherGCM;
    dec.setAuthTag(tag);
    dec.setAAD(aad);
    try {
        // Standalone copy for the same reason as encrypt (pooled node Buffers).
        const plaintext = new Uint8Array(dec.update(ciphertext));
        const final = new Uint8Array(dec.final());
        const out = new Uint8Array(plaintext.length + final.length);
        out.set(plaintext, 0);
        out.set(final, plaintext.length);
        return out;
    } catch (cause) {
        // The only operations inside the try are node:crypto calls, which always
        // throw an Error on auth failure — cast preserves it as the cause.
        throw new DecryptError(cipher, { cause: cause as Error });
    }
}
