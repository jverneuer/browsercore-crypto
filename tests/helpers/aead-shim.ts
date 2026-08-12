/**
 * Test-only AEAD shim — faithful replica of the production AEAD backend.
 *
 * This mirrors `browsersmith/src/platform/crypto/node/aead.ts` line-for-line so
 * tests verify the exact same `node:crypto` code path that the NodeCryptoProvider
 * uses in production. The concrete provider was extracted from this package
 * (browsercore-crypto) to browsersmith, but the dependency direction prevents
 * importing it here — so the shim replicates the identical node:crypto calls.
 *
 * Contract under audit:
 *   encrypt → returns Uint8Array of length plaintext.length + 16 (tag appended)
 *   decrypt → expects ciphertext || tag, returns plaintext
 *
 * @module
 */

import {
    createCipheriv,
    createDecipheriv,
    type CipherGCM,
    type DecipherGCM,
} from "node:crypto";

import { DecryptError } from "../../src/index.js";

/** AEAD tag length for GCM and ChaCha20-Poly1305 (bytes). */
const AEAD_TAG_LENGTH = 16;

/**
 * AEAD-encrypt using node:crypto — ciphertext with 16-byte tag appended.
 *
 * Replicates the `aeadEncrypt` + `runCipher` production path. GCM and
 * ChaCha20-Poly1305 use the default authTagLength (16), so no options object
 * is passed to `createCipheriv`.
 *
 * @param algorithm  node:crypto algorithm string (e.g. `"aes-128-gcm"`).
 * @param key        Symmetric key (16 bytes for AES-128, 32 for AES-256/ChaCha20).
 * @param nonce      12-byte initialization vector.
 * @param plaintext  Data to encrypt.
 * @param aad        Additional authenticated data.
 * @returns Ciphertext with the 16-byte tag appended.
 */
export function aeadEncrypt(
    algorithm: string,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    const cipher = createCipheriv(algorithm, key, nonce) as CipherGCM;
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const out = new Uint8Array(cipher.update(plaintext));
    const final = new Uint8Array(cipher.final());
    const tag = new Uint8Array(cipher.getAuthTag());
    const result = new Uint8Array(out.length + final.length + tag.length);
    result.set(out, 0);
    result.set(final, out.length);
    result.set(tag, out.length + final.length);
    return result;
}

/**
 * AEAD-decrypt using node:crypto — expects ciphertext with 16-byte tag appended.
 *
 * Replicates the `aeadDecrypt` production path: splits the tag off the end,
 * sets it via `setAuthTag`, then `final()` verifies it.
 *
 * @param algorithm       node:crypto algorithm string.
 * @param key             Symmetric key.
 * @param nonce           12-byte initialization vector.
 * @param ciphertextWithTag  Ciphertext with the 16-byte tag appended.
 * @param aad             Additional authenticated data from encrypt.
 * @returns Decrypted plaintext.
 * @throws {DecryptError} On authentication failure or input shorter than the tag.
 */
export function aeadDecrypt(
    algorithm: string,
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertextWithTag: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    if (ciphertextWithTag.length < AEAD_TAG_LENGTH) {
        throw new DecryptError(algorithm);
    }
    const tagStart = ciphertextWithTag.length - AEAD_TAG_LENGTH;
    const ciphertext = ciphertextWithTag.subarray(0, tagStart);
    const tag = ciphertextWithTag.subarray(tagStart);
    const dec = createDecipheriv(algorithm, key, nonce) as DecipherGCM;
    dec.setAuthTag(tag);
    dec.setAAD(aad, { plaintextLength: ciphertext.length });
    try {
        const plaintext = new Uint8Array(dec.update(ciphertext));
        const final = new Uint8Array(dec.final());
        const out = new Uint8Array(plaintext.length + final.length);
        out.set(plaintext, 0);
        out.set(final, plaintext.length);
        return out;
    } catch (cause) {
        throw new DecryptError(algorithm, { cause: cause as Error });
    }
}

/**
 * Decode a hex string to a fresh `Uint8Array`.
 *
 * @param hex Hex string (whitespace stripped automatically).
 * @returns Corresponding byte array.
 */
export function fromHex(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));
}

/**
 * Encode a byte array to a lowercase hex string.
 *
 * @param bytes Input bytes.
 * @returns Hex representation.
 */
export function toHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

/**
 * Check whether two byte arrays have identical contents.
 *
 * @param a First array.
 * @param b Second array.
 * @returns `true` if same length and every byte matches.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}
