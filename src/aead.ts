/**
 * AEAD encryption/decryption backed by node:crypto's GCM/ChaCha20-Poly1305 ciphers.
 *
 * Ciphertext is returned with the 16-byte authentication tag appended, matching the
 * CryptoProvider contract. These primitives are shared by the NodeCryptoProvider
 * methods and the concrete AeadCipher descriptors in ciphers.ts, so neither module
 * imports node:crypto directly for AEAD.
 */

import { createCipheriv, createDecipheriv, type CipherCCM, type CipherCCMOptions, type CipherCCMTypes, type CipherChaCha20Poly1305Types, type CipherGCM, type CipherGCMTypes, type DecipherCCM, type DecipherGCM } from "node:crypto";

import { type SymmetricCipherId } from "./types.js";
import { DecryptError } from "./errors.js";
import { assertNever } from "./utils.js";

/** AEAD tag length for the ciphers this provider supports (bytes). */
const AEAD_TAG_LENGTH = 16;

/**
 * Every node:crypto AEAD algorithm string this provider uses. Union of the three
 * algorithm-type unions so a single return type covers every branch below.
 */
type AeadAlgorithmName = CipherGCMTypes | CipherCCMTypes | CipherChaCha20Poly1305Types;

/** Map a branded {@link SymmetricCipherId} to the algorithm string node:crypto expects. */
function aeadAlgorithmName(cipher: SymmetricCipherId): AeadAlgorithmName {
    switch (cipher) {
        case "AES-128-GCM":
            return "aes-128-gcm";
        case "AES-256-GCM":
            return "aes-256-gcm";
        case "AES-128-CCM":
            return "aes-128-ccm";
        case "ChaCha20-Poly1305":
            return "chacha20-poly1305";
        default:
            return assertNever(cipher);
    }
}

/**
 * Per-cipher node:crypto options. AES-CCM requires an explicit `authTagLength`
 * (TLS 1.3 uses the full 16-byte tag); GCM and ChaCha20-Poly1305 use node's
 * default tag length, so they pass no options.
 */
function aeadCipherOptions(cipher: SymmetricCipherId): CipherCCMOptions | undefined {
    switch (cipher) {
        case "AES-128-CCM":
            return { authTagLength: AEAD_TAG_LENGTH };
        case "AES-128-GCM":
        case "AES-256-GCM":
        case "ChaCha20-Poly1305":
            return undefined;
        default:
            return assertNever(cipher);
    }
}

/**
 * Run the node:crypto AEAD step on a constructed cipher. Shared by encrypt and
 * decrypt: set the AAD, push the data, finalize, and append the auth tag.
 */
function runCipher(
    cipher: CipherGCM | CipherCCM,
    data: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    cipher.setAAD(aad, { plaintextLength: data.length });
    // Copy each piece into a fresh, exactly-sized buffer: node:crypto returns
    // Buffers that may be views over an internal pool, so a standalone copy keeps
    // the result correctly sized and safe to hold alongside later crypto calls.
    const out = new Uint8Array(cipher.update(data));
    const final = new Uint8Array(cipher.final());
    const tag = new Uint8Array(cipher.getAuthTag());
    const result = new Uint8Array(out.length + final.length + tag.length);
    result.set(out, 0);
    result.set(final, out.length);
    result.set(tag, out.length + final.length);
    return result;
}

/**
 * AEAD-encrypt with a node:crypto cipher. Returns ciphertext with the 16-byte
 * authentication tag appended, matching the CryptoProvider contract.
 *
 * The options argument is passed conditionally: AES-CCM requires an explicit
 * `authTagLength`, while GCM and ChaCha20-Poly1305 use node's default. Passing
 * `undefined` explicitly trips up TypeScript's overload resolution for
 * `createCipheriv`, so we branch on the options presence instead.
 */
export function aeadEncrypt(
    cipher: SymmetricCipherId,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    const algorithm = aeadAlgorithmName(cipher);
    const options = aeadCipherOptions(cipher);
    const enc = options === undefined
        ? (createCipheriv(algorithm, key, nonce) as CipherGCM)
        : (createCipheriv(algorithm, key, nonce, options) as CipherCCM);
    return runCipher(enc, plaintext, aad);
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
    const options = aeadCipherOptions(cipher);
    const tagStart = ciphertextAndTag.length - AEAD_TAG_LENGTH;
    const ciphertext = ciphertextAndTag.subarray(0, tagStart);
    const tag = ciphertextAndTag.subarray(tagStart);
    const dec = options === undefined
        ? (createDecipheriv(algorithm, key, nonce) as DecipherGCM)
        : (createDecipheriv(algorithm, key, nonce, options) as DecipherCCM);
    dec.setAuthTag(tag);
    dec.setAAD(aad, { plaintextLength: ciphertext.length });
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
