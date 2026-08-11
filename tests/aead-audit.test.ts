/**
 * AEAD ciphertext-format audit.
 *
 * Verifies that the node:crypto AEAD backend (replicated in helpers/aead-shim.ts
 * from browsersmith/src/platform/crypto/node/aead.ts) returns ciphertext WITH the
 * 16-byte authentication tag appended, and that decrypt expects the same format.
 *
 * This is the exact contract the TLS 1.3 record layer relies on:
 *   encrypt(key, nonce, plaintext, aad) → ciphertext || tag
 *   decrypt(key, nonce, ciphertext || tag, aad) → plaintext
 *
 * If the tag were NOT appended (e.g. returned separately), the TLS record layer
 * would silently produce garbage on decrypt — the failure mode under investigation.
 */

import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import { DecryptError } from "../src/index.js";
import {
    aeadDecrypt,
    aeadEncrypt,
    bytesEqual,
    fromHex,
    toHex,
} from "./helpers/aead-shim.js";

// ---------------------------------------------------------------------------
// Algorithm table — the three AEAD ciphers TLS 1.3 uses.
// ---------------------------------------------------------------------------

interface AeadAlgorithmSpec {
    /** Human-readable cipher name. */
    readonly name: string;
    /** node:crypto algorithm string. */
    readonly algorithm: string;
    /** Key size in bytes. */
    readonly keySize: number;
}

const ALGORITHMS: readonly AeadAlgorithmSpec[] = [
    { name: "AES-128-GCM", algorithm: "aes-128-gcm", keySize: 16 },
    { name: "AES-256-GCM", algorithm: "aes-256-gcm", keySize: 32 },
    { name: "ChaCha20-Poly1305", algorithm: "chacha20-poly1305", keySize: 32 },
] as const;

/** Standard AEAD nonce size for all three ciphers (bytes). */
const NONCE_SIZE = 12;
/** GCM / Poly1305 authentication tag size (bytes). */
const TAG_SIZE = 16;

// ---------------------------------------------------------------------------
// Round-trip + auth-failure tests for every algorithm.
// ---------------------------------------------------------------------------

describe("AEAD round-trip — all algorithms", () => {
    for (const spec of ALGORITHMS) {
        describe(`${spec.name}`, () => {
            it("encrypt output length === plaintext.length + 16 (tag appended)", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(256));
                const aad = new Uint8Array(randomBytes(13));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);

                expect(ciphertext.length).toBe(plaintext.length + TAG_SIZE);
            });

            it("decrypt recovers the original plaintext", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(256));
                const aad = new Uint8Array(randomBytes(13));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);
                const recovered = aeadDecrypt(spec.algorithm, key, nonce, ciphertext, aad);

                expect(recovered.length).toBe(plaintext.length);
                expect(bytesEqual(recovered, plaintext)).toBe(true);
            });

            it("works with empty plaintext (tag-only output)", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(0);
                const aad = new Uint8Array(randomBytes(5));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);

                expect(ciphertext.length).toBe(TAG_SIZE);

                const recovered = aeadDecrypt(spec.algorithm, key, nonce, ciphertext, aad);
                expect(recovered.length).toBe(0);
            });

            it("works with empty AAD", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(64));
                const aad = new Uint8Array(0);

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);
                const recovered = aeadDecrypt(spec.algorithm, key, nonce, ciphertext, aad);

                expect(bytesEqual(recovered, plaintext)).toBe(true);
            });

            it("decrypt with WRONG AAD throws DecryptError", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(128));
                const aad = new Uint8Array(randomBytes(8));
                const wrongAad = new Uint8Array(randomBytes(8));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);

                expect(() =>
                    aeadDecrypt(spec.algorithm, key, nonce, ciphertext, wrongAad),
                ).toThrow(DecryptError);
            });

            it("decrypt with WRONG key throws DecryptError", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const wrongKey = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(128));
                const aad = new Uint8Array(randomBytes(8));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);

                expect(() =>
                    aeadDecrypt(spec.algorithm, wrongKey, nonce, ciphertext, aad),
                ).toThrow(DecryptError);
            });

            it("decrypt with tampered ciphertext byte throws DecryptError", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(128));
                const aad = new Uint8Array(randomBytes(8));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);
                const tampered = new Uint8Array(ciphertext);
                // Flip a bit in the ciphertext body (not the tag).
                tampered[0] = (tampered[0] ?? 0) ^ 0x01;

                expect(() =>
                    aeadDecrypt(spec.algorithm, key, nonce, tampered, aad),
                ).toThrow(DecryptError);
            });

            it("decrypt with tampered tag byte throws DecryptError", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
                const plaintext = new Uint8Array(randomBytes(128));
                const aad = new Uint8Array(randomBytes(8));

                const ciphertext = aeadEncrypt(spec.algorithm, key, nonce, plaintext, aad);
                const tampered = new Uint8Array(ciphertext);
                // Flip a bit in the tag (last 16 bytes).
                const lastIdx = tampered.length - 1;
                tampered[lastIdx] = (tampered[lastIdx] ?? 0) ^ 0x01;

                expect(() =>
                    aeadDecrypt(spec.algorithm, key, nonce, tampered, aad),
                ).toThrow(DecryptError);
            });

            it("multiple sequential encrypts with the same key produce different ciphertext", () => {
                const key = new Uint8Array(randomBytes(spec.keySize));
                const plaintext = new Uint8Array(randomBytes(64));
                const aad = new Uint8Array(randomBytes(5));

                const nonce1 = new Uint8Array(randomBytes(NONCE_SIZE));
                const nonce2 = new Uint8Array(randomBytes(NONCE_SIZE));

                const ct1 = aeadEncrypt(spec.algorithm, key, nonce1, plaintext, aad);
                const ct2 = aeadEncrypt(spec.algorithm, key, nonce2, plaintext, aad);

                expect(bytesEqual(ct1, ct2)).toBe(false);
            });
        });
    }
});

// ---------------------------------------------------------------------------
// AES-128-GCM — NIST SP 800-38D test vectors (Test Cases 1 & 3).
// ---------------------------------------------------------------------------

describe("AES-128-GCM — NIST SP 800-38D vectors", () => {
    it("Test Case 1: empty plaintext, empty AAD → 16-byte tag output", () => {
        const key = fromHex("00000000000000000000000000000000");
        const nonce = fromHex("000000000000000000000000");
        const plaintext = new Uint8Array(0);
        const aad = new Uint8Array(0);
        const expectedTag = fromHex("58e2fccefa7e3061367f1d57a4e7455a");

        const ciphertext = aeadEncrypt("aes-128-gcm", key, nonce, plaintext, aad);

        // Empty plaintext → output is exactly the 16-byte tag.
        expect(ciphertext.length).toBe(16);
        expect(toHex(ciphertext)).toBe(toHex(expectedTag));

        // Decrypt the tag-only input → empty plaintext.
        const recovered = aeadDecrypt("aes-128-gcm", key, nonce, ciphertext, aad);
        expect(recovered.length).toBe(0);
    });

    it("Test Case 3: 60-byte plaintext with 20-byte AAD", () => {
        const key = fromHex("feffe9928665731c6d6a8f9467308308");
        const nonce = fromHex("cafebabefacedbaddecaf888");
        const plaintext = fromHex(
            "d9313225f88406e5a55909c5aff5269a" +
            "86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525" +
            "b16aedf5aa0de657ba637b39",
        );
        const aad = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        const expectedCiphertextWithTag = fromHex(
            "42831ec2217774244b7221b784d0d49c" +
            "e3aa212f2c02a4e035c17e2329aca12e" +
            "21d514b25466931c7d8f6a5aac84aa05" +
            "1ba30b396a0aac973d58e091" +
            "5bc94fbc3221a5db94fae95ae7121a47",
        );

        const ciphertext = aeadEncrypt("aes-128-gcm", key, nonce, plaintext, aad);

        expect(ciphertext.length).toBe(plaintext.length + TAG_SIZE);
        expect(toHex(ciphertext)).toBe(toHex(expectedCiphertextWithTag));

        // Decrypt the independently-constructed vector.
        const recovered = aeadDecrypt(
            "aes-128-gcm",
            key,
            nonce,
            expectedCiphertextWithTag,
            aad,
        );
        expect(bytesEqual(recovered, plaintext)).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// AES-256-GCM — NIST SP 800-38D test vectors (Test Cases 14 & 16).
// ---------------------------------------------------------------------------

describe("AES-256-GCM — NIST SP 800-38D vectors", () => {
    it("Test Case 14: empty plaintext, empty AAD → 16-byte tag output", () => {
        const key = fromHex(
            "00000000000000000000000000000000" +
            "00000000000000000000000000000000",
        );
        const nonce = fromHex("000000000000000000000000");
        const plaintext = new Uint8Array(0);
        const aad = new Uint8Array(0);
        const expectedTag = fromHex("530f8afbc74536b9a963b4f1c4cb738b");

        const ciphertext = aeadEncrypt("aes-256-gcm", key, nonce, plaintext, aad);

        expect(ciphertext.length).toBe(16);
        expect(toHex(ciphertext)).toBe(toHex(expectedTag));

        const recovered = aeadDecrypt("aes-256-gcm", key, nonce, ciphertext, aad);
        expect(recovered.length).toBe(0);
    });

    it("Test Case 16: 60-byte plaintext with 20-byte AAD", () => {
        const key = fromHex(
            "feffe9928665731c6d6a8f9467308308" +
            "feffe9928665731c6d6a8f9467308308",
        );
        const nonce = fromHex("cafebabefacedbaddecaf888");
        const plaintext = fromHex(
            "d9313225f88406e5a55909c5aff5269a" +
            "86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525" +
            "b16aedf5aa0de657ba637b39",
        );
        const aad = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        const expectedCiphertextWithTag = fromHex(
            "522dc1f099567d07f47f37a32a84427d" +
            "643a8cdcbfe5c0c97598a2bd2555d1aa" +
            "8cb08e48590dbb3da7b08b1056828838" +
            "c5f61e6393ba7a0abcc9f662" +
            "76fc6ece0f4e1768cddf8853bb2d551b",
        );

        const ciphertext = aeadEncrypt("aes-256-gcm", key, nonce, plaintext, aad);

        expect(ciphertext.length).toBe(plaintext.length + TAG_SIZE);
        expect(toHex(ciphertext)).toBe(toHex(expectedCiphertextWithTag));

        const recovered = aeadDecrypt(
            "aes-256-gcm",
            key,
            nonce,
            expectedCiphertextWithTag,
            aad,
        );
        expect(bytesEqual(recovered, plaintext)).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 — RFC 8439 §2.8.2 test vector.
// ---------------------------------------------------------------------------

describe("ChaCha20-Poly1305 — RFC 8439 §2.8.2 vector", () => {
    const key = fromHex(
        "808182838485868788898a8b8c8d8e8f" +
        "909192939495969798999a9b9c9d9e9f",
    );
    const nonce = fromHex("070000004041424344454647");
    const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
    // "Ladies and Gentlemen of the class of '99: If I could offer you only one
    //  tip for the future, sunscreen would be it." (114 bytes)
    const plaintext = fromHex(
        "4c616469657320616e642047656e746c" +
        "656d656e206f662074686520636c6173" +
        "73206f66202739393a20496620492063" +
        "6f756c64206f6666657220796f75206f" +
        "6e6c79206f6e652074697020666f7220" +
        "746865206675747572652c2073756e73" +
        "637265656e20776f756c642062652069" +
        "742e",
    );
    // RFC 8439 §2.8.2 — the full ciphertext and tag.
    const expectedCiphertextWithTag = fromHex(
        "d31a8d34648e60db7b86afbc53ef7ec2" +
        "a4aded51296e08fea9e2b5a736ee62d6" +
        "3dbea45e8ca9671282fafb69da92728b" +
        "1a71de0a9e060b2905d6a5b67ecd3b36" +
        "92ddbd7f2d778b8c9803aee328091b58" +
        "fab324e4fad675945585808b4831d7bc" +
        "3ff4def08e4b7a9de576d26586cec64b" +
        "6116" +
        "1ae10b594f09e26a7e902ecbd0600691",
    );

    it("plaintext is 114 bytes (sanity check)", () => {
        expect(plaintext.length).toBe(114);
    });

    it("encrypt output matches RFC 8439 ciphertext || tag exactly", () => {
        const ciphertext = aeadEncrypt("chacha20-poly1305", key, nonce, plaintext, aad);

        expect(ciphertext.length).toBe(plaintext.length + TAG_SIZE);
        expect(toHex(ciphertext)).toBe(toHex(expectedCiphertextWithTag));
    });

    it("decrypt the RFC 8439 ciphertext || tag recovers the known plaintext", () => {
        const recovered = aeadDecrypt(
            "chacha20-poly1305",
            key,
            nonce,
            expectedCiphertextWithTag,
            aad,
        );

        expect(bytesEqual(recovered, plaintext)).toBe(true);
    });

    it("decrypt recovers the original plaintext (round-trip)", () => {
        const ciphertext = aeadEncrypt("chacha20-poly1305", key, nonce, plaintext, aad);
        const recovered = aeadDecrypt("chacha20-poly1305", key, nonce, ciphertext, aad);

        expect(bytesEqual(recovered, plaintext)).toBe(true);
    });

    it("decrypt with wrong AAD throws DecryptError", () => {
        const ciphertext = aeadEncrypt("chacha20-poly1305", key, nonce, plaintext, aad);
        const wrongAad = fromHex("000000000000000000000000");

        expect(() =>
            aeadDecrypt("chacha20-poly1305", key, nonce, ciphertext, wrongAad),
        ).toThrow(DecryptError);
    });
});

// ---------------------------------------------------------------------------
// Cross-algorithm: verify encrypt output is NOT interchangeable.
// ---------------------------------------------------------------------------

describe("cross-algorithm independence", () => {
    it("AES-128-GCM ciphertext cannot be decrypted with AES-256-GCM key", () => {
        const key128 = new Uint8Array(randomBytes(16));
        const key256 = new Uint8Array(randomBytes(32));
        const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
        const plaintext = new Uint8Array(randomBytes(32));
        const aad = new Uint8Array(0);

        const ciphertext = aeadEncrypt("aes-128-gcm", key128, nonce, plaintext, aad);

        expect(() =>
            aeadDecrypt("aes-256-gcm", key256, nonce, ciphertext, aad),
        ).toThrow();
    });
});
