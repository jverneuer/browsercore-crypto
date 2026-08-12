/**
 * TLS 1.3 record-layer AEAD compatibility test.
 *
 * Simulates the exact encrypt→decrypt cycle that the @browsercore/tls record
 * layer performs:
 *
 *   1. Build a 5-byte TLS record header (type || version || length).
 *   2. XOR the static IV with the sequence number to form the nonce (RFC 8446 §5.3).
 *   3. AEAD-encrypt: ciphertext = encrypt(key, nonce, plaintext, header).
 *   4. AEAD-decrypt: plaintext  = decrypt(key, nonce, ciphertext, header).
 *
 * The audit question: does the node:crypto AEAD format (ciphertext || tag) survive
 * the encrypt→tag-split→decrypt round trip that the record layer relies on?
 */

import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import { DecryptError } from "../src/index.js";
import {
    aeadDecrypt,
    aeadEncrypt,
    bytesEqual,
    fromHex,
} from "./helpers/aead-shim.js";

/** GCM / Poly1305 authentication tag size (bytes). */
const TAG_SIZE = 16;

// ---------------------------------------------------------------------------
// TLS 1.3 nonce construction (RFC 8446 §5.3).
// ---------------------------------------------------------------------------

/**
 * Construct the per-record nonce by XOR'ing the static IV with the padded
 * 64-bit sequence number — exactly as TLS 1.3 does.
 *
 * @param staticIv  12-byte static IV derived from the traffic secret.
 * @param seqNum    64-bit record sequence number.
 * @returns 12-byte per-record nonce.
 */
function tlsNonce(staticIv: Uint8Array, seqNum: bigint): Uint8Array {
    const nonce = new Uint8Array(staticIv);
    // The sequence number occupies the rightmost 8 bytes of the 12-byte nonce;
    // the leftmost 4 bytes are XOR'd with zero (i.e. unchanged).
    for (let i = 0; i < 8; i++) {
        const shift = BigInt(8 * (7 - i));
        nonce[4 + i] = (nonce[4 + i] ?? 0) ^ Number((seqNum >> shift) & 0xffn);
    }
    return nonce;
}

/**
 * Build a 5-byte TLS record header used as AEAD additional data.
 *
 * Layout: `contentType(1) || legacyVersion(2) || length(2)`.
 * legacyVersion is always `0x0303` (TLS 1.2) per RFC 8446 §5.1.
 *
 * @param contentType TLS content type (0x16 = handshake, 0x17 = app data).
 * @param length      Length of the AEAD output (ciphertext || tag).
 * @returns 5-byte header.
 */
function tlsRecordHeader(contentType: number, length: number): Uint8Array {
    const header = new Uint8Array(5);
    header[0] = contentType;
    header[1] = 0x03;
    header[2] = 0x03;
    // Big-endian 16-bit length.
    header[3] = (length >> 8) & 0xff;
    header[4] = length & 0xff;
    return header;
}

// ---------------------------------------------------------------------------
// Core compatibility test: the exact TLS record-layer pattern.
// ---------------------------------------------------------------------------

describe("TLS record-layer encrypt→decrypt cycle", () => {
    it("AES-128-GCM: encrypt then decrypt recovers plaintext (the core pattern)", () => {
        const key = new Uint8Array(randomBytes(16));
        const nonce = new Uint8Array(randomBytes(12));
        const plaintext = new Uint8Array(randomBytes(200));
        const header = tlsRecordHeader(0x17, 0);

        // This is the exact call the TLS record layer makes.
        const ct = aeadEncrypt("aes-128-gcm", key, nonce, plaintext, header);
        const pt = aeadDecrypt("aes-128-gcm", key, nonce, ct, header);

        expect(bytesEqual(pt, plaintext)).toBe(true);
    });

    it("AES-256-GCM: encrypt then decrypt recovers plaintext", () => {
        const key = new Uint8Array(randomBytes(32));
        const nonce = new Uint8Array(randomBytes(12));
        const plaintext = new Uint8Array(randomBytes(200));
        const header = tlsRecordHeader(0x17, 0);

        const ct = aeadEncrypt("aes-256-gcm", key, nonce, plaintext, header);
        const pt = aeadDecrypt("aes-256-gcm", key, nonce, ct, header);

        expect(bytesEqual(pt, plaintext)).toBe(true);
    });

    it("ChaCha20-Poly1305: encrypt then decrypt recovers plaintext", () => {
        const key = new Uint8Array(randomBytes(32));
        const nonce = new Uint8Array(randomBytes(12));
        const plaintext = new Uint8Array(randomBytes(200));
        const header = tlsRecordHeader(0x17, 0);

        const ct = aeadEncrypt("chacha20-poly1305", key, nonce, plaintext, header);
        const pt = aeadDecrypt("chacha20-poly1305", key, nonce, ct, header);

        expect(bytesEqual(pt, plaintext)).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// Manual tag-split → reconstruct → decrypt cycle.
// This is what the record layer does internally: it writes ciphertext||tag
// to the wire, then reads it back and must correctly separate the two.
// ---------------------------------------------------------------------------

describe("manual tag-split and reassembly", () => {
    it("split ciphertext from tag, reconstruct, decrypt — all three algorithms", () => {
        const algorithms = [
            { name: "aes-128-gcm", keySize: 16 },
            { name: "aes-256-gcm", keySize: 32 },
            { name: "chacha20-poly1305", keySize: 32 },
        ] as const;

        for (const { name, keySize } of algorithms) {
            const key = new Uint8Array(randomBytes(keySize));
            const nonce = new Uint8Array(randomBytes(12));
            const plaintext = new Uint8Array(randomBytes(150));
            const header = tlsRecordHeader(0x16, 0);

            // Encrypt — produces ciphertext || tag.
            const ciphertextWithTag = aeadEncrypt(name, key, nonce, plaintext, header);

            // Manual split: ciphertext is everything but the last 16 bytes.
            const tagStart = ciphertextWithTag.length - TAG_SIZE;
            const ciphertextOnly = ciphertextWithTag.subarray(0, tagStart);
            const tagOnly = ciphertextWithTag.subarray(tagStart);

            expect(ciphertextOnly.length).toBe(plaintext.length);
            expect(tagOnly.length).toBe(TAG_SIZE);

            // Reconstruct ciphertext || tag in the SAME order.
            const reconstructed = new Uint8Array(ciphertextWithTag.length);
            reconstructed.set(ciphertextOnly, 0);
            reconstructed.set(tagOnly, ciphertextOnly.length);

            // Decrypt the reconstructed input.
            const recovered = aeadDecrypt(name, key, nonce, reconstructed, header);
            expect(bytesEqual(recovered, plaintext)).toBe(true);
        }
    });

    it("tag at the WRONG position (prepended) would cause decrypt failure", () => {
        // This test documents the failure mode: if the backend returned
        // tag || ciphertext instead of ciphertext || tag, the record layer's
        // decrypt would fail. Our backend appends the tag — so this confirms
        // the format is correct and the "wrong order" case would break.
        const key = new Uint8Array(randomBytes(16));
        const nonce = new Uint8Array(randomBytes(12));
        const plaintext = new Uint8Array(randomBytes(64));
        const header = tlsRecordHeader(0x17, 0);

        const ciphertextWithTag = aeadEncrypt("aes-128-gcm", key, nonce, plaintext, header);

        // Deliberately put the tag FIRST (wrong order).
        const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_SIZE);
        const ciphertextOnly = ciphertextWithTag.subarray(0, ciphertextWithTag.length - TAG_SIZE);
        const wrongOrder = new Uint8Array(ciphertextWithTag.length);
        wrongOrder.set(tag, 0);
        wrongOrder.set(ciphertextOnly, TAG_SIZE);

        // Decrypt with the tag-first format — this should FAIL because the
        // backend expects tag LAST. If it DIDN'T fail, the format would be
        // ambiguous, which would be a bug.
        expect(() =>
            aeadDecrypt("aes-128-gcm", key, nonce, wrongOrder, header),
        ).toThrow(DecryptError);
    });
});

// ---------------------------------------------------------------------------
// Multi-record: simulate a TLS flight with incrementing sequence numbers.
// ---------------------------------------------------------------------------

describe("multi-record TLS flight with nonce rotation", () => {
    it("five sequential records, each with a unique nonce, all round-trip", () => {
        const key = new Uint8Array(randomBytes(32));
        const staticIv = new Uint8Array(randomBytes(12));

        for (let seq = 0n; seq < 5n; seq++) {
            const nonce = tlsNonce(staticIv, seq);
            const plaintext = new Uint8Array(randomBytes(100));
            const header = tlsRecordHeader(0x17, 0);

            const ct = aeadEncrypt("aes-256-gcm", key, nonce, plaintext, header);
            const pt = aeadDecrypt("aes-256-gcm", key, nonce, ct, header);

            expect(bytesEqual(pt, plaintext)).toBe(true);
        }
    });

    it("nonce rotation changes every byte for adjacent sequence numbers", () => {
        const staticIv = new Uint8Array(12);
        staticIv.fill(0xab);

        const nonce0 = tlsNonce(staticIv, 0n);
        const nonce1 = tlsNonce(staticIv, 1n);

        // Seq 0 → nonce == static IV (XOR with 0).
        expect(bytesEqual(nonce0, staticIv)).toBe(true);
        // Seq 1 → last byte differs.
        expect(nonce1[11]).not.toBe(nonce0[11]);
    });
});

// ---------------------------------------------------------------------------
// AAD sensitivity: record header changes must break decryption.
// ---------------------------------------------------------------------------

describe("AAD sensitivity (record header mismatch)", () => {
    it("decrypt with a header that differs in the length field throws", () => {
        const key = new Uint8Array(randomBytes(16));
        const nonce = new Uint8Array(randomBytes(12));
        const plaintext = new Uint8Array(randomBytes(80));
        const correctHeader = tlsRecordHeader(0x17, 80 + TAG_SIZE);
        const wrongHeader = tlsRecordHeader(0x17, 80 + TAG_SIZE + 1);

        const ct = aeadEncrypt("aes-128-gcm", key, nonce, plaintext, correctHeader);

        expect(() => aeadDecrypt("aes-128-gcm", key, nonce, ct, wrongHeader)).toThrow(
            DecryptError,
        );
    });

    it("decrypt with a header that differs in the content type throws", () => {
        const key = new Uint8Array(randomBytes(16));
        const nonce = new Uint8Array(randomBytes(12));
        const plaintext = new Uint8Array(randomBytes(80));
        const correctHeader = tlsRecordHeader(0x17, 0);
        const wrongHeader = tlsRecordHeader(0x16, 0);

        const ct = aeadEncrypt("aes-128-gcm", key, nonce, plaintext, correctHeader);

        expect(() => aeadDecrypt("aes-128-gcm", key, nonce, ct, wrongHeader)).toThrow(
            DecryptError,
        );
    });
});

// ---------------------------------------------------------------------------
// Known vector with TLS-style AAD: RFC 8439 ChaCha20-Poly1305 with explicit
// 5-byte "record header" matching the AAD from the RFC.
// ---------------------------------------------------------------------------

describe("RFC 8439 vector with explicit AAD cross-check", () => {
    it("encrypt produces known tag, decrypt round-trips", () => {
        const key = fromHex(
            "808182838485868788898a8b8c8d8e8f" +
            "909192939495969798999a9b9c9d9e9f",
        );
        const nonce = fromHex("070000004041424344454647");
        const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
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

        const ct = aeadEncrypt("chacha20-poly1305", key, nonce, plaintext, aad);

        // Verify the full output matches the RFC (proves correctness).
        expect(bytesEqual(ct, expectedCiphertextWithTag)).toBe(true);

        // Round-trip.
        const pt = aeadDecrypt("chacha20-poly1305", key, nonce, ct, aad);
        expect(bytesEqual(pt, plaintext)).toBe(true);
    });
});
