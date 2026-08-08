/**
 * Tests for the @browsercore/crypto barrel (src/index.ts).
 *
 * The barrel re-exports types, errors, constants, the x25519 DER helpers, and
 * the default X25519 backend. This test exercises the barrel so the re-export
 * surface (and the `defaultX25519Backend` instantiation) is covered, and
 * confirms the public API resolves to the expected concrete values.
 */

import { describe, expect, it } from "vitest";

import {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    SHA_256,
    SHA_384,
    X25519,
    CryptoError,
    DecryptError,
    NobleX25519Backend,
    UnsupportedAlgorithmError,
    assertNever,
    createCryptoSessionId,
    createId,
    defaultX25519Backend,
    ensureCryptoError,
    pkcs8ToRaw,
    rawPrivateToPkcs8,
    rawPublicToSpki,
    spkiToRaw,
} from "../src/index.js";

describe("barrel re-exports resolve", () => {
    it("re-exports cipher/hash/key-exchange constants", () => {
        expect(AES_128_GCM).toBe("AES-128-GCM");
        expect(AES_256_GCM).toBe("AES-256-GCM");
        expect(CHACHA20_POLY1305).toBe("ChaCha20-Poly1305");
        expect(SHA_256).toBe("SHA-256");
        expect(SHA_384).toBe("SHA-384");
        expect(X25519).toBe("X25519");
    });

    it("re-exports the typed error classes", () => {
        expect(CryptoError).toBeInstanceOf(Function);
        expect(UnsupportedAlgorithmError).toBeInstanceOf(Function);
        expect(DecryptError).toBeInstanceOf(Function);
        expect(ensureCryptoError).toBeInstanceOf(Function);
    });

    it("re-exports the utility helpers", () => {
        expect(assertNever).toBeInstanceOf(Function);
        expect(createId).toBeInstanceOf(Function);
        expect(createCryptoSessionId).toBeInstanceOf(Function);
    });

    it("re-exports the x25519 DER helpers", () => {
        expect(rawPrivateToPkcs8).toBeInstanceOf(Function);
        expect(pkcs8ToRaw).toBeInstanceOf(Function);
        expect(rawPublicToSpki).toBeInstanceOf(Function);
        expect(spkiToRaw).toBeInstanceOf(Function);
    });

    it("re-exports the X25519 backend class and a live default instance", () => {
        expect(NobleX25519Backend).toBeInstanceOf(Function);
        expect(defaultX25519Backend).toBeInstanceOf(NobleX25519Backend);
    });

    it("the default backend derives a 32-byte public coordinate", () => {
        const scalar = new Uint8Array(32);
        scalar[0] = 7;
        expect(defaultX25519Backend.publicKey(scalar)).toHaveLength(32);
    });
});
