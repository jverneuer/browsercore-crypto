/**
 * Tests for the runtime pieces of the @browsercore/crypto domain types.
 *
 * Most of `src/types.ts` is type-level (branded identifiers, interfaces) and is
 * verified at compile time. The two runtime surfaces that need coverage are
 * the session-id factory (`createCryptoSessionId`) and the canonical branded
 * cipher/hash/key-exchange constant values used across the protocol stack.
 */

import { describe, expect, it } from "vitest";

import {
    AES_128_CCM,
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    SHA_256,
    SHA_384,
    X25519,
    createCryptoSessionId,
    type HashId,
    type KeyExchangeId,
    type SymmetricCipherId,
} from "../src/types.js";

describe("createCryptoSessionId", () => {
    it("returns a string branded as a CryptoSessionId", () => {
        const id = createCryptoSessionId();
        expect(typeof id).toBe("string");
        expect(id.startsWith("csid_")).toBe(true);
    });

    it("produces distinct ids across calls", () => {
        const a = createCryptoSessionId();
        const b = createCryptoSessionId();
        expect(a).not.toBe(b);
    });
});

describe("SymmetricCipherId constants", () => {
    it("exposes the four supported AEAD cipher tokens", () => {
        const ids: SymmetricCipherId[] = [AES_128_GCM, AES_256_GCM, AES_128_CCM, CHACHA20_POLY1305];
        expect(ids).toEqual(["AES-128-GCM", "AES-256-GCM", "AES-128-CCM", "ChaCha20-Poly1305"]);
    });
});

describe("HashId constants", () => {
    it("exposes the two supported hash tokens", () => {
        const ids: HashId[] = [SHA_256, SHA_384];
        expect(ids).toEqual(["SHA-256", "SHA-384"]);
    });
});

describe("KeyExchangeId constant", () => {
    it("exposes the X25519 token", () => {
        const ids: KeyExchangeId[] = [X25519];
        expect(ids).toEqual(["X25519"]);
    });
});
