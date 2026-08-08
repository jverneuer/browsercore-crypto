/**
 * Tests for the typed crypto error hierarchy.
 *
 * Every failure mode in @browsercore/crypto is an explicit error subtype so
 * callers can match on `kind` instead of parsing messages. These tests verify
 * the hierarchy wiring (kind narrowing, name/cause chaining) and the boundary
 * narrowing function `ensureCryptoError`, which guarantees every thrown value
 * is a typed CryptoError.
 */

import { describe, expect, it } from "vitest";

import {
    CryptoError,
    DecryptError,
    UnsupportedAlgorithmError,
    ensureCryptoError,
    type CryptoErrorKind,
} from "../src/errors.js";

describe("CryptoError hierarchy", () => {
    it("CryptoError records kind, algorithm, name and cause", () => {
        const cause = new Error("underlying failure");
        const err = new CryptoError("boom", "AES-256-GCM", { cause });
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(CryptoError);
        expect(err.kind).toBe("CryptoError");
        expect(err.algorithm).toBe("AES-256-GCM");
        expect(err.name).toBe("CryptoError");
        expect(err.message).toBe("boom");
        expect(err.cause).toBe(cause);
    });

    it("CryptoError tolerates no algorithm and no cause", () => {
        const err = new CryptoError("generic");
        expect(err.algorithm).toBeUndefined();
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("generic");
    });

    it("CryptoErrorKind is a union of every discriminator", () => {
        const kinds: CryptoErrorKind[] = [
            "CryptoError",
            "UnsupportedAlgorithmError",
            "DecryptError",
        ];
        expect(kinds).toHaveLength(3);
    });
});

describe("UnsupportedAlgorithmError", () => {
    it("narrows kind and records the unsupported algorithm", () => {
        const err = new UnsupportedAlgorithmError("AES-128-CCM");
        expect(err).toBeInstanceOf(CryptoError);
        expect(err.kind).toBe("UnsupportedAlgorithmError");
        expect(err.algorithm).toBe("AES-128-CCM");
        expect(err.name).toBe("UnsupportedAlgorithmError");
        expect(err.message).toContain("AES-128-CCM");
    });

    it("is caught by `instanceof CryptoError`", () => {
        const err = new UnsupportedAlgorithmError("FOO");
        expect(err instanceof CryptoError).toBe(true);
    });
});

describe("DecryptError", () => {
    it("narrows kind and records the algorithm being decoded", () => {
        const err = new DecryptError("AES-256-GCM");
        expect(err).toBeInstanceOf(CryptoError);
        expect(err.kind).toBe("DecryptError");
        expect(err.algorithm).toBe("AES-256-GCM");
        expect(err.name).toBe("DecryptError");
    });

    it("preserves an optional cause chain", () => {
        const cause = new Error("auth tag mismatch");
        const err = new DecryptError("AES-128-GCM", { cause });
        expect(err.cause).toBe(cause);
    });
});

describe("ensureCryptoError", () => {
    it("passes an existing CryptoError through unchanged (preserves kind)", () => {
        const original = new UnsupportedAlgorithmError("CHACHA20");
        expect(ensureCryptoError(original, "AES-256-GCM")).toBe(original);
        expect(ensureCryptoError(original).kind).toBe("UnsupportedAlgorithmError");
    });

    it("passes a DecryptError through unchanged", () => {
        const original = new DecryptError("AES-128-GCM");
        expect(ensureCryptoError(original)).toBe(original);
    });

    it("wraps a plain Error as a CryptoError, attaching the algorithm", () => {
        const e = new Error("cipher crash");
        const wrapped = ensureCryptoError(e, "AES-256-GCM");
        expect(wrapped).toBeInstanceOf(CryptoError);
        expect(wrapped).not.toBe(e);
        expect(wrapped.message).toBe("cipher crash");
        expect(wrapped.algorithm).toBe("AES-256-GCM");
        expect(wrapped.cause).toBe(e);
    });

    it("wraps a string thrown value as a CryptoError", () => {
        const wrapped = ensureCryptoError("bad input", "AES-128-GCM");
        expect(wrapped).toBeInstanceOf(CryptoError);
        expect(wrapped.message).toBe("bad input");
        expect(wrapped.algorithm).toBe("AES-128-GCM");
    });

    it("wraps a non-string non-Error value with a generic message", () => {
        const wrapped = ensureCryptoError(42, "AES-256-GCM");
        expect(wrapped).toBeInstanceOf(CryptoError);
        expect(wrapped.message).toBe("unknown crypto error");
        expect(wrapped.algorithm).toBe("AES-256-GCM");
    });

    it("defaults the algorithm to undefined when none is supplied", () => {
        const wrapped = ensureCryptoError(new Error("x"));
        expect(wrapped.algorithm).toBeUndefined();
    });
});
