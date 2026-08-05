/**
 * Known-answer and property tests for the noble-curves X25519 backend.
 *
 * Mirrors the coverage of tests/x25519-vectors.test.ts for the Node backend,
 * but exercises the pure-TypeScript NobleX25519Backend — no node:crypto
 * involved. Validates the RFC 7748 §5.2 scalar-multiplication vectors, the
 * §6.1 Diffie-Hellman vector, degenerate / small-order edge behavior, and
 * DH symmetry.
 */

import { describe, expect, it } from "vitest";

import { NobleX25519Backend } from "../../src/x25519/noble-backend.js";

const backend = new NobleX25519Backend();
const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));

/** The X25519 base point u=9, encoded little-endian as 32 bytes. */
const BASE_POINT_9: Uint8Array = (() => {
    const u = new Uint8Array(32);
    u[0] = 9;
    return u;
})();

describe("RFC 7748 §5.2 X25519 scalar-multiplication vectors", () => {
    it("Vector 1: matches the published output u-coordinate", () => {
        const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const u = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        const expected = fromHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        expect(backend.sharedSecret(scalar, u)).toEqual(expected);
    });

    it("Vector 2: matches the published output u-coordinate", () => {
        const scalar = fromHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        const u = fromHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        const expected = fromHex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        expect(backend.sharedSecret(scalar, u)).toEqual(expected);
    });
});

describe("RFC 7748 §6.1 X25519 Diffie-Hellman vector", () => {
    const alicePriv = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const alicePub = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const bobPriv = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const bobPub = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const sharedK = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    it("Alice's public key is X25519(a, 9) — the published value", () => {
        expect(backend.sharedSecret(alicePriv, BASE_POINT_9)).toEqual(alicePub);
    });

    it("Bob's public key is X25519(b, 9) — the published value", () => {
        expect(backend.sharedSecret(bobPriv, BASE_POINT_9)).toEqual(bobPub);
    });

    it("Alice's public key is getPublicKey(a)", () => {
        expect(backend.publicKey(alicePriv)).toEqual(alicePub);
    });

    it("Bob's public key is getPublicKey(b)", () => {
        expect(backend.publicKey(bobPriv)).toEqual(bobPub);
    });

    it("X25519(a, K_B) === the published shared secret K", () => {
        expect(backend.sharedSecret(alicePriv, bobPub)).toEqual(sharedK);
    });

    it("X25519(b, K_A) === the published shared secret K (DH symmetry)", () => {
        expect(backend.sharedSecret(bobPriv, alicePub)).toEqual(sharedK);
    });
});

describe("X25519 properties", () => {
    it("publicKey matches sharedSecret(secret, BASE_POINT_9)", () => {
        // Sanity: the backend's publicKey is exactly X25519(secret, 9).
        const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        expect(backend.publicKey(scalar)).toEqual(backend.sharedSecret(scalar, BASE_POINT_9));
    });

    it("two independent key pairs agree on the shared secret (DH symmetry, randomized)", () => {
        // Deterministic seeds so the test is reproducible; distinct values so
        // we exercise the DH symmetry on non-trivial scalars.
        const seedA = new Uint8Array(32);
        seedA[0] = 1;
        seedA[1] = 2;
        const seedB = new Uint8Array(32);
        seedB[0] = 3;
        seedB[1] = 4;
        const pubA = backend.publicKey(seedA);
        const pubB = backend.publicKey(seedB);
        const ab = backend.sharedSecret(seedA, pubB);
        const ba = backend.sharedSecret(seedB, pubA);
        expect(ab).toHaveLength(32);
        expect(ab).toEqual(ba);
    });

    it("two distinct public keys yield distinct shared secrets with the same scalar", () => {
        const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const pubA = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        const pubB = fromHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        const sa = backend.sharedSecret(scalar, pubA);
        const sb = backend.sharedSecret(scalar, pubB);
        expect(sa).not.toEqual(sb);
    });

    it("the shared secret is not all-zero for a genuine (non-degenerate) peer", () => {
        const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const pub = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        const secret = backend.sharedSecret(scalar, pub);
        expect(secret).toHaveLength(32);
        expect(secret.some((byte) => byte !== 0)).toBe(true);
    });
});

describe("RFC 7748 §5 degenerate / small-order u-coordinates", () => {
    // RFC 7748 §5 mandates that a degenerate (small-order) u-coordinate yield
    // the all-zero shared secret rather than aborting. The all-zero u
    // coordinate (u = 0, the identity element representation) is the canonical
    // degenerate input. The backend pre-checks for this case and returns 32
    // zero bytes.
    const ZERO = new Uint8Array(32);

    it("returns 32 zero bytes for the all-zero u-coordinate (no throw)", () => {
        const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const secret = backend.sharedSecret(scalar, ZERO);
        expect(secret).toHaveLength(32);
        expect(secret).toEqual(new Uint8Array(32));
    });

    it("the all-zero result is stable across distinct secret scalars", () => {
        const expected = new Uint8Array(32);
        const scalars = [
            fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            fromHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
        ];
        for (const scalar of scalars) {
            // Distinct scalars guarantee we're hitting the degenerate path,
            // not accidentally reusing the same key material.
            expect(backend.sharedSecret(scalar, ZERO)).toEqual(expected);
        }
    });

    it("a genuine (non-degenerate) peer still yields a non-zero secret", () => {
        // Regression guard: the degenerate-input fix must not mask real results.
        const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const pub = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        const secret = backend.sharedSecret(scalar, pub);
        expect(secret).toHaveLength(32);
        expect(secret.some((b) => b !== 0)).toBe(true);
    });
});
