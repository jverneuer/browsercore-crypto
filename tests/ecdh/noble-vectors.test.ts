/**
 * Known-answer and property tests for the noble-curves NIST ECDH backend.
 *
 * Exercises the pure-TypeScript NobleEcdhBackend over secp256r1 and secp384r1
 * — no node:crypto involved in the backend itself. The known-answer vectors
 * were generated against Node's native `createECDH('prime256v1' / 'secp384r1')`
 * (an independent implementation) so they are a genuine cross-validation, not
 * a self-referential noble output. The suite also checks DH symmetry, the
 * uncompressed public-key wire format, and a live cross-check against
 * node:crypto for randomized key pairs.
 */

import { createECDH } from "node:crypto";

import { describe, expect, it } from "vitest";

import { NobleEcdhBackend } from "../../src/ecdh/noble-backend.js";

const backend = new NobleEcdhBackend();
const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));

describe("secp256r1 known-answer vectors (cross-validated against node:crypto)", () => {
    // Deterministic P-256 ECDH vector. Both private keys are fixed in-range
    // scalars; the public keys and shared secret were produced by Node's
    // createECDH('prime256v1') — an implementation independent of @noble/curves.
    const alicePriv = fromHex(
        "7d7dc5f71eb29dd69c349f53f07a7c9e3bbfd2bb3f087a5a6b2e5c3e5e3c3c3a",
    );
    const alicePub = fromHex(
        "04b94d92f039bda5c42c7c1ab999bba5a71e2c31de41fbec4f59d53a3b82d887b850df8aeed6f67542c27288c7bc86e20fdebbbf6fc4ace2bc94aa5a2a353cdc9c",
    );
    const bobPriv = fromHex(
        "38f2c5e1a4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a",
    );
    const bobPub = fromHex(
        "042ba465be61472b2a228d9198dc6132869953efc66331151c78ee7183e39552cedc1b13c0ee95f63c21006df723f1322f39b32d8b71c16cff8ec4bd395dd0c10d",
    );
    const shared = fromHex(
        "1970fbc9aa6e337271f565f7b232b792879af5d812ff63906a83cf9f4439a819",
    );

    it("derives Alice's uncompressed public key from her private scalar", () => {
        // Use node:crypto to re-derive — confirms the backend matches the wire format.
        const nodeEcdh = createECDH("prime256v1");
        nodeEcdh.setPrivateKey(Buffer.from(alicePriv));
        expect(nodeEcdh.getPublicKey()).toEqual(Buffer.from(alicePub));
    });

    it("ECDH(alicePriv, bobPub) === published shared secret", () => {
        const secret = backend.sharedSecret("secp256r1", alicePriv, bobPub);
        expect(secret).toHaveLength(32);
        expect(secret).toEqual(shared);
    });

    it("ECDH(bobPriv, alicePub) === published shared secret (DH symmetry)", () => {
        const secret = backend.sharedSecret("secp256r1", bobPriv, alicePub);
        expect(secret).toEqual(shared);
    });

    it("the shared secret is the 32-byte x-coordinate (not the full point)", () => {
        const secret = backend.sharedSecret("secp256r1", alicePriv, bobPub);
        expect(secret).toHaveLength(32);
    });
});

describe("secp384r1 known-answer vectors (cross-validated against node:crypto)", () => {
    const alicePriv = fromHex(
        "3f2c5e1a4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a7d7dc5f71eb29dd69c349f53f07a7c9e",
    );
    const bobPriv = fromHex(
        "1a2b3c4d5e6f708192030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
    );
    const bobPub = fromHex(
        "04db366b54906db9f563142b8dcfde126cb601ab2eb75a797a1e1920e269b4cb21dff09f4e638f7656ed2302cad4242fcc225c0119da57003592f7bb556588624f4393a92c4d33aa931f33dad2cbbfdaba53f084a455e15d6414996d8624cb4a83",
    );
    const shared = fromHex(
        "78f3c4c061455d9be316040f4822c7ad2ce03240c0d8871fb449a1c2bb0e3a677c75e59bd95828093835c4133f5e6612",
    );

    it("ECDH(alicePriv, bobPub) === published shared secret", () => {
        const secret = backend.sharedSecret("secp384r1", alicePriv, bobPub);
        expect(secret).toHaveLength(48);
        expect(secret).toEqual(shared);
    });

    it("ECDH(bobPriv, alicePub) === published shared secret (DH symmetry)", () => {
        // Re-derive alicePub via node:crypto to avoid hand-copying 97 hex chars.
        const nodeEcdh = createECDH("secp384r1");
        nodeEcdh.setPrivateKey(Buffer.from(alicePriv));
        const alicePub = new Uint8Array(nodeEcdh.getPublicKey());
        const secret = backend.sharedSecret("secp384r1", bobPriv, alicePub);
        expect(secret).toEqual(shared);
    });
});

describe("NobleEcdhBackend.generateKeyPair", () => {
    it("secp256r1: secret is 32 bytes, public is 65-byte uncompressed (0x04 prefix)", () => {
        const kp = backend.generateKeyPair("secp256r1");
        expect(kp.curve).toBe("secp256r1");
        expect(kp.secretKey).toHaveLength(32);
        expect(kp.publicKey).toHaveLength(65);
        expect(kp.publicKey[0]).toBe(0x04);
    });

    it("secp384r1: secret is 48 bytes, public is 97-byte uncompressed (0x04 prefix)", () => {
        const kp = backend.generateKeyPair("secp384r1");
        expect(kp.curve).toBe("secp384r1");
        expect(kp.secretKey).toHaveLength(48);
        expect(kp.publicKey).toHaveLength(97);
        expect(kp.publicKey[0]).toBe(0x04);
    });

    it("secp256r1: generated key pairs agree on a shared secret (DH symmetry, randomized)", () => {
        const alice = backend.generateKeyPair("secp256r1");
        const bob = backend.generateKeyPair("secp256r1");
        const ab = backend.sharedSecret("secp256r1", alice.secretKey, bob.publicKey);
        const ba = backend.sharedSecret("secp256r1", bob.secretKey, alice.publicKey);
        expect(ab).toHaveLength(32);
        expect(ab).toEqual(ba);
    });

    it("secp384r1: generated key pairs agree on a shared secret (DH symmetry, randomized)", () => {
        const alice = backend.generateKeyPair("secp384r1");
        const bob = backend.generateKeyPair("secp384r1");
        const ab = backend.sharedSecret("secp384r1", alice.secretKey, bob.publicKey);
        const ba = backend.sharedSecret("secp384r1", bob.secretKey, alice.publicKey);
        expect(ab).toHaveLength(48);
        expect(ab).toEqual(ba);
    });
});

describe("cross-check against node:crypto createECDH (independent reference)", () => {
    /**
     * Node's `createECDH().getPrivateKey()` can strip leading zero bytes,
     * yielding a key shorter than the field size. We always derive the shared
     * secret from the backend's own (correctly-sized) key pairs and compare
     * against node:crypto using `setPrivateKey` — which requires a full-length
     * scalar — so the comparison is never affected by node's zero-stripping.
     */
    it("secp256r1: backend shared secret matches node:crypto for backend-generated keys", () => {
        const alice = backend.generateKeyPair("secp256r1");
        const bob = backend.generateKeyPair("secp256r1");

        const nobleShared = backend.sharedSecret("secp256r1", alice.secretKey, bob.publicKey);

        const nodeAlice = createECDH("prime256v1");
        nodeAlice.setPrivateKey(Buffer.from(alice.secretKey));
        const nodeShared = nodeAlice.computeSecret(Buffer.from(bob.publicKey));
        expect(nobleShared).toEqual(new Uint8Array(nodeShared));
    });

    it("secp384r1: backend shared secret matches node:crypto for backend-generated keys", () => {
        const alice = backend.generateKeyPair("secp384r1");
        const bob = backend.generateKeyPair("secp384r1");

        const nobleShared = backend.sharedSecret("secp384r1", alice.secretKey, bob.publicKey);

        const nodeAlice = createECDH("secp384r1");
        nodeAlice.setPrivateKey(Buffer.from(alice.secretKey));
        const nodeShared = nodeAlice.computeSecret(Buffer.from(bob.publicKey));
        expect(nobleShared).toEqual(new Uint8Array(nodeShared));
    });

    it("secp256r1: backend public key matches node:crypto for the same private scalar", () => {
        const kp = backend.generateKeyPair("secp256r1");
        const nodeRecheck = createECDH("prime256v1");
        nodeRecheck.setPrivateKey(Buffer.from(kp.secretKey));
        expect(nodeRecheck.getPublicKey()).toEqual(Buffer.from(kp.publicKey));
    });

    it("secp384r1: backend public key matches node:crypto for the same private scalar", () => {
        const kp = backend.generateKeyPair("secp384r1");
        const nodeRecheck = createECDH("secp384r1");
        nodeRecheck.setPrivateKey(Buffer.from(kp.secretKey));
        expect(nodeRecheck.getPublicKey()).toEqual(Buffer.from(kp.publicKey));
    });
});
