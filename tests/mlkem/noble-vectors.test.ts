/**
 * Round-trip and property tests for the @noble/post-quantum ML-KEM-768 backend.
 *
 * ML-KEM-768 (FIPS 203, formerly Kyber) is a Key Encapsulation Mechanism: the
 * decapsulation key holder generates a key pair, the encapsulating side
 * produces a ciphertext + shared secret from the encapsulation key, and the
 * decapsulation key holder recovers the identical shared secret. There are no
 * published NIST CAVP answer files bundled with the runtime, so correctness is
 * verified via the round-trip identity (the defining property of a correct
 * KEM) and strict parameter-size checks mandated by FIPS 203. The hybrid
 * X25519MLKEM768 secret — the concatenation of the classical and post-quantum
 * shared secrets — is verified to match the independent components.
 */

import { describe, expect, it } from "vitest";

import { NobleX25519Backend } from "../../src/x25519/noble-backend.js";
import { NobleMlKem768Backend } from "../../src/mlkem/noble-backend.js";
import {
    MLKEM768_CIPHERTEXT_LENGTH,
    MLKEM768_PUBLIC_KEY_LENGTH,
    MLKEM768_SECRET_KEY_LENGTH,
    MLKEM768_SHARED_SECRET_LENGTH,
} from "../../src/types.js";

const mlkem = new NobleMlKem768Backend();

describe("NobleMlKem768Backend.generateKeyPair", () => {
    it("produces a key pair with the FIPS 203 ML-KEM-768 parameter sizes", () => {
        const kp = mlkem.generateKeyPair();
        expect(kp.publicKey).toHaveLength(MLKEM768_PUBLIC_KEY_LENGTH);
        expect(kp.secretKey).toHaveLength(MLKEM768_SECRET_KEY_LENGTH);
    });

    it("1184-byte public key and 2400-byte secret key", () => {
        const kp = mlkem.generateKeyPair();
        expect(kp.publicKey).toHaveLength(1184);
        expect(kp.secretKey).toHaveLength(2400);
    });

    it("distinct key pairs are statistically different", () => {
        const a = mlkem.generateKeyPair();
        const b = mlkem.generateKeyPair();
        expect(a.publicKey).not.toEqual(b.publicKey);
        expect(a.secretKey).not.toEqual(b.secretKey);
    });
});

describe("ML-KEM-768 encapsulation / decapsulation round-trip", () => {
    it("decapsulation recovers the exact shared secret the encapsulator derived", () => {
        const kp = mlkem.generateKeyPair();
        const encapsulation = mlkem.encapsulate(kp.publicKey);
        const decapsulated = mlkem.decapsulate(kp.secretKey, encapsulation.ciphertext);
        expect(decapsulated).toEqual(encapsulation.sharedSecret);
    });

    it("the ciphertext is 1088 bytes and the shared secret is 32 bytes", () => {
        const kp = mlkem.generateKeyPair();
        const { ciphertext, sharedSecret } = mlkem.encapsulate(kp.publicKey);
        expect(ciphertext).toHaveLength(MLKEM768_CIPHERTEXT_LENGTH);
        expect(sharedSecret).toHaveLength(MLKEM768_SHARED_SECRET_LENGTH);
    });

    it("the round-trip is stable across many independent key pairs", () => {
        for (let i = 0; i < 10; i++) {
            const kp = mlkem.generateKeyPair();
            const encapsulation = mlkem.encapsulate(kp.publicKey);
            const decapsulated = mlkem.decapsulate(kp.secretKey, encapsulation.ciphertext);
            expect(decapsulated).toEqual(encapsulation.sharedSecret);
        }
    });

    it("distinct encapsulations under the same public key yield distinct ciphertexts", () => {
        const kp = mlkem.generateKeyPair();
        const a = mlkem.encapsulate(kp.publicKey);
        const b = mlkem.encapsulate(kp.publicKey);
        expect(a.ciphertext).not.toEqual(b.ciphertext);
        expect(a.sharedSecret).not.toEqual(b.sharedSecret);
        // Both must still decapsulate correctly.
        expect(mlkem.decapsulate(kp.secretKey, a.ciphertext)).toEqual(a.sharedSecret);
        expect(mlkem.decapsulate(kp.secretKey, b.ciphertext)).toEqual(b.sharedSecret);
    });
});

describe("ML-KEM-768 error handling", () => {
    it("encapsulate wraps a malformed public key as a CryptoError", async () => {
        const { CryptoError } = await import("../../src/errors.js");
        expect(() => mlkem.encapsulate(new Uint8Array(10))).toThrow(CryptoError);
    });

    it("decapsulate wraps a malformed ciphertext / secret key as a CryptoError", async () => {
        const { CryptoError } = await import("../../src/errors.js");
        const kp = mlkem.generateKeyPair();
        expect(() => mlkem.decapsulate(kp.secretKey, new Uint8Array(10))).toThrow(CryptoError);
    });
});

/**
 * The hybrid shared-secret layout for TLS 1.3 X25519MLKEM768:
 * `x25519_shared_secret || mlkem_shared_secret` (draft-ietf-tls-hybrid-design).
 *
 * This recomputes the concatenation from the two independent backends and
 * verifies it matches the documented hybrid composition. The x25519 side uses
 * the RFC 7748 §6.1 published DH vector so the hybrid output is fully
 * deterministic and reproducible.
 */
describe("X25519MLKEM768 hybrid shared secret composition", () => {
    const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));
    const x25519 = new NobleX25519Backend();

    // RFC 7748 §6.1 vector — deterministic X25519 inputs.
    const alicePriv = fromHex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
    const bobPub = fromHex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    );
    const x25519Shared = fromHex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    );

    it("x25519 shared secret matches the RFC 7748 §6.1 vector", () => {
        expect(x25519.sharedSecret(alicePriv, bobPub)).toEqual(x25519Shared);
    });

    it("hybrid secret is x25519_shared || mlkem_shared (64 bytes total)", () => {
        const mlkemKp = mlkem.generateKeyPair();
        const mlkemEnc = mlkem.encapsulate(mlkemKp.publicKey);
        const mlkemShared = mlkem.decapsulate(mlkemKp.secretKey, mlkemEnc.ciphertext);

        const hybrid = concat(
            x25519.sharedSecret(alicePriv, bobPub),
            mlkemShared,
        );
        expect(hybrid).toHaveLength(64);
        expect(hybrid.subarray(0, 32)).toEqual(x25519Shared);
        expect(hybrid.subarray(32)).toEqual(mlkemShared);
    });

    it("hybrid secret is deterministic for fixed x25519 + fixed mlkem inputs", () => {
        // Encapsulate once, then recompute the hybrid from the same inputs —
        // the two recomputations must be byte-identical.
        const mlkemKp = mlkem.generateKeyPair();
        const mlkemEnc = mlkem.encapsulate(mlkemKp.publicKey);
        const mlkemShared = mlkem.decapsulate(mlkemKp.secretKey, mlkemEnc.ciphertext);

        const h1 = concat(x25519.sharedSecret(alicePriv, bobPub), mlkemShared);
        const h2 = concat(x25519.sharedSecret(alicePriv, bobPub), mlkemShared);
        expect(h1).toEqual(h2);
    });
});

/** Concatenate two byte arrays into a fresh copy. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}
