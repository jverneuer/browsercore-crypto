/**
 * Pure TypeScript ECDH backend for NIST curves, backed by @noble/curves.
 *
 * This module is intentionally free of any `node:crypto` import — raw scalar
 * bytes in, raw point bytes out. noble-curves handles point validation and
 * constant-time scalar multiplication internally, which makes this a
 * side-channel-resistant default backend for the crypto provider.
 *
 * The public-key layout is the uncompressed form (`0x04 || x || y`) that TLS
 * 1.3 KeyShareEntry expects on the wire. The shared secret is the
 * x-coordinate of the shared point — the exact value the TLS 1.3 key schedule
 * feeds into HKDF-Extract.
 */

import { p256, p384 } from "@noble/curves/nist.js";

import type { EcdhCurve, EcdhKeyPair } from "../types.js";
import type { EcdhBackend } from "./types.js";

/**
 * Field-element size in bytes for each supported NIST curve.
 *
 * secp256r1 has a 256-bit field (32 bytes); secp384r1 has a 384-bit field
 * (48 bytes). This drives both the secret-key length and the slice into the
 * shared point that yields the x-coordinate shared secret.
 */
const FIELD_BYTES: Readonly<Record<EcdhCurve, number>> = Object.freeze({
    secp256r1: 32,
    secp384r1: 48,
});

/**
 * noble-curves ECDH/ECSA interface — the subset we use (`keygen`,
 * `getPublicKey`, `getSharedSecret`). Both {@link p256} and {@link p384}
 * satisfy this shape; indexing by curve name keeps the backend curve-agnostic.
 */
interface NobleEcdhApi {
    /** Generate a fresh random secret scalar. */
    keygen(): { secretKey: Uint8Array; publicKey: Uint8Array };
    /** Derive the public point from a secret scalar. */
    getPublicKey(secretKey: Uint8Array, isCompressed?: boolean): Uint8Array;
    /** Scalar-multiply a secret by a public point (the DH operation). */
    getSharedSecret(secretKey: Uint8Array, publicKey: Uint8Array, isCompressed?: boolean): Uint8Array;
}

/**
 * The noble-curves API for each supported curve, indexed by {@link EcdhCurve}.
 *
 * Frozen so callers cannot swap a curve implementation at runtime.
 */
const CURVE_API: Readonly<Record<EcdhCurve, NobleEcdhApi>> = Object.freeze({
    secp256r1: p256,
    secp384r1: p384,
});

/**
 * Noble-curves-backed {@link EcdhBackend} for NIST prime-order curves.
 *
 * Uses the audited, constant-time @noble/curves implementation. All operations
 * run in pure JS with no native bindings, so the same code path executes on
 * every platform — no subtle behavior differences between Node, Deno, and
 * browser environments.
 *
 * @since 0.3.0
 */
export class NobleEcdhBackend implements EcdhBackend {
    public generateKeyPair(curve: EcdhCurve): EcdhKeyPair {
        const api = CURVE_API[curve];
        // keygen returns a random scalar; we re-derive the public key in
        // uncompressed form so the output matches the TLS 1.3 wire layout.
        const { secretKey } = api.keygen();
        const publicKey = api.getPublicKey(secretKey, false);
        return { curve, publicKey, secretKey };
    }

    public sharedSecret(
        curve: EcdhCurve,
        secretKey: Uint8Array,
        peerPublicKey: Uint8Array,
    ): Uint8Array {
        const api = CURVE_API[curve];
        // isCompressed=false yields the uncompressed shared point
        // (0x04 || x || y); the TLS 1.3 shared secret is the x-coordinate,
        // which occupies bytes [1 .. 1+fieldBytes] of that encoding.
        const fieldBytes = FIELD_BYTES[curve];
        const sharedPoint = api.getSharedSecret(secretKey, peerPublicKey, false);
        return sharedPoint.subarray(1, 1 + fieldBytes);
    }
}
