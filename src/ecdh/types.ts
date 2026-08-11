/**
 * The named-curve ECDH backend contract.
 *
 * Higher layers depend on this interface — never on a concrete implementation
 * — so the ECDH backend is replaceable (Node crypto, WebCrypto, HSM, test
 * double). The implementation is pure scalar multiplication over NIST
 * prime-order curves: derive the public point from a private scalar and
 * compute a Diffie-Hellman shared secret from a private scalar plus a peer's
 * public point. All inputs and outputs are raw byte arrays matching the
 * TLS 1.3 KeyShareEntry wire layout — no ASN.1/DER container encoding.
 */

import type { EcdhCurve, EcdhKeyPair } from "../types.js";

/**
 * NIST-curve ECDH primitives for TLS 1.3 key exchange.
 *
 * Implementations derive the public point from a private scalar and compute a
 * Diffie-Hellman shared secret from a private scalar plus a peer's public
 * point. Public keys use the uncompressed wire layout (`0x04 || x || y`);
 * shared secrets are the x-coordinate of the shared point — the raw output the
 * TLS 1.3 key schedule consumes.
 */
export interface EcdhBackend {
    /** Generate an ECDH key pair on the given named curve. */
    generateKeyPair(curve: EcdhCurve): EcdhKeyPair;
    /**
     * Compute the ECDH shared secret on the given named curve.
     * Returns the x-coordinate of the shared point.
     */
    sharedSecret(
        curve: EcdhCurve,
        secretKey: Uint8Array,
        peerPublicKey: Uint8Array,
    ): Uint8Array;
}
