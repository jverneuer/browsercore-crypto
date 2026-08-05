/**
 * The X25519 key-exchange backend contract.
 *
 * Higher layers depend on this interface — never on a concrete implementation —
 * so the X25519 backend is replaceable (Node crypto, WebCrypto, HSM, test
 * double). The implementation is pure scalar multiplication: derive the public
 * coordinate from a private scalar, and compute a shared secret from a private
 * scalar plus a peer's public coordinate. All ASN.1/DER encoding is delegated
 * to the rfc8410 module — this interface deals only in raw 32-byte keys.
 */
/**
 * Pure X25519 scalar multiplication — the only two operations the curve
 * supports. Implementations derive the public coordinate from a private
 * scalar and compute a Diffie-Hellman shared secret from a private scalar
 * plus a peer's public coordinate.
 *
 * All inputs and outputs are raw 32-byte values. ASN.1/DER container encoding
 * (PKCS#8, SPKI) is the responsibility of the rfc8410 module — this interface
 * stays format-agnostic so it never needs to know about DER prefixes.
 */
export interface X25519Backend {
    /** Derive the 32-byte public key from a 32-byte private scalar. */
    publicKey(privateKey: Uint8Array): Uint8Array;
    /** Compute the 32-byte shared secret (raw X25519, no cofactor). */
    sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
}
//# sourceMappingURL=types.d.ts.map