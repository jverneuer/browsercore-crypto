/**
 * node:crypto-backed X25519 scalar multiplication.
 *
 * Delegates all ASN.1 (PKCS#8 / SPKI DER wrapping) to fixed RFC 8410 prefixes
 * so the OpenSSL implementation owns the curve arithmetic. This is the tested
 * alternative to the noble-curves backend — it trades the dependency for a
 * double-clamping suspicion documented where it matters.
 *
 * If `src/x25519/rfc8410.ts` exists (a parallel task), import
 * `rawPrivateToPkcs8` / `rawPublicToSpki` from there so this file holds ZERO
 * hardcoded DER bytes. Until then, the conversions live inline below.
 */
/**
 * The X25519 scalar-multiplication backend contract. Higher layers depend on
 * this interface — never on a concrete backend — so the implementation is
 * replaceable (noble-curves, WebCrypto, HSM).
 */
export interface X25519Backend {
    /**
     * Compute the X25519 shared secret between the raw 32-byte private scalar
     * `priv` and the raw 32-byte public u-coordinate `pub`. Returns 32 bytes,
     * or 32 zero bytes for degenerate (small-order) u-coordinates.
     */
    sharedSecret(priv: Uint8Array, pub: Uint8Array): Uint8Array;
    /** Generate an X25519 key pair (32-byte keys). */
    generateKeyPair(): {
        publicKey: Uint8Array;
        secretKey: Uint8Array;
    };
}
export declare class NodeX25519Backend implements X25519Backend {
    sharedSecret(priv: Uint8Array, pub: Uint8Array): Uint8Array;
    generateKeyPair(): {
        publicKey: Uint8Array;
        secretKey: Uint8Array;
    };
}
//# sourceMappingURL=node-backend.d.ts.map