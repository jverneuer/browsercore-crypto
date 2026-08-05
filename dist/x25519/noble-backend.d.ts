/**
 * Pure TypeScript X25519 backend backed by @noble/curves.
 *
 * This module is intentionally free of any `node:crypto` import — raw 32-byte
 * scalars in, raw 32-byte coordinates out. noble-curves handles clamping
 * internally, which removes the entire ASN.1/DER bug class that plagues the
 * Node backend (see src/x25519.ts). That makes this the recommended default
 * backend for the crypto provider.
 */
/**
 * The X25519 backend contract. A backend provides raw scalar-multiplication
 * and Diffie-Hellman over curve25519 without coupling to any particular
 * crypto implementation (Node, WebCrypto, HSM). Implementations MUST clamp
 * the scalar per RFC 7748 §5 — but callers need not do so themselves.
 */
export interface X25519Backend {
    /** Derive the public coordinate from a 32-byte private scalar. */
    publicKey(privateKey: Uint8Array): Uint8Array;
    /**
     * Compute the X25519 shared secret between a private scalar and a peer's
     * public coordinate. Both inputs are raw 32-byte little-endian values.
     */
    sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
}
/**
 * Noble-curves-backed {@link X25519Backend}.
 *
 * Uses the audited, constant-time @noble/curves implementation. All operations
 * run in pure JS with no native bindings, so the same code path executes on
 * every platform — no subtle behavior differences between Node, Deno, and
 * browser environments.
 */
export declare class NobleX25519Backend implements X25519Backend {
    publicKey(privateKey: Uint8Array): Uint8Array;
    sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
}
//# sourceMappingURL=noble-backend.d.ts.map