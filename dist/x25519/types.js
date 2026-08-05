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
export {};
//# sourceMappingURL=types.js.map