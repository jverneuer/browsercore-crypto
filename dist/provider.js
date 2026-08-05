/**
 * The cryptographic provider contract for @browsercore/crypto.
 *
 * Higher layers depend on this interface — never on a concrete provider — so the
 * backend is replaceable (WebCrypto, HSM, test double). The TLS implementation
 * calls these methods, never `node:crypto` directly.
 */
export {};
//# sourceMappingURL=provider.js.map