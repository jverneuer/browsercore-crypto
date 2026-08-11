/**
 * Barrel for the NIST-curve ECDH subpackage.
 *
 * The types module defines the backend contract; the noble-backend provides
 * the pure-TypeScript ECDH implementation over secp256r1 / secp384r1. Everything
 * re-exports from here.
 */

export type { EcdhBackend } from "./types.js";
export { NobleEcdhBackend } from "./noble-backend.js";
