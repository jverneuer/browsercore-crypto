/**
 * @browsercore/crypto — provider abstraction.
 *
 * This file is a barrel: the implementation lives in focused domain modules
 * (provider contract, X25519 conversion). The Node-backed provider, AEAD
 * primitives, and node-backend now live in `browsersmith/src/platform/crypto/node/`
 * so that this package has zero `node:*` imports.
 */

export type { CryptoProvider } from "./provider.js";
