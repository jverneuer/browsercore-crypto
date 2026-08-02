/**
 * @browsercore/crypto — provider abstraction and its Node backend.
 *
 * This file is a barrel: the implementation lives in focused domain modules
 * (provider contract, AEAD primitives, X25519 conversion, Node-backed provider),
 * while these re-exports preserve every historical import path used by tests and
 * the public index surface.
 */

export type { CryptoProvider } from "./provider.js";
export { aeadEncrypt, aeadDecrypt } from "./aead.js";
export { NodeCryptoProvider, crypto } from "./node-crypto-provider.js";
