/**
 * Barrel for the x25519 subpackage.
 *
 * The rfc8410 module is the single place DER is built for X25519 keys; the types
 * module defines the backend contract. The noble-backend provides the
 * pure-TypeScript X25519 implementation. Everything re-exports from here.
 */

export { rawPrivateToPkcs8, pkcs8ToRaw, rawPublicToSpki, spkiToRaw } from "./rfc8410.js";
export type { X25519Backend } from "./types.js";
export { NobleX25519Backend } from "./noble-backend.js";
