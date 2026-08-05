/**
 * Barrel for the x25519 subpackage.
 *
 * The rfc8410 module is the single place DER is built for X25519 keys; the types
 * module defines the backend contract. The noble-backend provides the default
 * pure-TypeScript X25519 implementation; the node-backend is the alternative.
 * Everything re-exports from here.
 */

export { rawPrivateToPkcs8, pkcs8ToRaw, rawPublicToSpki, spkiToRaw } from "./rfc8410.js";
export type { X25519Backend } from "./types.js";
export { NobleX25519Backend } from "./noble-backend.js";
export { NodeX25519Backend } from "./node-backend.js";

import { NobleX25519Backend } from "./noble-backend.js";

/**
 * Default X25519 backend instance — pure TypeScript, no node:crypto.
 * Use this unless you have a specific reason to swap the implementation.
 */
export const defaultX25519Backend = new NobleX25519Backend();
