/**
 * X25519 backend abstraction and its pure-TypeScript implementation.
 *
 * The default export is a {@link NobleX25519Backend} instance so consumers can
 * import-and-call without constructing anything. The interface and class are
 * re-exported for providers and tests that need the types.
 */

export type { X25519Backend } from "./noble-backend.js";
export { NobleX25519Backend } from "./noble-backend.js";

import { NobleX25519Backend } from "./noble-backend.js";

/**
 * Default X25519 backend instance — pure TypeScript, no node:crypto.
 * Use this unless you have a specific reason to swap the implementation.
 */
export const defaultX25519Backend = new NobleX25519Backend();
