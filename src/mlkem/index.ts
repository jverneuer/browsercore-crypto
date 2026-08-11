/**
 * Barrel for the ML-KEM-768 subpackage.
 *
 * The types module defines the backend contract; the noble-backend provides
 * the pure-TypeScript ML-KEM-768 implementation backed by @noble/post-quantum.
 * Everything re-exports from here.
 */

export type { MlKem768Backend } from "./types.js";
export { NobleMlKem768Backend } from "./noble-backend.js";
