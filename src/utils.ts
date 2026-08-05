/**
 * Small shared helpers for @browsercore/crypto.
 *
 * Kept dependency-free so every package can copy the pattern without pulling in
 * cross-package imports.
 *
 * @module
 * @since 0.1.0
 */

/**
 * Exhaustiveness check for `switch`/`if-else` over discriminated unions.
 *
 * Call in the `default` branch: `default: assertNever(x)`. Adding a new union
 * member forces every handler to compile-error until handled.
 *
 * @param x The value that should never reach this branch (typed as `never`).
 * @returns Never returns — always throws.
 *
 * @example
 * ```ts
 * switch (cipher) {
 *   case "AES-128-GCM": return handleAes128Gcm();
 *   case "AES-256-GCM": return handleAes256Gcm();
 *   default: return assertNever(cipher); // compile error if a cipher is added
 * }
 * ```
 *
 * @throws {Error} Always — indicates an unhandled case.
 * @since 0.1.0
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

/**
 * Generate a unique identifier with a human-readable prefix.
 *
 * Combines a millisecond timestamp (base-36) and a random suffix (base-36)
 * to produce a collision-resistant identifier without requiring a CSPRNG.
 *
 * @param prefix Human-readable prefix (e.g. `"csid"` for session ids).
 * @returns A unique string like `"csid_l4k3x2_1a2b3c"`.
 *
 * @example
 * ```ts
 * const id = createId("conn");
 * // => "conn_l4k3x2_1a2b3c"
 * ```
 *
 * @since 0.1.0
 */
export function createId(prefix: string): string {
    return `${prefix}_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}
