/**
 * Small shared helpers for @browsercore/crypto.
 *
 * Kept dependency-free so every package can copy the pattern without pulling in
 * cross-package imports.
 */
/**
 * Exhaustiveness check for `switch`/`if-else` over discriminated unions.
 * Call in the `default` branch: `default: assertNever(x)`.
 * Adding a new union member forces every handler to compile-error until handled.
 */
export declare function assertNever(x: never): never;
/** Monotonic-ish unique id generator (not cryptographically random). */
export declare function createId(prefix: string): string;
//# sourceMappingURL=utils.d.ts.map