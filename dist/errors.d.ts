/**
 * Typed errors for @browsercore/crypto.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 */
/**
 * The set of all crypto-error discriminator values. Declared as a union so each
 * subclass can narrow `kind` to its own literal while still satisfying the base
 * class's property type (a single `"CryptoError"` literal would forbid that).
 */
export type CryptoErrorKind = "CryptoError" | "UnsupportedAlgorithmError" | "DecryptError";
/** Base class for all crypto errors. Carries the algorithm that failed, if known. */
export declare class CryptoError extends Error {
    readonly kind: CryptoErrorKind;
    /** Algorithm identifier that triggered the error, when applicable. */
    readonly algorithm: string | undefined;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    readonly cause: Error | undefined;
    constructor(message: string, algorithm?: string, options?: {
        cause?: Error;
    });
}
/**
 * The requested algorithm is not supported by this provider.
 *
 * Extends {@link CryptoError} so it flows through {@link ensureCryptoError}
 * unchanged (preserving `kind`) and satisfies `instanceof CryptoError`.
 */
export declare class UnsupportedAlgorithmError extends CryptoError {
    readonly kind: "UnsupportedAlgorithmError";
    readonly algorithm: string;
    constructor(algorithm: string);
}
/**
 * Decryption failed — authentication tag mismatch or corrupt input.
 *
 * Extends {@link CryptoError} so it flows through {@link ensureCryptoError}
 * unchanged (preserving `kind`) and satisfies `instanceof CryptoError`.
 */
export declare class DecryptError extends CryptoError {
    readonly kind: "DecryptError";
    readonly algorithm: string;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    readonly cause: Error | undefined;
    constructor(algorithm: string, options?: {
        cause?: Error;
    });
}
/** Narrow a caught error to a typed crypto error, or wrap it in CryptoError. */
export declare function ensureCryptoError(e: unknown, algorithm?: string): CryptoError;
//# sourceMappingURL=errors.d.ts.map