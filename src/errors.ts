/**
 * Typed errors for @browsercore/crypto.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 */

import { assertNever } from "./utils.js";

/**
 * The set of all crypto-error discriminator values. Declared as a union so each
 * subclass can narrow `kind` to its own literal while still satisfying the base
 * class's property type (a single `"CryptoError"` literal would forbid that).
 */
export type CryptoErrorKind = "CryptoError" | "UnsupportedAlgorithmError" | "DecryptError";

/** Base class for all crypto errors. Carries the algorithm that failed, if known. */
export class CryptoError extends Error {
    public readonly kind: CryptoErrorKind = "CryptoError";
    /** Algorithm identifier that triggered the error, when applicable. */
    public readonly algorithm: string | undefined;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    constructor(
        message: string,
        algorithm?: string,
        options?: { cause?: Error },
    ) {
        super(message, options);
        this.name = new.target.name;
        this.algorithm = algorithm;
        this.cause = options?.cause;
    }
}

/**
 * The requested algorithm is not supported by this provider.
 *
 * Extends {@link CryptoError} so it flows through {@link ensureCryptoError}
 * unchanged (preserving `kind`) and satisfies `instanceof CryptoError`.
 */
export class UnsupportedAlgorithmError extends CryptoError {
    public override readonly kind = "UnsupportedAlgorithmError" as const;
    public override readonly algorithm: string;

    constructor(algorithm: string) {
        // Align with CryptoError's (message, algorithm?, options?) signature so
        // the base class records the algorithm and sets `name` via new.target.
        super(`Unsupported crypto algorithm: ${algorithm}`, algorithm);
        this.algorithm = algorithm;
    }
}

/**
 * Decryption failed — authentication tag mismatch or corrupt input.
 *
 * Extends {@link CryptoError} so it flows through {@link ensureCryptoError}
 * unchanged (preserving `kind`) and satisfies `instanceof CryptoError`.
 */
export class DecryptError extends CryptoError {
    public override readonly kind = "DecryptError" as const;
    public override readonly algorithm: string;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    constructor(algorithm: string, options?: { cause?: Error }) {
        // Align with CryptoError's (message, algorithm?, options?) signature so
        // the base class records the algorithm/cause and sets `name` via new.target.
        super(
            `Decryption failed for ${algorithm}: authentication mismatch or corrupt input`,
            algorithm,
            options,
        );
        this.algorithm = algorithm;
        this.cause = options?.cause;
    }
}

/** Narrow a caught error to a typed crypto error, or wrap it in CryptoError. */
export function ensureCryptoError(e: unknown, algorithm?: string): CryptoError {
    if (e instanceof CryptoError) {
        return e;
    }
    if (e instanceof Error) {
        return new CryptoError(e.message, algorithm, { cause: e });
    }
    return new CryptoError(typeof e === "string" ? e : "unknown crypto error", algorithm);
}

void assertNever; // referenced for tree-shaking safety in bundlers
