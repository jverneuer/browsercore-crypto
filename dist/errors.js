/**
 * Typed errors for @browsercore/crypto.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 */
import { assertNever } from "./utils.js";
/** Base class for all crypto errors. Carries the algorithm that failed, if known. */
export class CryptoError extends Error {
    kind = "CryptoError";
    /** Algorithm identifier that triggered the error, when applicable. */
    algorithm;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    cause;
    constructor(message, algorithm, options) {
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
    kind = "UnsupportedAlgorithmError";
    algorithm;
    constructor(algorithm) {
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
    kind = "DecryptError";
    algorithm;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    cause;
    constructor(algorithm, options) {
        // Align with CryptoError's (message, algorithm?, options?) signature so
        // the base class records the algorithm/cause and sets `name` via new.target.
        super(`Decryption failed for ${algorithm}: authentication mismatch or corrupt input`, algorithm, options);
        this.algorithm = algorithm;
        this.cause = options?.cause;
    }
}
/** Narrow a caught error to a typed crypto error, or wrap it in CryptoError. */
export function ensureCryptoError(e, algorithm) {
    if (e instanceof CryptoError) {
        return e;
    }
    if (e instanceof Error) {
        return new CryptoError(e.message, algorithm, { cause: e });
    }
    return new CryptoError(typeof e === "string" ? e : "unknown crypto error", algorithm);
}
void assertNever; // referenced for tree-shaking safety in bundlers
//# sourceMappingURL=errors.js.map