/**
 * Typed errors for @browsercore/crypto.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 *
 * @module
 * @since 0.1.0
 */

import { assertNever } from "./utils.js";

/**
 * The set of all crypto-error discriminator values.
 *
 * Declared as a union so each subclass can narrow `kind` to its own literal
 * while still satisfying the base class's property type (a single
 * `"CryptoError"` literal would forbid that).
 *
 * @since 0.1.0
 */
export type CryptoErrorKind = "CryptoError" | "UnsupportedAlgorithmError" | "DecryptError";

/**
 * Base class for all crypto errors.
 *
 * Carries the algorithm that failed (if known) and an optional `cause` for
 * chaining. All typed crypto errors extend this class, so `instanceof CryptoError`
 * catches every failure from the provider.
 *
 * @since 0.1.0
 */
export class CryptoError extends Error {
    /** Discriminator for narrowing — always `"CryptoError"` on the base class. */
    public readonly kind: CryptoErrorKind = "CryptoError";
    /** Algorithm identifier that triggered the error, when applicable. */
    public readonly algorithm: string | undefined;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    /**
     * Create a {@link CryptoError}.
     *
     * @param message   Human-readable error message.
     * @param algorithm Algorithm identifier that triggered the error, when applicable.
     * @param options   Optional cause chain.
     * @param options.cause The underlying error that caused this failure.
     */
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
 *
 * @since 0.1.0
 */
export class UnsupportedAlgorithmError extends CryptoError {
    public override readonly kind = "UnsupportedAlgorithmError" as const;
    public override readonly algorithm: string;

    /**
     * Create an {@link UnsupportedAlgorithmError}.
     *
     * @param algorithm The algorithm identifier that is not supported.
     */
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
 *
 * @since 0.1.0
 */
export class DecryptError extends CryptoError {
    public override readonly kind = "DecryptError" as const;
    public override readonly algorithm: string;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    /**
     * Create a {@link DecryptError}.
     *
     * @param algorithm The algorithm identifier being decoded when the failure happened.
     * @param options   Optional cause chain.
     * @param options.cause The underlying backend error that caused this failure.
     */
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

/**
 * Narrow a caught error to a typed crypto error, or wrap it in {@link CryptoError}.
 *
 * Use this at API boundaries to guarantee that every thrown value is a typed
 * {@link CryptoError}` subclass — callers can then match on `kind` instead of
 * parsing messages.
 *
 * @param e          The caught unknown value.
 * @param algorithm  Optional algorithm identifier to attach to the wrapped error.
 * @returns A typed {@link CryptoError} — either `e` itself (if already typed)
 *          or a new wrapping instance.
 *
 * @example
 * ```ts
 * try {
 *   cipher.decrypt(key, nonce, ciphertext, aad);
 * } catch (e) {
 *   throw ensureCryptoError(e, "AES-256-GCM");
 * }
 * ```
 *
 * @since 0.1.0
 */
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
