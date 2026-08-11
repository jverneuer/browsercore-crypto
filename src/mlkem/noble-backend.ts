/**
 * Pure TypeScript ML-KEM-768 backend backed by @noble/post-quantum.
 *
 * This module is intentionally free of any `node:crypto` import — raw byte
 * arrays in, raw byte arrays out. ML-KEM-768 (FIPS 203, formerly Kyber) is a
 * module-lattice Key Encapsulation Mechanism. The @noble/post-quantum
 * implementation runs in constant time where it matters, with no native
 * bindings, so the same code path executes on every platform.
 *
 * Three operations are exposed, matching the {@link MlKem768Backend} contract:
 * key generation (server holds the decapsulation key), encapsulation (client
 * side — produces the ciphertext sent over the wire plus the shared secret),
 * and decapsulation (server side — recovers the shared secret from the
 * received ciphertext).
 *
 * The ciphertext naming is bridged here: @noble/post-quantum exposes the
 * property as `cipherText` (camelCase) while the package's public types use the
 * lowercase `ciphertext` to match the TLS / FIPS-203 vocabulary. This is the
 * single place that translation happens.
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import type { MLKEM768Encapsulation, MLKEM768KeyPair } from "../types.js";
import { ensureCryptoError } from "../errors.js";
import type { MlKem768Backend } from "./types.js";

/**
 * Noble-post-quantum-backed {@link MlKem768Backend}.
 *
 * Uses the audited @noble/post-quantum implementation of ML-KEM-768. All
 * operations run in pure JS with no native bindings, so the same code path
 * executes on every platform.
 *
 * @since 0.3.0
 */
export class NobleMlKem768Backend implements MlKem768Backend {
    public generateKeyPair(): MLKEM768KeyPair {
        try {
            return ml_kem768.keygen();
        } catch (e) {
            // keygen is deterministic over the internal DRBG — a failure here
            // indicates a programming error or a corrupted build. Wrap it so
            // callers never see an untyped throw.
            throw ensureCryptoError(e, "ML-KEM-768");
        }
    }

    public encapsulate(publicKey: Uint8Array): MLKEM768Encapsulation {
        try {
            const result = ml_kem768.encapsulate(publicKey);
            // Bridge the noble camelCase (`cipherText`) to the package's
            // lowercase vocabulary (`ciphertext`).
            return {
                ciphertext: result.cipherText,
                sharedSecret: result.sharedSecret,
            };
        } catch (e) {
            throw ensureCryptoError(e, "ML-KEM-768");
        }
    }

    public decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        try {
            return ml_kem768.decapsulate(ciphertext, secretKey);
        } catch (e) {
            throw ensureCryptoError(e, "ML-KEM-768");
        }
    }
}
