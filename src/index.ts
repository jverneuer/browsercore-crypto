/**
 * @browsercore/crypto — public API surface.
 *
 * A clean abstraction wrapping crypto primitives. The TLS implementation
 * calls these methods — never `node:crypto` directly — so the backend is
 * replaceable (WebCrypto, HSM, test double).
 *
 * The Node-backed implementation (NodeCryptoProvider, AEAD, node-backend)
 * lives in `browsersmith/src/platform/crypto/node/` — this package exports
 * only pure types, errors, and utilities with zero `node:*` imports.
 */

export type { CryptoProvider } from "./crypto.js";

export {
    CryptoError,
    DecryptError,
    UnsupportedAlgorithmError,
    ensureCryptoError,
} from "./errors.js";
export type { CryptoErrorKind } from "./errors.js";

export {
    type AeadCipher,
    type Aes128GcmId,
    type Aes256GcmId,
    type Aes128CcmId,
    type ChaCha20Poly1305Id,
    type CryptoSessionId,
    type EcdhCurve,
    type EcdhKeyPair,
    type HashId,
    type KeyExchangeId,
    type Sha256Id,
    type Sha384Id,
    type SymmetricCipherId,
    type X25519Id,
    type X25519KeyPair,
    AES_128_GCM,
    AES_256_GCM,
    AES_128_CCM,
    CHACHA20_POLY1305,
    SHA_256,
    SHA_384,
    X25519,
    createCryptoSessionId,
} from "./types.js";

export { assertNever, createId } from "./utils.js";

export { rawPrivateToPkcs8, pkcs8ToRaw, rawPublicToSpki, spkiToRaw } from "./x25519/index.js";
export { NobleX25519Backend } from "./x25519/index.js";
export type { X25519Backend } from "./x25519/index.js";
