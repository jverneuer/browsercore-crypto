/**
 * {@link CryptoProvider} backed by Node's native `node:crypto` module.
 *
 * Higher layers call the provider methods here, never `node:crypto` directly, so the
 * backend stays replaceable. Exported as the default singleton so consumers can call
 * `crypto.hkdf(...)` without threading a provider through every constructor.
 */

import {
    randomBytes as nodeRandomBytes,
    createHash,
    createHmac,
    hkdfSync,
    generateKeyPairSync,
    createPublicKey,
    createVerify,
    diffieHellman,
    constants,
} from "node:crypto";

import {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    type HashId,
    type X25519KeyPair,
} from "./types.js";
import { UnsupportedAlgorithmError } from "./errors.js";
import { assertNever } from "./utils.js";
import { aeadEncrypt, aeadDecrypt } from "./aead.js";
import { x25519PrivateKeyFromRaw, x25519PublicKeyFromRaw, X25519_PUB_PREFIX, X25519_PRIV_PREFIX } from "./x25519.js";
import type { CryptoProvider } from "./provider.js";

/**
 * Map a branded {@link HashId} to the algorithm string Node's `node:crypto`
 * expects. Exhaustive — adding a member to {@link HashId} forces every branch
 * below to compile-error until handled.
 */
function hashAlgorithmName(hash: HashId): string {
    switch (hash) {
        case "SHA-256":
            return "sha256";
        case "SHA-384":
            return "sha384";
        default:
            return assertNever(hash);
    }
}

export class NodeCryptoProvider implements CryptoProvider {
    public randomBytes(length: number): Uint8Array {
        return nodeRandomBytes(length);
    }

    public sha256(data: Uint8Array): Uint8Array {
        return createHash("sha256").update(data).digest();
    }

    public sha384(data: Uint8Array): Uint8Array {
        return createHash("sha384").update(data).digest();
    }

    public hkdf(
        hash: HashId,
        salt: Uint8Array,
        ikm: Uint8Array,
        info: Uint8Array,
        length: number,
    ): Uint8Array {
        // node:crypto.hkdfSync(digest, ikm, salt, info, length).
        const digest = hashAlgorithmName(hash);
        const key = hkdfSync(digest, ikm, salt, info, length);
        return new Uint8Array(key);
    }

    public hmac(hash: HashId, key: Uint8Array, data: Uint8Array): Uint8Array {
        const algorithm = hashAlgorithmName(hash);
        const digest = createHmac(algorithm, key).update(data).digest();
        return new Uint8Array(digest);
    }

    public aes128GcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array {
        return aeadEncrypt(AES_128_GCM, key, nonce, plaintext, aad);
    }

    public aes128GcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array {
        return aeadDecrypt(AES_128_GCM, key, nonce, ciphertext, aad);
    }

    public aes256GcmEncrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array {
        return aeadEncrypt(AES_256_GCM, key, nonce, plaintext, aad);
    }

    public aes256GcmDecrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array {
        return aeadDecrypt(AES_256_GCM, key, nonce, ciphertext, aad);
    }

    public chacha20Poly1305Encrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        plaintext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array {
        return aeadEncrypt(CHACHA20_POLY1305, key, nonce, plaintext, aad);
    }

    public chacha20Poly1305Decrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        ciphertext: Uint8Array,
        aad: Uint8Array,
    ): Uint8Array {
        return aeadDecrypt(CHACHA20_POLY1305, key, nonce, ciphertext, aad);
    }

    public x25519GenerateKeyPair(): X25519KeyPair {
        // node:crypto.generateKeyPairSync("x25519") yields KeyObjects; export each
        // as raw DER and strip the fixed prefix to recover the 32-byte coordinate.
        const pair = generateKeyPairSync("x25519", {
            publicKeyEncoding: { type: "spki", format: "der" },
            privateKeyEncoding: { type: "pkcs8", format: "der" },
        });
        const publicKey = new Uint8Array(pair.publicKey).subarray(X25519_PUB_PREFIX.length);
        const secretKey = new Uint8Array(pair.privateKey).subarray(X25519_PRIV_PREFIX.length);
        return { publicKey, secretKey };
    }

    public x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
        // Rehydrate raw 32-byte coordinates into KeyObjects via DER, then DH.
        const priv = x25519PrivateKeyFromRaw(secretKey);
        const pub = x25519PublicKeyFromRaw(peerPublicKey);
        const secret = diffieHellman({ privateKey: priv, publicKey: pub });
        return new Uint8Array(secret);
    }

    public verifySignature(
        scheme: string,
        publicKey: Uint8Array,
        signature: Uint8Array,
        data: Uint8Array,
    ): boolean {
        // Rehydrate the DER SPKI into a KeyObject node:crypto can verify with.
        const key = createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
        switch (scheme) {
            case "ecdsa_secp256r1_sha256":
                return createVerify("sha256").update(data).verify(key, signature);
            case "ecdsa_secp384r1_sha384":
                return createVerify("sha384").update(data).verify(key, signature);
            // RSA-PSS salt length MUST equal the hash digest length (RFC 8017 §8.1.1):
            // SHA-256 = 32 bytes, SHA-384 = 48 bytes. node:crypto enforces this.
            case "rsa_pss_rsae_sha256":
                return createVerify("sha256").update(data).verify(
                    { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
                    signature,
                );
            case "rsa_pss_rsae_sha384":
                return createVerify("sha384").update(data).verify(
                    { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
                    signature,
                );
            case "rsa_pkcs1_sha256":
                return createVerify("sha256").update(data).verify(
                    { key, padding: constants.RSA_PKCS1_PADDING },
                    signature,
                );
            default:
                throw new UnsupportedAlgorithmError(`unsupported signature scheme: ${scheme}`);
        }
    }
}

/** Default singleton — the crypto backend higher layers call into. */
export const crypto: CryptoProvider = new NodeCryptoProvider();
