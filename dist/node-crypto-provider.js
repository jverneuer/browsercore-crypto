/**
 * {@link CryptoProvider} backed by Node's native `node:crypto` module.
 *
 * Higher layers call the provider methods here, never `node:crypto` directly, so the
 * backend stays replaceable. Exported as the default singleton so consumers can call
 * `crypto.hkdf(...)` without threading a provider through every constructor.
 */
import { randomBytes as nodeRandomBytes, createHash, createHmac, hkdfSync, createPublicKey, createVerify, createECDH, createCipheriv, constants, } from "node:crypto";
import { AES_128_GCM, AES_128_CCM, AES_256_GCM, CHACHA20_POLY1305, } from "./types.js";
import { UnsupportedAlgorithmError } from "./errors.js";
import { assertNever } from "./utils.js";
import { aeadEncrypt, aeadDecrypt } from "./aead.js";
import { defaultX25519Backend } from "./x25519/index.js";
/**
 * Map a branded {@link HashId} to the algorithm string Node's `node:crypto`
 * expects. Exhaustive — adding a member to {@link HashId} forces every branch
 * below to compile-error until handled.
 */
function hashAlgorithmName(hash) {
    switch (hash) {
        case "SHA-256":
            return "sha256";
        case "SHA-384":
            return "sha384";
        default:
            return assertNever(hash);
    }
}
export class NodeCryptoProvider {
    randomBytes(length) {
        return nodeRandomBytes(length);
    }
    sha256(data) {
        return createHash("sha256").update(data).digest();
    }
    sha384(data) {
        return createHash("sha384").update(data).digest();
    }
    hkdf(hash, salt, ikm, info, length) {
        // node:crypto.hkdfSync(digest, ikm, salt, info, length).
        const digest = hashAlgorithmName(hash);
        const key = hkdfSync(digest, ikm, salt, info, length);
        return new Uint8Array(key);
    }
    hmac(hash, key, data) {
        const algorithm = hashAlgorithmName(hash);
        const digest = createHmac(algorithm, key).update(data).digest();
        return new Uint8Array(digest);
    }
    aes128GcmEncrypt(key, nonce, plaintext, aad) {
        return aeadEncrypt(AES_128_GCM, key, nonce, plaintext, aad);
    }
    aes128GcmDecrypt(key, nonce, ciphertext, aad) {
        return aeadDecrypt(AES_128_GCM, key, nonce, ciphertext, aad);
    }
    aes256GcmEncrypt(key, nonce, plaintext, aad) {
        return aeadEncrypt(AES_256_GCM, key, nonce, plaintext, aad);
    }
    aes256GcmDecrypt(key, nonce, ciphertext, aad) {
        return aeadDecrypt(AES_256_GCM, key, nonce, ciphertext, aad);
    }
    aes128CcmEncrypt(key, nonce, plaintext, aad) {
        return aeadEncrypt(AES_128_CCM, key, nonce, plaintext, aad);
    }
    aes128CcmDecrypt(key, nonce, ciphertext, aad) {
        return aeadDecrypt(AES_128_CCM, key, nonce, ciphertext, aad);
    }
    chacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
        return aeadEncrypt(CHACHA20_POLY1305, key, nonce, plaintext, aad);
    }
    chacha20Poly1305Decrypt(key, nonce, ciphertext, aad) {
        return aeadDecrypt(CHACHA20_POLY1305, key, nonce, ciphertext, aad);
    }
    x25519GenerateKeyPair() {
        // Delegate to the default X25519 backend (noble-curves). The backend
        // applies RFC 7748 §5 clamping internally, removing the DER/ASN.1 bug
        // class that plagued the old node:crypto KeyObject path.
        const secretKey = this.randomBytes(32);
        const publicKey = defaultX25519Backend.publicKey(secretKey);
        return { publicKey, secretKey };
    }
    x25519SharedSecret(secretKey, peerPublicKey) {
        // Delegate to the default X25519 backend. The noble-curves backend
        // handles the RFC 7748 §5 degenerate (all-zero) u-coordinate correctly,
        // returning the mandated 32 zero bytes — no special-casing needed.
        return defaultX25519Backend.sharedSecret(secretKey, peerPublicKey);
    }
    verifySignature(scheme, publicKey, signature, data) {
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
                return createVerify("sha256").update(data).verify({ key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
            case "rsa_pss_rsae_sha384":
                return createVerify("sha384").update(data).verify({ key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, signature);
            case "rsa_pkcs1_sha256":
                return createVerify("sha256").update(data).verify({ key, padding: constants.RSA_PKCS1_PADDING }, signature);
            default:
                throw new UnsupportedAlgorithmError(`unsupported signature scheme: ${scheme}`);
        }
    }
    ecdhGenerateKeyPair(curve) {
        const ecdh = createECDH(ecdhCurveToNode(curve));
        ecdh.generateKeys();
        // getPublicKey() defaults to uncompressed form (0x04 || x || y) — exactly
        // the layout TLS 1.3 KeyShareEntry expects.
        //
        // getPrivateKey() returns a big-endian scalar with leading zero bytes
        // stripped, so it can be shorter than the curve's fixed byte length
        // (e.g. 47 bytes for secp384r1 instead of 48). Left-pad to the curve's
        // canonical length so callers get a fixed-width scalar.
        const scalarLength = curve === "secp256r1" ? 32 : 48;
        const rawScalar = ecdh.getPrivateKey();
        const secretKey = new Uint8Array(scalarLength);
        secretKey.set(rawScalar, scalarLength - rawScalar.length);
        return {
            curve,
            publicKey: new Uint8Array(ecdh.getPublicKey()),
            secretKey,
        };
    }
    ecdhSharedSecret(curve, secretKey, peerPublicKey) {
        const ecdh = createECDH(ecdhCurveToNode(curve));
        ecdh.setPrivateKey(secretKey);
        // computeSecret returns the x-coordinate of the shared point — the raw
        // ECDH output that TLS feeds into the key schedule.
        return new Uint8Array(ecdh.computeSecret(peerPublicKey));
    }
    aesEcbEncrypt(key, block) {
        // QUIC header protection (RFC 9001 §5.4.1) requires AES-ECB on a
        // single 16-byte block. ECB mode takes no IV. Only AES-128 (16-byte
        // key) and AES-256 (32-byte key) are used by QUIC.
        const algorithm = key.length === 16 ? "aes-128-ecb" : "aes-256-ecb";
        const cipher = createCipheriv(algorithm, key, new Uint8Array(0));
        cipher.setAutoPadding(false);
        const out = new Uint8Array(cipher.update(block));
        const final = new Uint8Array(cipher.final());
        const result = new Uint8Array(out.length + final.length);
        result.set(out, 0);
        result.set(final, out.length);
        return result;
    }
}
/** Map a branded {@link EcdhCurve} to the node:crypto curve name. */
function ecdhCurveToNode(curve) {
    switch (curve) {
        case "secp256r1":
            return "prime256v1";
        case "secp384r1":
            return "secp384r1";
        default:
            return assertNever(curve);
    }
}
/** Default singleton — the crypto backend higher layers call into. */
export const crypto = new NodeCryptoProvider();
//# sourceMappingURL=node-crypto-provider.js.map