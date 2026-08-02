/**
 * Raw-bytes <-> KeyObject conversion for X25519.
 *
 * Node's JWK import needs the public coordinate on a private key, which a bare
 * 32-byte secret doesn't carry, so we instead rebuild the fixed DER containers:
 * PKCS8 (private) and SPKI (public). Each is a constant prefix followed by the
 * 32-byte coordinate. Capturing the prefixes from one template keypair gives us
 * stable wrappers for any raw scalar — no per-key metadata required.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey } from "node:crypto";

const x25519Template = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
});
export const X25519_PRIV_PREFIX = new Uint8Array(x25519Template.privateKey).subarray(0, -32);
export const X25519_PUB_PREFIX = new Uint8Array(x25519Template.publicKey).subarray(0, -32);

/** Wrap a raw 32-byte X25519 private scalar as a PKCS8 DER KeyObject. */
export function x25519PrivateKeyFromRaw(d: Uint8Array): ReturnType<typeof createPrivateKey> {
    const der = new Uint8Array(X25519_PRIV_PREFIX.length + d.length);
    der.set(X25519_PRIV_PREFIX, 0);
    der.set(d, X25519_PRIV_PREFIX.length);
    return createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" });
}

/** Wrap a raw 32-byte X25519 public coordinate as a SPKI DER KeyObject. */
export function x25519PublicKeyFromRaw(x: Uint8Array): ReturnType<typeof createPublicKey> {
    const der = new Uint8Array(X25519_PUB_PREFIX.length + x.length);
    der.set(X25519_PUB_PREFIX, 0);
    der.set(x, X25519_PUB_PREFIX.length);
    return createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
}
