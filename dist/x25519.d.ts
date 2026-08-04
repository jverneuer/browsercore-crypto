/**
 * Raw-bytes <-> KeyObject conversion for X25519.
 *
 * Node's JWK import needs the public coordinate on a private key, which a bare
 * 32-byte secret doesn't carry, so we instead rebuild the fixed DER containers:
 * PKCS8 (private) and SPKI (public). Each is a constant prefix followed by the
 * 32-byte coordinate. Capturing the prefixes from one template keypair gives us
 * stable wrappers for any raw scalar — no per-key metadata required.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
export declare const X25519_PRIV_PREFIX: Uint8Array<ArrayBuffer>;
export declare const X25519_PUB_PREFIX: Uint8Array<ArrayBuffer>;
/** Wrap a raw 32-byte X25519 private scalar as a PKCS8 DER KeyObject. */
export declare function x25519PrivateKeyFromRaw(d: Uint8Array): ReturnType<typeof createPrivateKey>;
/** Wrap a raw 32-byte X25519 public coordinate as a SPKI DER KeyObject. */
export declare function x25519PublicKeyFromRaw(x: Uint8Array): ReturnType<typeof createPublicKey>;
//# sourceMappingURL=x25519.d.ts.map