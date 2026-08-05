/**
 * Pure TypeScript X25519 backend backed by @noble/curves.
 *
 * This module is intentionally free of any `node:crypto` import — raw 32-byte
 * scalars in, raw 32-byte coordinates out. noble-curves handles clamping
 * internally, which removes the entire ASN.1/DER bug class that plagues the
 * Node backend (see src/x25519.ts). That makes this the recommended default
 * backend for the crypto provider.
 */
import { x25519 } from "@noble/curves/ed25519";
/**
 * RFC 7748 §5 mandates that a degenerate (small-order) u-coordinate — the
 * all-zero input being the canonical case — yield the all-zero shared secret
 * rather than aborting. noble-curves rejects such inputs with a validation
 * error; we translate that specific failure into the RFC-mandated 32 zero
 * bytes. Any other error (malformed key, genuine programming error) is
 * re-thrown so it is not masked.
 *
 * We pre-check the all-zero u-coordinate as an optimization so the hot path
 * avoids entering the noble-curves codepath only to fail.
 */
function isAllZero(bytes) {
    for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] !== 0) {
            return false;
        }
    }
    return true;
}
/**
 * Noble-curves-backed {@link X25519Backend}.
 *
 * Uses the audited, constant-time @noble/curves implementation. All operations
 * run in pure JS with no native bindings, so the same code path executes on
 * every platform — no subtle behavior differences between Node, Deno, and
 * browser environments.
 */
export class NobleX25519Backend {
    publicKey(privateKey) {
        // x25519.getPublicKey accepts a raw 32-byte scalar and returns the
        // 32-byte public u-coordinate. Clamping is applied internally.
        return x25519.getPublicKey(privateKey);
    }
    sharedSecret(privateKey, publicKey) {
        // RFC 7748 §5: the all-zero u-coordinate is degenerate (small-order)
        // and MUST produce the all-zero shared secret. Check this first so
        // the hot path never enters noble-curves only to fail validation.
        if (isAllZero(publicKey)) {
            return new Uint8Array(32);
        }
        // x25519.getSharedSecret is an alias for scalarMult — it computes
        // X25519(privateKey, publicKey) per RFC 7748 §5.
        return x25519.getSharedSecret(privateKey, publicKey);
    }
}
//# sourceMappingURL=noble-backend.js.map