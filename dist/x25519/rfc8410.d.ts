/**
 * RFC 8410 ASN.1 encoding for X25519 keys (Curve25519 / Curve448).
 *
 * Pure ASN.1 construction — NO crypto logic. This is the single place that
 * converts raw 32-byte keys <-> PKCS#8/SPKI DER containers. Every other module
 * in @browsercore/crypto that needs DER goes through here, never hand-rolls a
 * prefix.
 *
 * DER layout (both formats carry the X25519 algorithm OID 1.3.101.110):
 *
 *   PKCS#8 (private) — RFC 8410 §10.2:
 *     SEQUENCE {
 *       version         INTEGER 0,
 *       algorithm       SEQUENCE { OID 1.3.101.110 },
 *       privateKey      OCTET STRING,  -- wraps: OCTET STRING (raw 32 bytes)
 *       attributes  [0]  OPTIONAL
 *     }
 *     Prefix: 302e020100300506032b656e04220420  +  32-byte scalar
 *
 *   SPKI (public) — RFC 8410 §10.3:
 *     SEQUENCE {
 *       algorithm       SEQUENCE { OID 1.3.101.110 },
 *       subjectPublicKey  BIT STRING  -- raw 32 bytes
 *     }
 *     Prefix: 302a300506032b656e032100  +  32-byte coordinate
 */
/**
 * Wrap a raw 32-byte X25519 private scalar as PKCS#8 DER.
 * Per RFC 8410 §10.2.
 *
 * @param raw  32-byte little-endian private scalar.
 * @returns  48-byte PKCS#8 DER.
 * @throws  If `raw` is not exactly 32 bytes.
 */
export declare function rawPrivateToPkcs8(raw: Uint8Array): Uint8Array;
/**
 * Wrap a raw 32-byte X25519 public coordinate as SPKI DER.
 * Per RFC 8410 §10.3.
 *
 * @param raw  32-byte little-endian public coordinate.
 * @returns  44-byte SPKI DER.
 * @throws  If `raw` is not exactly 32 bytes.
 */
export declare function rawPublicToSpki(raw: Uint8Array): Uint8Array;
/**
 * Extract the raw 32-byte private scalar from a PKCS#8 DER container.
 *
 * Parses the DER structure strictly: validates the outer SEQUENCE, the
 * version INTEGER (0), the algorithm OID (1.3.101.110 = X25519), and the
 * nested OCTET STRING layout. Rejects malformed DER, the wrong OID, wrong
 * sizes, and trailing bytes — anything that isn't a canonical RFC 8410 §10.2
 * private key container is an error, never silently coerced.
 *
 * @param der  48-byte PKCS#8 DER.
 * @returns  32-byte raw private scalar.
 */
export declare function pkcs8ToRaw(der: Uint8Array): Uint8Array;
/**
 * Extract the raw 32-byte public coordinate from a SPKI DER container.
 *
 * Parses the DER structure strictly: validates the outer SEQUENCE, the
 * algorithm OID (1.3.101.110 = X25519), and the BIT STRING layout (0 unused
 * bits prefix). Rejects malformed DER, the wrong OID, wrong sizes, and
 * trailing bytes.
 *
 * @param der  44-byte SPKI DER.
 * @returns  32-byte raw public coordinate.
 */
export declare function spkiToRaw(der: Uint8Array): Uint8Array;
//# sourceMappingURL=rfc8410.d.ts.map