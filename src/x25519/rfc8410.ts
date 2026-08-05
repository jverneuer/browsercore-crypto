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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Raw X25519 key size in bytes (256-bit scalar / coordinate). */
const RAW_KEY_LENGTH = 32;

/** DER-encoded X25519 algorithm OID (1.3.101.110) — the inner bytes of the OID TLV. */
const X25519_OID_VALUE = new Uint8Array([0x2b, 0x65, 0x6e]);

// ASN.1 DER tag octets (class=universal, constructed bit off/on per type).
const TAG_SEQUENCE = 0x30;
const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_BIT_STRING = 0x03;
const TAG_OID = 0x06;

/**
 * The fixed PKCS#8 DER prefix (16 bytes) preceding the raw 32-byte private
 * scalar. Captured by encoding the well-known RFC 8410 §2 structure and
 * stripping the trailing coordinate:
 *
 *   30 2e        SEQUENCE (46 bytes)
 *   02 01 00     INTEGER = 0 (version)
 *   30 05        SEQUENCE (5 bytes — algorithm identifier)
 *   06 03 2b 65 6e  OID 1.3.101.110 (X25519)
 *   04 22 04 20  OCTET STRING (34 bytes) wrapping OCTET STRING (32 bytes)
 */
const PKCS8_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * The fixed SPKI DER prefix (12 bytes) preceding the raw 32-byte public
 * coordinate:
 *
 *   30 2a           SEQUENCE (42 bytes)
 *   30 05           SEQUENCE (5 bytes — algorithm identifier)
 *   06 03 2b 65 6e  OID 1.3.101.110 (X25519)
 *   03 21 00        BIT STRING (33 bytes, 0 unused bits)
 */
const SPKI_PREFIX = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x6e, 0x03, 0x21, 0x00,
]);

const PKCS8_DER_LENGTH = PKCS8_PREFIX.length + RAW_KEY_LENGTH; // 48
const SPKI_DER_LENGTH = SPKI_PREFIX.length + RAW_KEY_LENGTH; // 44

// ---------------------------------------------------------------------------
// DER reading helpers — a minimal, validating ASN.1 DER decoder.
//
// We don't pull in a full ASN.1 library; the X25519 containers are tiny,
// fixed-layout, and only need shallow parsing (read tag, read length, advance
// a cursor). The parser is strict — DER only (no indefinite-length encodings,
// no trailing bytes) — matching what node:crypto expects.
// ---------------------------------------------------------------------------

/** The result of reading one DER TLV: where the value starts and how long it is. */
interface DerValue {
    /** Offset of the first value byte in the buffer. */
    readonly offset: number;
    /** Length of the value in bytes. */
    readonly length: number;
}

/** Read a DER length field. Returns the value offset and length. Throws on malformed input. */
function readDerLength(buf: Uint8Array, offset: number): { valueOffset: number; length: number } {
    if (offset >= buf.length) {
        throw new Error("DER decode: truncated buffer reading length");
    }
    const first = buf[offset];
    if (first === undefined) {
        throw new Error("DER decode: truncated buffer reading length");
    }
    if (first < 0x80) {
        // Short form: single-byte length, value follows immediately.
        return { valueOffset: offset + 1, length: first };
    }
    if (first === 0x80) {
        // Indefinite-length encoding is BER, not DER — forbidden by the spec.
        throw new Error("DER decode: indefinite-length encoding is not allowed in DER");
    }
    // Long form: low 7 bits of the first byte encode the number of length bytes.
    const numLengthBytes = first & 0x7f;
    if (numLengthBytes === 0 || numLengthBytes > 4) {
        throw new Error(`DER decode: unsupported long-form length (${numLengthBytes} bytes)`);
    }
    if (offset + 1 + numLengthBytes > buf.length) {
        throw new Error("DER decode: truncated buffer reading long-form length");
    }
    let length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
        const byte = buf[offset + 1 + i];
        if (byte === undefined) {
            throw new Error("DER decode: truncated buffer reading long-form length");
        }
        length = (length << 8) | byte;
    }
    // DER mandates the shortest encoding; a leading zero byte is non-canonical.
    const leadingLengthByte = buf[offset + 1];
    if (numLengthBytes > 1 && leadingLengthByte === 0x00) {
        throw new Error("DER decode: non-canonical DER length (leading zero byte)");
    }
    return { valueOffset: offset + 1 + numLengthBytes, length };
}

/**
 * Read a DER TLV at the given offset, validating the tag. Returns the value's
 * offset and length. Throws if the tag doesn't match or the length is malformed.
 */
function readDerTag(buf: Uint8Array, offset: number, expectedTag: number): DerValue {
    if (offset >= buf.length) {
        throw new Error(
            `DER decode: expected tag 0x${expectedTag.toString(16).padStart(2, "0")} at offset ${offset}, got end of buffer`,
        );
    }
    const tag = buf[offset];
    if (tag === undefined) {
        throw new Error(
            `DER decode: expected tag 0x${expectedTag.toString(16).padStart(2, "0")} at offset ${offset}, got end of buffer`,
        );
    }
    if (tag !== expectedTag) {
        throw new Error(
            `DER decode: expected tag 0x${expectedTag.toString(16).padStart(2, "0")} at offset ${offset}, got 0x${tag.toString(16).padStart(2, "0")}`,
        );
    }
    const { valueOffset, length } = readDerLength(buf, offset + 1);
    return { offset: valueOffset, length };
}

/**
 * Verify that `actual` equals the expected bytes. Used to validate the OID and
 * other fixed fields we don't need to pass around. Callers must ensure
 * `actual.length === expected.length` before invoking.
 */
function expectBytesEqual(actual: Uint8Array, expected: Uint8Array, label: string): void {
    for (let i = 0; i < actual.length; i++) {
        // Lengths are equal (enforced by callers), so both lookups succeed —
        // the type assertion satisfies the strict type checker without a lint error.
        const actualByte = actual[i] as number;
        const expectedByte = expected[i] as number;
        if (actualByte !== expectedByte) {
            throw new Error(
                `${label}: byte ${i} mismatch — expected 0x${expectedByte.toString(16).padStart(2, "0")}, got 0x${actualByte.toString(16).padStart(2, "0")}`,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Public encoding functions
// ---------------------------------------------------------------------------

/**
 * Wrap a raw 32-byte X25519 private scalar as PKCS#8 DER.
 * Per RFC 8410 §10.2.
 *
 * @param raw  32-byte little-endian private scalar.
 * @returns  48-byte PKCS#8 DER.
 * @throws  If `raw` is not exactly 32 bytes.
 */
export function rawPrivateToPkcs8(raw: Uint8Array): Uint8Array {
    if (raw.length !== RAW_KEY_LENGTH) {
        throw new Error(
            `rawPrivateToPkcs8: private scalar must be ${RAW_KEY_LENGTH} bytes, got ${raw.length}`,
        );
    }
    const der = new Uint8Array(PKCS8_DER_LENGTH);
    der.set(PKCS8_PREFIX, 0);
    der.set(raw, PKCS8_PREFIX.length);
    return der;
}

/**
 * Wrap a raw 32-byte X25519 public coordinate as SPKI DER.
 * Per RFC 8410 §10.3.
 *
 * @param raw  32-byte little-endian public coordinate.
 * @returns  44-byte SPKI DER.
 * @throws  If `raw` is not exactly 32 bytes.
 */
export function rawPublicToSpki(raw: Uint8Array): Uint8Array {
    if (raw.length !== RAW_KEY_LENGTH) {
        throw new Error(
            `rawPublicToSpki: public coordinate must be ${RAW_KEY_LENGTH} bytes, got ${raw.length}`,
        );
    }
    const der = new Uint8Array(SPKI_DER_LENGTH);
    der.set(SPKI_PREFIX, 0);
    der.set(raw, SPKI_PREFIX.length);
    return der;
}

// ---------------------------------------------------------------------------
// Public decoding functions
// ---------------------------------------------------------------------------

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
export function pkcs8ToRaw(der: Uint8Array): Uint8Array {
    if (der.length !== PKCS8_DER_LENGTH) {
        throw new Error(
            `pkcs8ToRaw: PKCS#8 DER must be ${PKCS8_DER_LENGTH} bytes, got ${der.length}`,
        );
    }

    // 1. Outer SEQUENCE (the whole container).
    const outer = readDerTag(der, 0, TAG_SEQUENCE);
    if (outer.length !== der.length - 2) {
        // 2 = tag (1) + length (1, short form, length < 128).
        throw new Error(
            `pkcs8ToRaw: outer SEQUENCE length ${outer.length} does not match DER size ${der.length}`,
        );
    }

    // 2. version INTEGER = 0.
    let cursor = outer.offset;
    const version = readDerTag(der, cursor, TAG_INTEGER);
    const versionByte = der[version.offset];
    if (version.length !== 1 || versionByte !== 0x00) {
        throw new Error(
            `pkcs8ToRaw: expected version INTEGER 0 (1 byte), got length ${version.length}`,
        );
    }
    cursor = version.offset + version.length;

    // 3. algorithm SEQUENCE { OID }.
    const algorithm = readDerTag(der, cursor, TAG_SEQUENCE);
    if (algorithm.length !== 5) {
        throw new Error(
            `pkcs8ToRaw: algorithm SEQUENCE must be 5 bytes, got ${algorithm.length}`,
        );
    }
    const oid = readDerTag(der, algorithm.offset, TAG_OID);
    if (oid.length !== 3) {
        throw new Error(`pkcs8ToRaw: OID must be 3 bytes, got ${oid.length}`);
    }
    expectBytesEqual(
        der.subarray(oid.offset, oid.offset + oid.length),
        X25519_OID_VALUE,
        "pkcs8ToRaw: algorithm OID",
    );
    cursor = algorithm.offset + algorithm.length;

    // 4. privateKey OCTET STRING (the outer wrapper around the inner OCTET STRING).
    const outerOctet = readDerTag(der, cursor, TAG_OCTET_STRING);
    if (outerOctet.length !== RAW_KEY_LENGTH + 2) {
        // +2 for the inner OCTET STRING tag + length byte.
        throw new Error(
            `pkcs8ToRaw: outer OCTET STRING must be ${RAW_KEY_LENGTH + 2} bytes, got ${outerOctet.length}`,
        );
    }

    // 5. Inner OCTET STRING (the raw 32-byte scalar).
    const innerOctet = readDerTag(der, outerOctet.offset, TAG_OCTET_STRING);
    if (innerOctet.length !== RAW_KEY_LENGTH) {
        throw new Error(
            `pkcs8ToRaw: inner OCTET STRING must be ${RAW_KEY_LENGTH} bytes, got ${innerOctet.length}`,
        );
    }

    // Return a copy so callers can mutate without touching the DER container.
    return der.subarray(innerOctet.offset, innerOctet.offset + innerOctet.length).slice();
}

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
export function spkiToRaw(der: Uint8Array): Uint8Array {
    if (der.length !== SPKI_DER_LENGTH) {
        throw new Error(
            `spkiToRaw: SPKI DER must be ${SPKI_DER_LENGTH} bytes, got ${der.length}`,
        );
    }

    // 1. Outer SEQUENCE (the whole container).
    const outer = readDerTag(der, 0, TAG_SEQUENCE);
    if (outer.length !== der.length - 2) {
        throw new Error(
            `spkiToRaw: outer SEQUENCE length ${outer.length} does not match DER size ${der.length}`,
        );
    }

    // 2. algorithm SEQUENCE { OID }.
    const algorithm = readDerTag(der, outer.offset, TAG_SEQUENCE);
    if (algorithm.length !== 5) {
        throw new Error(
            `spkiToRaw: algorithm SEQUENCE must be 5 bytes, got ${algorithm.length}`,
        );
    }
    const oid = readDerTag(der, algorithm.offset, TAG_OID);
    if (oid.length !== 3) {
        throw new Error(`spkiToRaw: OID must be 3 bytes, got ${oid.length}`);
    }
    expectBytesEqual(
        der.subarray(oid.offset, oid.offset + oid.length),
        X25519_OID_VALUE,
        "spkiToRaw: algorithm OID",
    );

    // 3. subjectPublicKey BIT STRING.
    const bitString = readDerTag(der, algorithm.offset + algorithm.length, TAG_BIT_STRING);
    if (bitString.length !== RAW_KEY_LENGTH + 1) {
        // +1 for the "unused bits" prefix byte.
        throw new Error(
            `spkiToRaw: BIT STRING must be ${RAW_KEY_LENGTH + 1} bytes, got ${bitString.length}`,
        );
    }
    // BIT STRING content is prefixed by a "number of unused bits" byte; for a
    // raw 32-byte coordinate this MUST be 0.
    const unusedBits = der[bitString.offset];
    if (unusedBits !== 0x00) {
        throw new Error(
            `spkiToRaw: BIT STRING must have 0 unused bits, got ${unusedBits}`,
        );
    }

    // 4. No trailing bytes after the outer SEQUENCE.
    if (outer.offset + outer.length !== der.length) {
        throw new Error(
            `spkiToRaw: trailing bytes after outer SEQUENCE (${der.length - (outer.offset + outer.length)} bytes)`,
        );
    }

    // Return the 32 bytes after the "unused bits" prefix — a copy so callers
    // can mutate without touching the DER container.
    return der.subarray(bitString.offset + 1, bitString.offset + 1 + RAW_KEY_LENGTH).slice();
}
