/**
 * Tests for the RFC 8410 ASN.1 encoding/decoding module.
 *
 * Covers round-trips (encode then decode recovers the raw key), the canonical
 * RFC 8410 §10.2 / §10.3 DER byte sequences (decode produces the known raw
 * key; encode produces the known DER), the RFC 7748 §5.2 private scalar, and
 * the strict-decode rejection path (wrong size, wrong OID, trailing bytes,
 * non-canonical DER).
 */

import { describe, expect, it } from "vitest";

import {
    rawPrivateToPkcs8,
    pkcs8ToRaw,
    rawPublicToSpki,
    spkiToRaw,
} from "../../src/x25519/rfc8410.js";

/** Hex string → Uint8Array. */
const fromHex = (hex: string): Uint8Array => {
    if (hex.length % 2 !== 0) {
        throw new Error(`fromHex: odd-length hex string "${hex}"`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        if (Number.isNaN(byte)) {
            throw new Error(`fromHex: invalid hex at offset ${i * 2}`);
        }
        bytes[i] = byte;
    }
    return bytes;
};

/** Uint8Array → hex string. */
const toHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** The RFC 8410 §10.2 private scalar (also the RFC 7748 §5.2 scalar). */
const RFC8410_PRIV_SCALAR = fromHex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1880900a2e1d4105d5",
);

/**
 * The RFC 7748 §6.1 Alice public coordinate — used as the known public key for
 * SPKI round-trip and encoding tests. Sourced from the same test vector the
 * existing x25519-vectors.test.ts already uses, so it's a stable, well-known value.
 */
const RFC8410_PUB_COORD = fromHex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
);

// The canonical DER containers from RFC 8410 §10.2 and §10.3, hex-encoded.
const RFC8410_PKCS8_DER = fromHex(
    "302e020100300506032b656e04220420" + "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1880900a2e1d4105d5",
);
const RFC8410_SPKI_DER = fromHex(
    "302a300506032b656e032100" +
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
);

describe("PKCS#8 round-trip", () => {
    it("encode then decode recovers the raw private scalar", () => {
        const der = rawPrivateToPkcs8(RFC8410_PRIV_SCALAR);
        expect(pkcs8ToRaw(der)).toEqual(RFC8410_PRIV_SCALAR);
    });

    it("decode then encode recovers the original DER (bidirectional)", () => {
        const der = rawPrivateToPkcs8(RFC8410_PRIV_SCALAR);
        expect(rawPrivateToPkcs8(pkcs8ToRaw(der))).toEqual(der);
    });

    it("round-trips an all-zero scalar", () => {
        const zero = new Uint8Array(32);
        expect(pkcs8ToRaw(rawPrivateToPkcs8(zero))).toEqual(zero);
    });

    it("round-trips an all-0xff scalar", () => {
        const ff = new Uint8Array(32).fill(0xff);
        expect(pkcs8ToRaw(rawPrivateToPkcs8(ff))).toEqual(ff);
    });

    it("round-trips a monotonically increasing scalar", () => {
        const raw = new Uint8Array(32);
        for (let i = 0; i < 32; i++) raw[i] = i;
        expect(pkcs8ToRaw(rawPrivateToPkcs8(raw))).toEqual(raw);
    });

    it("produces a 48-byte DER container", () => {
        expect(rawPrivateToPkcs8(RFC8410_PRIV_SCALAR)).toHaveLength(48);
    });
});

describe("SPKI round-trip", () => {
    it("encode then decode recovers the raw public coordinate", () => {
        const der = rawPublicToSpki(RFC8410_PUB_COORD);
        expect(spkiToRaw(der)).toEqual(RFC8410_PUB_COORD);
    });

    it("decode then encode recovers the original DER (bidirectional)", () => {
        const der = rawPublicToSpki(RFC8410_PUB_COORD);
        expect(rawPublicToSpki(spkiToRaw(der))).toEqual(der);
    });

    it("round-trips an all-zero coordinate", () => {
        const zero = new Uint8Array(32);
        expect(spkiToRaw(rawPublicToSpki(zero))).toEqual(zero);
    });

    it("round-trips an all-0xff coordinate", () => {
        const ff = new Uint8Array(32).fill(0xff);
        expect(spkiToRaw(rawPublicToSpki(ff))).toEqual(ff);
    });

    it("produces a 44-byte DER container", () => {
        expect(rawPublicToSpki(RFC8410_PUB_COORD)).toHaveLength(44);
    });
});

describe("RFC 8410 §10.2 — known PKCS#8 DER", () => {
    it("decodes the canonical DER to the known scalar", () => {
        expect(pkcs8ToRaw(RFC8410_PKCS8_DER)).toEqual(RFC8410_PRIV_SCALAR);
    });

    it("encodes the known scalar to the canonical DER", () => {
        expect(rawPrivateToPkcs8(RFC8410_PRIV_SCALAR)).toEqual(RFC8410_PKCS8_DER);
    });

    it("the canonical DER has the documented hex bytes", () => {
        expect(toHex(RFC8410_PKCS8_DER)).toBe(
            "302e020100300506032b656e04220420" +
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1880900a2e1d4105d5",
        );
    });
});

describe("SPKI — known DER byte decoding (encode matches decode)", () => {
    it("decodes the known SPKI DER to the expected coordinate", () => {
        expect(spkiToRaw(RFC8410_SPKI_DER)).toEqual(RFC8410_PUB_COORD);
    });

    it("encodes the known coordinate to the expected SPKI DER", () => {
        expect(rawPublicToSpki(RFC8410_PUB_COORD)).toEqual(RFC8410_SPKI_DER);
    });

    it("the SPKI DER has the documented hex bytes (prefix + coordinate)", () => {
        expect(toHex(RFC8410_SPKI_DER)).toBe(
            "302a300506032b656e032100" +
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        );
    });
});

describe("RFC 7748 §5.2 scalar round-trip", () => {
    // The RFC 7748 §5.2 private scalar — also the RFC 8410 §10.2 example key.
    const scalar = fromHex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1880900a2e1d4105d5",
    );

    it("PKCS#8 round-trip recovers the RFC 7748 scalar exactly", () => {
        const der = rawPrivateToPkcs8(scalar);
        expect(pkcs8ToRaw(der)).toEqual(scalar);
        expect(toHex(pkcs8ToRaw(der))).toBe(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1880900a2e1d4105d5",
        );
    });

    it("encodes the scalar to exactly the RFC 8410 §10.2 DER bytes", () => {
        expect(toHex(rawPrivateToPkcs8(scalar))).toBe(
            "302e020100300506032b656e04220420" +
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1880900a2e1d4105d5",
        );
    });
});

describe("decode rejects malformed PKCS#8", () => {
    it("rejects a buffer of the wrong size (too short)", () => {
        const short = new Uint8Array(47);
        short.set(RFC8410_PKCS8_DER.subarray(0, 47), 0);
        expect(() => pkcs8ToRaw(short)).toThrow(/48 bytes/);
    });

    it("rejects a buffer of the wrong size (too long)", () => {
        const long = new Uint8Array(49);
        long.set(RFC8410_PKCS8_DER, 0);
        expect(() => pkcs8ToRaw(long)).toThrow(/48 bytes/);
    });

    it("rejects a buffer with the wrong outer tag", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        bad[0] = 0x31; // SET instead of SEQUENCE.
        expect(() => pkcs8ToRaw(bad)).toThrow(/tag 0x30/);
    });

    it("rejects a buffer with the wrong algorithm OID", () => {
        // Flip one byte of the OID (offset 11 holds 0x6e → 0x6f).
        const bad = RFC8410_PKCS8_DER.slice();
        bad[11] = 0x6f;
        expect(() => pkcs8ToRaw(bad)).toThrow(/algorithm OID/);
    });

    it("rejects a buffer with trailing bytes after the outer SEQUENCE", () => {
        // Concatenate the valid DER with one extra byte — total is 49 bytes,
        // so the size check catches it before structural parsing.
        const trailing = new Uint8Array(49);
        trailing.set(RFC8410_PKCS8_DER, 0);
        trailing[48] = 0x00;
        expect(() => pkcs8ToRaw(trailing)).toThrow(/48 bytes/);
    });

    it("rejects a buffer with a wrong outer OCTET STRING length", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        // Offset 13 holds the outer OCTET STRING length byte (0x22 = 34). Change to 0x23.
        bad[13] = 0x23;
        expect(() => pkcs8ToRaw(bad)).toThrow(/outer OCTET STRING must be 34 bytes/);
    });

    it("rejects a buffer with a wrong inner OCTET STRING length", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        // Offset 15 holds the inner OCTET STRING length byte (0x20 = 32). Change to 0x21.
        bad[15] = 0x21;
        expect(() => pkcs8ToRaw(bad)).toThrow(/inner OCTET STRING must be 32 bytes/);
    });

    it("rejects a buffer with a wrong algorithm SEQUENCE length", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        // Offset 6 holds the algorithm SEQUENCE length byte (0x05). Change to 0x06.
        bad[6] = 0x06;
        expect(() => pkcs8ToRaw(bad)).toThrow(/algorithm SEQUENCE must be 5 bytes/);
    });

    it("rejects a buffer with a wrong OID length", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        // Offset 8 holds the OID length byte (0x03). Change to 0x04.
        bad[8] = 0x04;
        expect(() => pkcs8ToRaw(bad)).toThrow(/OID must be 3 bytes/);
    });

    it("rejects a buffer whose outer SEQUENCE length does not match DER size", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        // Offset 1 holds the outer SEQUENCE length byte (0x2e = 46). Change to 0x2d.
        bad[1] = 0x2d;
        expect(() => pkcs8ToRaw(bad)).toThrow(/outer SEQUENCE length/);
    });

    it("rejects a buffer with a non-zero version INTEGER", () => {
        const bad = RFC8410_PKCS8_DER.slice();
        // Offset 4 holds the version byte (0x00). Change to 0x01.
        bad[4] = 0x01;
        expect(() => pkcs8ToRaw(bad)).toThrow(/version INTEGER/);
    });
});

describe("decode rejects malformed SPKI", () => {
    it("rejects a buffer of the wrong size (too short)", () => {
        const short = new Uint8Array(43);
        short.set(RFC8410_SPKI_DER.subarray(0, 43), 0);
        expect(() => spkiToRaw(short)).toThrow(/44 bytes/);
    });

    it("rejects a buffer of the wrong size (too long)", () => {
        const long = new Uint8Array(45);
        long.set(RFC8410_SPKI_DER, 0);
        expect(() => spkiToRaw(long)).toThrow(/44 bytes/);
    });

    it("rejects a buffer with the wrong outer tag", () => {
        const bad = RFC8410_SPKI_DER.slice();
        bad[0] = 0x31; // SET instead of SEQUENCE.
        expect(() => spkiToRaw(bad)).toThrow(/tag 0x30/);
    });

    it("rejects a buffer with the wrong algorithm OID", () => {
        // Flip one byte of the OID (offset 7 holds 0x6e → 0x6f).
        const bad = RFC8410_SPKI_DER.slice();
        bad[7] = 0x6f;
        expect(() => spkiToRaw(bad)).toThrow(/algorithm OID/);
    });

    it("rejects a BIT STRING with non-zero unused bits", () => {
        const bad = RFC8410_SPKI_DER.slice();
        // The "unused bits" byte is at offset 11 (the first byte of the BIT STRING value).
        bad[11] = 0x01;
        expect(() => spkiToRaw(bad)).toThrow(/unused bits/);
    });

    it("rejects a buffer with a wrong algorithm SEQUENCE length", () => {
        const bad = RFC8410_SPKI_DER.slice();
        // Offset 3 holds the algorithm SEQUENCE length byte (0x05). Change to 0x06.
        bad[3] = 0x06;
        expect(() => spkiToRaw(bad)).toThrow(/algorithm SEQUENCE must be 5 bytes/);
    });

    it("rejects a buffer with a wrong OID length", () => {
        const bad = RFC8410_SPKI_DER.slice();
        // Offset 5 holds the OID length byte (0x03). Change to 0x04.
        bad[5] = 0x04;
        expect(() => spkiToRaw(bad)).toThrow(/OID must be 3 bytes/);
    });

    it("rejects a buffer with a wrong BIT STRING length", () => {
        const bad = RFC8410_SPKI_DER.slice();
        // Offset 10 holds the BIT STRING length byte (0x21 = 33). Change to 0x20.
        bad[10] = 0x20;
        expect(() => spkiToRaw(bad)).toThrow(/BIT STRING must be 33 bytes/);
    });

    it("rejects a buffer whose outer SEQUENCE length does not match DER size", () => {
        const bad = RFC8410_SPKI_DER.slice();
        // Offset 1 holds the outer SEQUENCE length byte (0x2a = 42). Change to 0x29.
        bad[1] = 0x29;
        expect(() => spkiToRaw(bad)).toThrow(/outer SEQUENCE length/);
    });
});

describe("encode rejects non-32-byte inputs", () => {
    it("rawPrivateToPkcs8 rejects a 31-byte input", () => {
        expect(() => rawPrivateToPkcs8(new Uint8Array(31))).toThrow(/32 bytes/);
    });

    it("rawPrivateToPkcs8 rejects a 33-byte input", () => {
        expect(() => rawPrivateToPkcs8(new Uint8Array(33))).toThrow(/32 bytes/);
    });

    it("rawPublicToSpki rejects a 31-byte input", () => {
        expect(() => rawPublicToSpki(new Uint8Array(31))).toThrow(/32 bytes/);
    });

    it("rawPublicToSpki rejects a 33-byte input", () => {
        expect(() => rawPublicToSpki(new Uint8Array(33))).toThrow(/32 bytes/);
    });
});

describe("encoding produces independent copies (no aliasing)", () => {
    it("mutating the raw input after encoding does not change the DER", () => {
        const raw = RFC8410_PRIV_SCALAR.slice();
        const der = rawPrivateToPkcs8(raw);
        raw.fill(0);
        // The DER container holds its own copy of the scalar.
        expect(pkcs8ToRaw(der)).toEqual(RFC8410_PRIV_SCALAR);
    });

    it("mutating the DER after decoding does not change the extracted raw", () => {
        const der = rawPublicToSpki(RFC8410_PUB_COORD);
        const raw = spkiToRaw(der);
        der.fill(0);
        // The extracted raw key holds its own copy.
        expect(raw).toEqual(RFC8410_PUB_COORD);
    });
});

describe("decode returns independent copies (no aliasing)", () => {
    it("mutating the decoded raw does not affect a re-decode of the same DER", () => {
        const der = rawPrivateToPkcs8(RFC8410_PRIV_SCALAR);
        const a = pkcs8ToRaw(der);
        const b = pkcs8ToRaw(der);
        a.fill(0xff);
        expect(b).toEqual(RFC8410_PRIV_SCALAR);
    });
});


