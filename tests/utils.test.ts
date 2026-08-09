/**
 * Tests for the small shared helpers in @browsercore/crypto.
 *
 * `assertNever` is the exhaustiveness guard for discriminated unions; `createId`
 * builds collision-resistant identifiers. These are the only pieces of runtime
 * logic in the utils module, so they need direct coverage.
 */

import { describe, expect, it } from "vitest";

import { assertNever, createId } from "../src/utils.js";

describe("assertNever", () => {
    it("throws an Error describing the unexpected value", () => {
        expect(() => assertNever("surprise" as never)).toThrow(/Unexpected value/);
    });

    it("includes a JSON representation of the value in the message", () => {
        expect(() => assertNever(123 as never)).toThrow(/123/);
    });
});

describe("createId", () => {
    it("prefixes the id with the supplied prefix", () => {
        const id = createId("csid");
        expect(id.startsWith("csid_")).toBe(true);
    });

    it("produces a non-empty string containing a timestamp and random suffix", () => {
        const id = createId("conn");
        const parts = id.split("_");
        // prefix + timestamp(base36) + random(base36)
        expect(parts.length).toBeGreaterThanOrEqual(3);
        expect(parts[0]).toBe("conn");
        // timestamp and suffix segments are present and non-empty
        expect(parts[1]?.length).toBeGreaterThan(0);
        expect(parts[2]?.length).toBeGreaterThan(0);
    });

    it("produces distinct ids across successive calls", () => {
        const ids = new Set<string>();
        for (let i = 0; i < 50; i++) {
            ids.add(createId("x"));
        }
        // 50 draws should yield 50 distinct values (collision-resistant).
        expect(ids.size).toBe(50);
    });
});
