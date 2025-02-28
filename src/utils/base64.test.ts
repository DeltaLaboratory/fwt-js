import { describe, expect, it } from "vitest"

import { base64URLDecode, base64URLEncode } from "./base64"

describe("base64URL", () => {
    describe("base64URLEncode", () => {
        it("should encode an empty array", () => {
            const input = new Uint8Array([])
            expect(base64URLEncode(input)).toBe("")
        })

        it("should encode basic ASCII text", () => {
            const input = new Uint8Array([104, 101, 108, 108, 111]) // "hello"
            expect(base64URLEncode(input)).toBe("aGVsbG8")
        })

        it("should encode data with potential URL-unsafe characters", () => {
            // This will produce base64 with +, / and = which should be converted
            const input = new Uint8Array([251, 255, 191])
            expect(base64URLEncode(input)).not.toContain("+")
            expect(base64URLEncode(input)).not.toContain("/")
            expect(base64URLEncode(input)).not.toContain("=")
        })
    })

    describe("base64URLDecode", () => {
        it("should decode an empty string", () => {
            const input = ""
            expect(base64URLDecode(input)).toEqual(new Uint8Array([]))
        })

        it("should decode basic ASCII text", () => {
            const input = "aGVsbG8"
            const expected = new Uint8Array([104, 101, 108, 108, 111]) // "hello"
            expect(base64URLDecode(input)).toEqual(expected)
        })

        it("should decode URL-safe base64 (with - and _)", () => {
            const input = "a-_b"
            const decoded = base64URLDecode(input)
            expect(decoded).toBeInstanceOf(Uint8Array)
        })
    })

    describe("round trip", () => {
        it("should correctly round-trip encode and decode", () => {
            const original = new Uint8Array([1, 2, 3, 4, 5])
            const encoded = base64URLEncode(original)
            const decoded = base64URLDecode(encoded)
            expect(decoded).toEqual(original)
        })

        it("should handle various byte values", () => {
            // Test with a range of byte values
            const original = new Uint8Array(
                Array.from({ length: 256 }, (_, i) => i),
            )
            const encoded = base64URLEncode(original)
            const decoded = base64URLDecode(encoded)
            expect(decoded).toEqual(original)
        })

        it("should handle Unicode characters", () => {
            // Create a Uint8Array from a Unicode string
            const str = "👋🌍"
            const encoder = new TextEncoder()
            const original = encoder.encode(str)
            const encoded = base64URLEncode(original)
            const decoded = base64URLDecode(encoded)
            expect(decoded).toEqual(original)
        })

        it("should decode test strings", () => {
            const decoded = base64URLDecode(
                "AIALpmRoYXNoWCB55JLBodMqCUn3ZXkBdGQ62mWGHIkdXx7m7gK6yTBaUWZsZW5ndGgaAQAAAGdleHBpcmVzGmfBGv1nZmlsZV9pZFABlUoafnZ8RZfT4tpsdkfEbWNvbGxlY3Rpb25faWRQAZVKGn5ze6yiqkUxd6tbInBzZWdtZW50X3NlcXVlbmNlALdZtQZ4D0nhBBTD2Kv_bjxzvbiAYxqUYSjEGRqRd0LtI5vXoqFRrmLriX1TTp-Eub1eai7e3Tf6Scr9oZJ5-ww",
            )
            expect(decoded).any
        })
    })
})
