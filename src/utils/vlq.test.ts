import { describe, expect, it } from "vitest"

import { decodeVLQ, encodeVLQ } from "./vlq"

describe("VLQ Encode/Decode", () => {
    interface TestCase {
        name: string
        value: bigint
        wantLen: number
        wantErr: boolean
        maxBytes: number
    }

    const tests: TestCase[] = [
        { name: "zero", value: 0n, wantLen: 1, wantErr: false, maxBytes: 1 },
        {
            name: "one-byte-min",
            value: 1n,
            wantLen: 1,
            wantErr: false,
            maxBytes: 1,
        },
        {
            name: "one-byte-max",
            value: 127n,
            wantLen: 1,
            wantErr: false,
            maxBytes: 1,
        },
        {
            name: "two-bytes-min",
            value: 128n,
            wantLen: 2,
            wantErr: false,
            maxBytes: 2,
        },
        {
            name: "two-bytes-mid",
            value: 255n,
            wantLen: 2,
            wantErr: false,
            maxBytes: 2,
        },
        {
            name: "two-bytes-max",
            value: 16384n,
            wantLen: 2,
            wantErr: false,
            maxBytes: 2,
        },
        {
            name: "large-value",
            value: 1234567890n,
            wantLen: 5,
            wantErr: false,
            maxBytes: 5,
        },
        {
            name: "max-uint32",
            value: 4294967295n,
            wantLen: 5,
            wantErr: false,
            maxBytes: 5,
        },
        {
            name: "max-uint64",
            value: 18446744073709551615n,
            wantLen: 10,
            wantErr: false,
            maxBytes: 10,
        },
    ]

    tests.forEach((tt) => {
        it(`should encode and decode: ${tt.name}`, () => {
            // Test encoding
            const buf = new Uint8Array(tt.maxBytes)
            const encodeResult = encodeVLQ(buf, tt.value)

            if (tt.wantErr) {
                expect(encodeResult.ok).toBe(false)
                return
            }

            expect(encodeResult.ok).toBe(true)
            if (!encodeResult.ok) return
            expect(encodeResult.value).toBe(tt.wantLen)

            // Test decoding
            const decodeResult = decodeVLQ(buf.subarray(0, encodeResult.value))
            expect(decodeResult.ok).toBe(true)
            if (!decodeResult.ok) return
            expect(decodeResult.value.value).toBe(tt.value)
            expect(decodeResult.value.bytesRead).toBe(tt.wantLen)
        })
    })
})

describe("VLQ Encode Errors", () => {
    it("should handle buffer too small cases", () => {
        const tests = [
            { name: "buffer-too-small-one-byte", value: 127n, bufSize: 0 },
            { name: "buffer-too-small-two-bytes", value: 128n, bufSize: 1 },
            {
                name: "buffer-too-small-large-value",
                value: 1234567890n,
                bufSize: 3,
            },
        ]

        tests.forEach((tt) => {
            const buf = new Uint8Array(tt.bufSize)
            const result = encodeVLQ(buf, tt.value)
            expect(result.ok).toBe(false)
            if (!result.ok) expect(result.error).toBeDefined()
        })
    })
})

describe("VLQ Decode Errors", () => {
    it("should handle invalid input cases", () => {
        const tests = [
            { name: "empty-input", data: new Uint8Array() },
            { name: "incomplete-sequence", data: new Uint8Array([0x80]) },
            {
                name: "too-long-sequence",
                data: new Uint8Array(Array(10).fill(0x80)),
            },
        ]

        tests.forEach((tt) => {
            const result = decodeVLQ(tt.data)
            expect(result.ok).toBe(false)
            if (!result.ok) expect(result.error).toBeDefined()
        })
    })
})

describe("VLQ Round Trip", () => {
    it("should correctly round-trip encode/decode random values", () => {
        const testValues = [0n, 1n, 127n, 128n, 16383n, 16384n, 1234567890n]

        testValues.forEach((value) => {
            const buf = new Uint8Array(10)
            const encodeResult = encodeVLQ(buf, value)
            expect(encodeResult.ok).toBe(true)
            if (!encodeResult.ok) return

            const decodeResult = decodeVLQ(buf.subarray(0, encodeResult.value))
            expect(decodeResult.ok).toBe(true)
            if (!decodeResult.ok) return

            expect(decodeResult.value.value).toBe(value)
        })
    })
})
