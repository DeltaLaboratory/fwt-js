import { ed25519 } from "@noble/curves/ed25519"
import { describe, expect, it } from "vitest"

import {
    newXChaCha20Poly1305Decryptor,
    newXChaCha20Poly1305Encryptor,
} from "./encryptor"
import { Signer, Verifier } from "./index"
import { newEd25519Signer, newEd25519Verifier } from "./signer"

describe("Signer and Verifier", () => {
    // Test vectors
    const signingKey = new Uint8Array(32).fill(1) // Example key
    const verifyKey = new Uint8Array(32).fill(2) // Example key
    const encryptionKey = new Uint8Array(32).fill(3) // Example key

    describe("Basic Signing and Verification", () => {
        it("should sign and verify string data", async () => {
            // noinspection DuplicatedCode
            const signer = await Signer.new(await newEd25519Signer(signingKey))
            expect(signer.ok).toBe(true)
            if (!signer.ok) return

            const verifier = await Verifier.new(
                await newEd25519Verifier(ed25519.getPublicKey(signingKey)),
            )
            expect(verifier.ok).toBe(true)
            if (!verifier.ok) return

            const data = "Hello, World!"
            const token = await signer.value.sign(data)
            expect(token.ok).toBe(true)
            if (!token.ok) return

            const verification = await verifier.value.verify(token.value)
            expect(verification.ok).toBe(true)

            const result = await verifier.value.verifyAndUnmarshal<string>(
                token.value,
            )
            expect(result.ok).toBe(true)
            if (result.ok) {
                expect(result.value).toBe(data)
            }
        })

        it("should sign and verify complex objects", async () => {
            // noinspection DuplicatedCode
            const signer = await Signer.new(await newEd25519Signer(signingKey))
            expect(signer.ok).toBe(true)
            if (!signer.ok) return

            const verifier = await Verifier.new(
                await newEd25519Verifier(ed25519.getPublicKey(signingKey)),
            )
            expect(verifier.ok).toBe(true)
            if (!verifier.ok) return

            const data = {
                id: 123,
                name: "Test",
                array: [1, 2, 3],
                nested: { field: "value" },
            }

            // noinspection DuplicatedCode
            const token = await signer.value.sign(data)
            expect(token.ok).toBe(true)
            if (!token.ok) return

            const result = await verifier.value.verifyAndUnmarshal<typeof data>(
                token.value,
            )
            expect(result.ok).toBe(true)
            if (result.ok) {
                expect(result.value).toEqual(data)
            }
        })
    })

    describe("Encryption Integration", () => {
        it("should sign, encrypt, decrypt, and verify data", async () => {
            const signer = await Signer.new(
                await newEd25519Signer(signingKey),
                await newXChaCha20Poly1305Encryptor(encryptionKey),
            )
            expect(signer.ok).toBe(true)
            if (!signer.ok) return

            const verifier = await Verifier.new(
                await newEd25519Verifier(ed25519.getPublicKey(signingKey)),
                await newXChaCha20Poly1305Decryptor(encryptionKey),
            )
            expect(verifier.ok).toBe(true)
            if (!verifier.ok) return

            const data = { message: "Secret data" }
            // noinspection DuplicatedCode
            const token = await signer.value.sign(data)
            expect(token.ok).toBe(true)
            if (!token.ok) return

            const result = await verifier.value.verifyAndUnmarshal<typeof data>(
                token.value,
            )
            expect(result.ok).toBe(true)
            if (result.ok) {
                expect(result.value).toEqual(data)
            }
        })
    })

    describe("Error Cases", () => {
        it("should fail verification with wrong key", async () => {
            const signer = await Signer.new(await newEd25519Signer(signingKey))
            expect(signer.ok).toBe(true)
            if (!signer.ok) return

            // Create verifier with different key
            const verifier = await Verifier.new(
                await newEd25519Verifier(verifyKey),
            )
            expect(verifier.ok).toBe(true)
            if (!verifier.ok) return

            const data = "Test data"
            const token = await signer.value.sign(data)
            expect(token.ok).toBe(true)
            if (!token.ok) return

            const result = await verifier.value.verify(token.value)
            expect(result.ok).toBe(false)
        })

        it("should fail with wrong encryption key", async () => {
            const signer = await Signer.new(
                await newEd25519Signer(signingKey),
                await newXChaCha20Poly1305Encryptor(encryptionKey),
            )
            expect(signer.ok).toBe(true)
            if (!signer.ok) return

            const wrongKey = new Uint8Array(32).fill(9)
            const verifier = await Verifier.new(
                await newEd25519Verifier(signingKey),
                await newXChaCha20Poly1305Decryptor(wrongKey),
            )
            expect(verifier.ok).toBe(true)
            if (!verifier.ok) return

            const data = { secret: "value" }
            const token = await signer.value.sign(data)
            expect(token.ok).toBe(true)
            if (!token.ok) return

            const result = await verifier.value.verify(token.value)
            expect(result.ok).toBe(false)
        })

        it("should fail with invalid token format", async () => {
            const verifier = await Verifier.new(
                await newEd25519Verifier(signingKey),
            )
            expect(verifier.ok).toBe(true)
            if (!verifier.ok) return

            const invalidToken = "invalid.token.format"
            const result = await verifier.value.verify(invalidToken)
            expect(result.ok).toBe(false)
        })
    })
})
