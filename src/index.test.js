import * as fwt from "./index.js"
import { ed448 } from "@noble/curves/ed448"
import { ed25519 } from "@noble/curves/ed25519"
import { describe, test, expect } from "vitest"

const testData = {
    A: 42,
    B: "foo",
    C: [1, 2, 3],
    D: { foo: "bar" },
    E: new Date("2021-01-01T00:00:00Z"),
    F: new Uint8Array(32),
    G: { foo: { bar: { baz: 42 } } },
}

const ed25519PVK = Uint8Array.from([
    0x8a, 0xea, 0xd7, 0xac, 0xf0, 0xae, 0x31, 0x59, 0x00, 0x26, 0x66, 0xec,
    0x5a, 0x15, 0xdb, 0x6b, 0x97, 0x91, 0x30, 0xac, 0x2c, 0xa1, 0x32, 0x68,
    0xa5, 0xda, 0xf7, 0xfb, 0xfe, 0xb4, 0x7f, 0x17,
])
const ed25519PBK = ed25519.getPublicKey(ed25519PVK)

const ed448PVK = Uint8Array.from([
    0x77, 0xe8, 0xfc, 0x42, 0xb0, 0x12, 0xd4, 0xbb, 0x42, 0xf3, 0x45, 0x06,
    0xc7, 0x11, 0xee, 0xf6, 0xf4, 0x3f, 0x18, 0x2c, 0xa2, 0xd4, 0xa9, 0xaf,
    0xe4, 0xeb, 0xf2, 0x7f, 0xb6, 0x52, 0x20, 0xdc, 0xfc, 0xf3, 0x39, 0x93,
    0x03, 0xe3, 0xfa, 0xbb, 0xd2, 0xbc, 0xb3, 0xa3, 0xb4, 0x73, 0x72, 0x9f,
    0xe8, 0x72, 0x26, 0xdd, 0x2f, 0x50, 0x55, 0x82, 0x80,
])
const ed448PBK = ed448.getPublicKey(ed448PVK)

const byteKey = Uint8Array.from([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

describe("FWT JS Tests", () => {
    // test signer/verifier
    describe("Signer/Verifier Tests", () => {
        test("Ed25519 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newEd25519Signer(ed25519PVK),
                null,
                fwt.SignatureType.SignatureTypeEd25519,
            )

            const verifier = new fwt.Verifier(
                await fwt.newEd25519Verifier(ed25519PBK),
                null,
                fwt.SignatureType.SignatureTypeEd25519,
            )

            const token = await signer.sign(testData)
            console.log(`Ed25519 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Ed25519 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newEd25519Signer(ed25519PVK),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeEd25519,
            )

            const verifier = new fwt.Verifier(
                await fwt.newEd25519Verifier(ed25519PBK),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeEd25519,
            )

            const token = await signer.sign(testData)
            console.log(`Ed25519 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Ed448 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newEd448Signer(ed448PVK),
                null,
                fwt.SignatureType.SignatureTypeEd448,
            )

            const verifier = new fwt.Verifier(
                await fwt.newEd448Verifier(ed448PBK),
                null,
                fwt.SignatureType.SignatureTypeEd448,
            )

            const token = await signer.sign(testData)
            console.log(`Ed448 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Ed448 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newEd448Signer(ed448PVK),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeEd448,
            )

            const verifier = new fwt.Verifier(
                await fwt.newEd448Verifier(ed448PBK),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeEd448,
            )

            const token = await signer.sign(testData)
            console.log(`Ed448 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("HMAC-SHA256 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newHMACSha256Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newHMACSha256Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha256,
            )

            const token = await signer.sign(testData)
            console.log(`HMAC-SHA256 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("HMAC-SHA256 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newHMACSha256Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeHMACSha256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newHMACSha256Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeHMACSha256,
            )

            const token = await signer.sign(testData)
            console.log(`HMAC-SHA256 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("HMAC-SHA512 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newHMACSha512Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha512,
            )

            const verifier = new fwt.Verifier(
                await fwt.newHMACSha512Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha512,
            )

            const token = await signer.sign(testData)
            console.log(`HMAC-SHA512 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("HMAC-SHA512 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newHMACSha512Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeHMACSha512,
            )

            const verifier = new fwt.Verifier(
                await fwt.newHMACSha512Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeHMACSha512,
            )

            const token = await signer.sign(testData)
            console.log(`HMAC-SHA512 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Blake2b256 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`Blake2b256 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Blake2b256 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`Blake2b256 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Blake2b512 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b512Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b512,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b512Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b512,
            )

            const token = await signer.sign(testData)
            console.log(`Blake2b512 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Blake2b512 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b512Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b512,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b512Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b512,
            )

            const token = await signer.sign(testData)
            console.log(`Blake2b512 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Blake3 Sign and Verify", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake3Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake3,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake3Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake3,
            )

            const token = await signer.sign(testData)
            console.log(`Blake3 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("Blake3 Sign and Verify with Encryption", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake3Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake3,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake3Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake3,
            )

            const token = await signer.sign(testData)
            console.log(`Blake3 token: ${token}`)

            expect(async () => await verifier.verify(token)).not.toThrow()
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })
    })

    // test encryption/decryption, use blake2b256 for testing
    describe("Encryptor/Decrypter Tests", () => {
        test("XChaCha20Poly1305 Encrypt and Decrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newXChaCha20Poly1305Encrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newXChaCha20Poly1305Decrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`XChaCha20Poly token: ${token}`)
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("AES-ECB Encrypt and Decrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESECBEncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESECBDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`AES-ECB token: ${token}`)
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("AES-CBC Encrypt and Decrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESCBCEncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESCBCDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`AES-CBC token: ${token}`)
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("AES-CTR Encrypt and Decrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`AES-CTR token: ${token}`)
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })

        test("AES-GCM Encrypt and Decrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESGCMEncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESGCMDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            const token = await signer.sign(testData)
            console.log(`AES-GCM token: ${token}`)
            const verified = await verifier.verifyAndUnmarshal(token)

            expect(verified).toEqual(testData)
        })
    })
})
