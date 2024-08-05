import * as fwt from "./index.js"
import { ed25519 } from "@noble/curves/ed25519"

// Assuming the original code is in a file named fwt.js

function describe(name, fn) {
    console.log(name)
    fn()
}

function test(name, fn) {
    console.log(name)
    fn()
}

function expect(actual) {
    return {
        toBe(expected) {
            if (JSON.stringify(actual) !== JSON.stringify(expected)) {
                throw new Error(`Expected ${expected}, but got ${actual}`)
            }
            console.log(
                `match: provided: ${JSON.stringify(actual)}, expected: ${JSON.stringify(expected)}`,
            )
        },
        toEqual(expected) {
            if (JSON.stringify(actual) !== JSON.stringify(expected)) {
                throw new Error(`Expected ${expected}, but got ${actual}`)
            }
            console.log(
                `match: provided: ${JSON.stringify(actual)}, expected: ${JSON.stringify(expected)}`,
            )
        },
    }
}

describe("FWT (Fast Web Token) Tests", () => {
    // Test Ed25519 signing and verification
    test("Ed25519 Sign and Verify", async () => {
        const privateKey = ed25519.utils.randomPrivateKey()
        const publicKey = ed25519.getPublicKey(privateKey)

        const signer = new fwt.Signer(
            fwt.newEd25519Signer(privateKey),
            null,
            fwt.SignatureType.SignatureTypeEd25519,
        )

        const verifier = new fwt.Verifier(
            fwt.newEd25519Verifier(publicKey),
            null,
            fwt.SignatureType.SignatureTypeEd25519,
        )

        const data = { foo: "bar" }
        const token = await signer.sign(data)
        console.log(`Ed25519 token: ${token}`)
        const verified = await verifier.verifyAndUnmarshal(token)

        expect(verified).toEqual(data)
    })

    test("Ed25519 Sign and Verify with Encryption", async () => {
        const privateKey = ed25519.utils.randomPrivateKey()
        const publicKey = ed25519.getPublicKey(privateKey)
        const encryptionKey = new Uint8Array(32)
        crypto.getRandomValues(encryptionKey)

        const signer = new fwt.Signer(
            fwt.newEd25519Signer(privateKey),
            fwt.newAESCTREncryptor(encryptionKey),
            fwt.SignatureType.SignatureTypeEd25519,
        )

        const verifier = new fwt.Verifier(
            fwt.newEd25519Verifier(publicKey),
            fwt.newAESCTRDecrypter(encryptionKey),
            fwt.SignatureType.SignatureTypeEd25519,
        )

        const data = { foo: "bar" }
        const token = await signer.sign(data)
        console.log(`Ed25519 token: ${token}`)
        const verified = await verifier.verifyAndUnmarshal(token)

        expect(verified).toEqual(data)
    })

    // Test HMAC-SHA256 signing and verification
    test("HMAC-SHA256 Sign and Verify", async () => {
        const key = new TextEncoder().encode("secret-key")

        const signer = new fwt.Signer(
            await fwt.newHMACSha256Signer(key),
            null,
            fwt.SignatureType.SignatureTypeHMACSha256,
        )

        const verifier = new fwt.Verifier(
            await fwt.newHMACSha256Verifier(key),
            null,
            fwt.SignatureType.SignatureTypeHMACSha256,
        )

        const data = { hello: "world" }
        const token = await signer.sign(data)
        console.log(`HMAC-SHA256 token: ${token}`)
        const verified = await verifier.verifyAndUnmarshal(token)

        expect(verified).toEqual(data)
    })

    // Test XChaCha20-Poly1305 encryption and decryption
    test("XChaCha20-Poly1305 Encrypt and Decrypt", async () => {
        const key = new Uint8Array(32) // 32-byte key
        crypto.getRandomValues(key)

        const signer = new fwt.Signer(
            await fwt.newBlake2b256Signer(key),
            fwt.newXChaCha20PolyEncryptor(key),
            fwt.SignatureType.SignatureTypeBlake2b256,
        )
        const verifier = new fwt.Verifier(
            await fwt.newBlake2b256Verifier(key),
            fwt.newXChaCha20PolyDecrypter(key),
            fwt.SignatureType.SignatureTypeBlake2b256,
        )

        const data = new TextEncoder().encode("Hello, World!")
        const token = await signer.sign(data)
        console.log(`XChaCha20-Poly1305 token: ${token}`)
        const decrypted = await verifier.verifyAndUnmarshal(token)

        expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!")
    })

    // Test AES-CBC encryption and decryption
    test("AES-CBC Encrypt and Decrypt", async () => {
        const key = new Uint8Array(32) // 32-byte key
        crypto.getRandomValues(key)

        const signer = new fwt.Signer(
            await fwt.newBlake2b256Signer(key),
            fwt.newAESCBCEncryptor(key),
            fwt.SignatureType.SignatureTypeBlake2b256,
        )

        const verifier = new fwt.Verifier(
            await fwt.newBlake2b256Verifier(key),
            fwt.newAESCBCDecrypter(key),
            fwt.SignatureType.SignatureTypeBlake2b256,
        )

        const data = new TextEncoder().encode("Hello, World!")
        const token = await signer.sign(data)
        console.log(`AES-CBC token: ${token}`)
        const decrypted = await verifier.verifyAndUnmarshal(token)
    })

    test("External Generated Token", async () => {
        const key = new Uint8Array(32)
        for (let i = 0; i < 32; i++) {
            key[i] = 48
        }
        const token =
            "BkQAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAwAESnNvbWUgYnl0ZXNfUfdgdxFn2YAdHaO3VFbnyNTQOKBjc1/dlonKx8vE/Q=="

        const verifier = new fwt.Verifier(
            await fwt.newBlake3Verifier(key),
            null,
            fwt.SignatureType.SignatureTypeBlake3,
        )

        const verified = await verifier.verifyAndUnmarshal(token)
        console.log(verified)
    })

    // Test signing and verifying with encryption
    test("Sign, Encrypt, Decrypt, and Verify", async () => {
        const signingKey = new TextEncoder().encode("signing-key")
        const encryptionKey = new Uint8Array(32)
        crypto.getRandomValues(encryptionKey)

        const signer = new fwt.Signer(
            await fwt.newBlake2b256Signer(signingKey),
            fwt.newAESCTREncryptor(encryptionKey),
            fwt.SignatureType.SignatureTypeBlake2b256,
        )

        const verifier = new fwt.Verifier(
            await fwt.newBlake2b256Verifier(signingKey),
            fwt.newAESCTRDecrypter(encryptionKey),
            fwt.SignatureType.SignatureTypeBlake2b256,
        )

        const data = { sensitive: "data" }
        const token = await signer.sign(data)
        console.log(`Encrypted token: ${token}`)
        const verified = await verifier.verifyAndUnmarshal(token)

        expect(verified).toEqual(data)
    })
})
