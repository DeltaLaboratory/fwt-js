import * as fwt from "./index.js"
import { ed448 } from "@noble/curves/ed448"
import { ed25519 } from "@noble/curves/ed25519"
import { bench, describe } from "vitest"

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

describe("FWT JS Benchmarks", () => {
    // benchmark tests
    // signer/verifier use no encryption
    // encryption/decryption use blake2b256 for signing
    describe("Signer Benchmark Tests", () => {
        bench("Ed25519 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newEd25519Signer(ed25519PVK),
                null,
                fwt.SignatureType.SignatureTypeEd25519,
            )

            await signer.sign(testData)
        })

        bench("Ed448 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newEd448Signer(ed448PVK),
                null,
                fwt.SignatureType.SignatureTypeEd448,
            )

            await signer.sign(testData)
        })

        bench("HMAC-SHA256 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newHMACSha256Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha256,
            )

            await signer.sign(testData)
        })

        bench("HMAC-SHA512 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newHMACSha512Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha512,
            )

            await signer.sign(testData)
        })

        bench("Blake2b256 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await signer.sign(testData)
        })

        bench("Blake2b512 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b512Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b512,
            )

            await signer.sign(testData)
        })

        bench("Blake3 Sign", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake3Signer(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake3,
            )

            await signer.sign(testData)
        })
    })

    describe("Verifier Benchmark Tests", () => {
        bench("Ed25519 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newEd25519Verifier(ed25519PBK),
                null,
                fwt.SignatureType.SignatureTypeEd25519,
            )

            await verifier.verify(
                `AGcAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKseAAwdYJXt/k3xhjeD66Xv10kyTF8EsEDHAPJsfJ0pKgq04dU1dpwv3D6YMKK3VY6NY6pU1BlP9mFa5Ngfwug0=`,
            )
        })

        bench("Ed448 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newEd448Verifier(ed448PBK),
                null,
                fwt.SignatureType.SignatureTypeEd448,
            )

            await verifier.verify(
                `AWcAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKljLOIWzBx3GAlaRUiJX07IswDUbtkhHu9oMZy2WB39ofHWSZgMcZfQJXodJlDQZUTdz3hiW9C3CgHqii5Ux2fIc6kACHAuG5g5Fn2uoY7sToqp7ujYnkL4C8plFHyeXqEnzl+EyGfXL5P1OiDJWVOM3AA==`,
            )
        })

        bench("HMAC-SHA256 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newHMACSha256Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha256,
            )

            await verifier.verify(
                ` AmcAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKnMTVpcLyZTIJ2KSpNhz1T3KiEA2V+hJU4Tp7rEgdIMV`,
            )
        })

        bench("HMAC-SHA512 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newHMACSha512Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeHMACSha512,
            )

            await verifier.verify(
                `A2cAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKvA31/KL8x6hjcdiPsUrXFaAVjnyhmBnSE48gFFR34GlaOqQG9yxBqU+JX5nuT4V163QXzwZyKVEAyjAbAH3CWI=`,
            )
        })

        bench("Blake2b256 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await verifier.verify(
                `BGcAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKs39Mzw=`,
            )
        })

        bench("Blake2b512 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b512Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake2b512,
            )

            await verifier.verify(
                `BWcAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKh2p5jkSkIn+`,
            )
        })

        bench("Blake3 Verify", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake3Verifier(byteKey),
                null,
                fwt.SignatureType.SignatureTypeBlake3,
            )

            await verifier.verify(
                `BmcAAABnAAAAuQAHYUEYKmFCY2Zvb2FDgwECA2FEuQABY2Zvb2NiYXJhRcEaX+5mAGFG2EBYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYUe5AAFjZm9vuQABY2JhcrkAAWNiYXoYKsD3s9bglJXdVGH71zRKeBT7bJYL2/6zl6WhCsgSJaDJ`,
            )
        })
    })

    describe("Encryptor Benchmark Tests", () => {
        bench("XChaCha20Poly1305 Encrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newXChaCha20Poly1305Encrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await signer.sign(testData)
        })

        bench("AES-ECB Encrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESECBEncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await signer.sign(testData)
        })

        bench("AES-CBC Encrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESCBCEncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await signer.sign(testData)
        })

        bench("AES-CTR Encrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESCTREncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await signer.sign(testData)
        })

        bench("AES-GCM Encrypt", async () => {
            const signer = new fwt.Signer(
                await fwt.newBlake2b256Signer(byteKey),
                await fwt.newAESGCMEncrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await signer.sign(testData)
        })
    })

    describe("Decrypter Benchmark Tests", () => {
        bench("XChaCha20Poly1305 Decrypt", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newXChaCha20Poly1305Decrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await verifier.verify(
                `6c+LQAKGkJt+N4OBVt9ebcTSjoBRgKVOlGaov8yeb1ADqa9VfPllXcesex6Cyvt391NsZTCDMZqIX1kvbrU9cKibLp0IUjVgYGtSdLgpqnpRDM26IaGvhGdfmJ+3zV0vjRIGJjZOlCenjNL9eHIF4JYEdtELOITa3S3fFJWA4Gr/1L5fUO08HzBsyDn3rTMp8GW8Q4V5KZRZIHXE`,
            )
        })

        bench("AES-ECB Decrypt", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESECBDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await verifier.verify(
                `zrG2xVWt/2uakFkP2Q0VWCZQvw9GLuqkAFXQ96K3ufikcyAc/XN0tsjL3npip0NZ44Na7XH24GHCGlzPvjAGS9yVwHiiQImJrUiiFJKEIIcwwoJu2QHjU+k4Xn4xEr0ND+4NO8UZw1Wth3U9wHcYl6RexsYlS22zykYS1XyFcog=`,
            )
        })

        bench("AES-CBC Decrypt", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESCBCDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await verifier.verify(
                `4WtsxSYiMEggqAvKGGVHpC5i6OYfYmt+jPAMjlNt5RUDs04vTgnhzHor4xQjaJE1Ecm/uaOUUUcXNWt72HfLlvboG0LV6246kYNQKo1Nadgn5VwQIwPJ7BnkNKx/2Li4oBAQPSXalz5OI4IcWrWdZnj2Tq+SIzxuk/jCJ+dGhO49Gjbn13eDOZavwLqJnONrWT2O+5KWBe/PL8VAz0e7/w==`,
            )
        })

        bench("AES-CTR Decrypt", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESCTRDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await verifier.verify(
                `BfFmbQ+wswrrR0sTkLO9XX0pk7xPNnVDFd73DOtcTSlQ7HaG0akEoIgt/aegyWlhz4ww2S9OWFyZSROqp5kjDLgwe8auCnK9rkvs+eSZf4sk6l/CtoeJBSIwHmOOP0i0OKf5WKffc8ScEPA7dfWAGJCZuk/dKvmDliBKGXIiSwgJNzf5`,
            )
        })

        bench("AES-GCM Decrypt", async () => {
            const verifier = new fwt.Verifier(
                await fwt.newBlake2b256Verifier(byteKey),
                await fwt.newAESGCMDecrypter(byteKey),
                fwt.SignatureType.SignatureTypeBlake2b256,
            )

            await verifier.verify(
                `c3gOqjgq75oMlbCLTNr7UX/garmFuNLETO6U19eLQPlZxk7uCxtAhYuTiFeh0Fnpwc3gVwR/LZITelbtV6QSl6pAnKsJScE4EiUguSFo9T7aPLvoaq/K+uqeN1TMCD4IrPRMwrPCVHxbiRERytVCb6xEnC1Caa56l2tZGhARfD8VxUmyHM8QAL+Z+dTA+XVY`,
            )
        })
    })
})
