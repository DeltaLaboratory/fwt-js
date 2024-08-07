import * as fwt from "./index.js"
import { ed448 } from "@noble/curves/ed448"
import { ed25519 } from "@noble/curves/ed25519"
import { describe, test, expect } from "vitest"

const suites = {
    suites: [
        {
            signing_algorithm: "ed25519",
            encryption_algorithm: "none",
            signing_key:
                "5dd4b03d09035490f9063db4fd271769ab9f13f371565ac712844911cfa25771",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "AFMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCE6E+CSmbVtvOXNAKOrz+tGqIg8YktG1ypxGYFHqd7lKGPY+21qT5cax9QKmAKMwbIz79aELDLeP99l2hH9PyAN",
        },
        {
            signing_algorithm: "ed448",
            encryption_algorithm: "none",
            signing_key:
                "dfb0a50e4b90e0a04fc92df1af9bc7271e199a248a2177852daa51c64d88f0e46c026819f9fcce1cfab7382c228909a700882378c0835d74c3",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "AVMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCHjtWhksJTQqLfUEoctgxMnOZfxI2MeqXvcAjEtFJXio3DpIfkgVqiIivuFDkcpKT1sTslS+7YBg4CBIhGC8PeV/pPqW6QrzdxC5FS0JFxCAzMdAHlG34RCiDrz5yPJOSd/EeZOAJTephjk5a34vRZIDwA=",
        },
        {
            signing_algorithm: "hmac-sha256",
            encryption_algorithm: "none",
            signing_key:
                "61b6af09ba66a6071f7bf642fd41f9f78b084af480326fd3c57e4d3da5da967d",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "AlMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCHzTBIeJXph48ZWjwkbCKqRxmBX6ndB42gEx67/m/Ctvg==",
        },
        {
            signing_algorithm: "hmac-sha512",
            encryption_algorithm: "none",
            signing_key:
                "7e5cfd54d96d55fdde82fca8c29ad924f613c1f071a78c7768ae66894c7c7fdc7863ba6e0585839fa4deffe44613a70c86a312592fdf6f2e22141f2001190413",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "A1MAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCHCf6L+CETQvCGNkzTvCUT2pm+bnrXAIbSd3nVT2a2dpcWhK8RqJ6vj+eT+CE9CNlh0D27MA5yrdr5dk6K7OT0V",
        },
        {
            signing_algorithm: "blake2b-256",
            encryption_algorithm: "none",
            signing_key:
                "284946f4fff7fcef02e1bdb8b16f146694213aa50e44e6031e0ba9623bc5c6a7",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "BFMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCGiBNf3SjssNNuXxM1fhmnRDTuGZ6BH/uA8Y2u+2LDSeQ==",
        },
        {
            signing_algorithm: "blake2b-512",
            encryption_algorithm: "none",
            signing_key:
                "7d9579d99f745b7ee962d819efdb40153a6e9efc3d54b6dad0556cc5b3c9629a5c0a1ea8f81d0676b682be4b985e22cdde5622197ee80e6bcad7ccc5d0c3ca0d",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "BVMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCHDYRZ+SAf1Kez/7mR5xJ7+Uxq6smIHw54pL6xkueto9SyuPN0YIH5furbSH55INrcWF9BsVTnb77PR8d1wP5rS",
        },
        {
            signing_algorithm: "blake3",
            encryption_algorithm: "none",
            signing_key:
                "76f2e5d62d435ded7981a82d4bf4ba7bdac461f89dbfdfe3599cc2a634e57536",
            encrypt_key: "",
            test_data: {
                bool: true,
                float: 3.14,
                int: 42,
                map: {
                    key: "value",
                },
                slice: ["Hello, World!"],
                text: "Hello, World!",
            },
            token: "BlMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCEtTDCxtLd9nP0BlCwntynkdIyEhjdZGOuFTtTb6zz94g==",
        },
    ],
}

const hexToUint8Array = (hex) => {
    return new Uint8Array(
        hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)),
    )
}

describe("FWT (Fast Web Token) Interop Tests", () => {
    suites.suites.forEach((suite, index) => {
        test(`Test Suite ${index + 1}: ${suite.signing_algorithm}`, async () => {
            let signer, verifier

            const signingKey = hexToUint8Array(suite.signing_key)

            switch (suite.signing_algorithm) {
                case "ed25519":
                    signer = new fwt.Signer(
                        await fwt.newEd25519Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeEd25519,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newEd25519Verifier(
                            ed25519.getPublicKey(signingKey),
                        ),
                        null,
                        fwt.SignatureType.SignatureTypeEd25519,
                    )
                    break
                case "ed448":
                    signer = new fwt.Signer(
                        await fwt.newEd448Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeEd448,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newEd448Verifier(
                            ed448.getPublicKey(signingKey),
                        ),
                        null,
                        fwt.SignatureType.SignatureTypeEd448,
                    )
                    break
                case "hmac-sha256":
                    signer = new fwt.Signer(
                        await fwt.newHMACSha256Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeHMACSha256,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newHMACSha256Verifier(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeHMACSha256,
                    )
                    break
                case "hmac-sha512":
                    signer = new fwt.Signer(
                        await fwt.newHMACSha512Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeHMACSha512,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newHMACSha512Verifier(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeHMACSha512,
                    )
                    break
                case "blake2b-256":
                    signer = new fwt.Signer(
                        await fwt.newBlake2b256Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeBlake2b256,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newBlake2b256Verifier(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeBlake2b256,
                    )
                    break
                case "blake2b-512":
                    signer = new fwt.Signer(
                        await fwt.newBlake2b512Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeBlake2b512,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newBlake2b512Verifier(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeBlake2b512,
                    )
                    break
                case "blake3":
                    signer = new fwt.Signer(
                        await fwt.newBlake3Signer(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeBlake3,
                    )
                    verifier = new fwt.Verifier(
                        await fwt.newBlake3Verifier(signingKey),
                        null,
                        fwt.SignatureType.SignatureTypeBlake3,
                    )
                    break
                default:
                    throw new Error(
                        `Unsupported signing algorithm: ${suite.signing_algorithm}`,
                    )
            }

            if (!signer || !verifier) {
                console.warn(
                    `Skipping test for ${suite.signing_algorithm} - not implemented`,
                )
                return
            }

            // Test verifying
            const verified = await verifier.verifyAndUnmarshal(suite.token)
            expect(verified).toEqual(suite.test_data)
        })
    })
})
