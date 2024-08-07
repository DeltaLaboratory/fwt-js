import * as fwt from "./index.js"
import { ed448 } from "@noble/curves/ed448"
import { ed25519 } from "@noble/curves/ed25519"
import { describe, test, expect } from "vitest"

const suites = {
    "suites": [
        {
            "signing_algorithm": "ed25519",
            "encryption_algorithm": "none",
            "signing_key": "11279cd9b1b74ee727e2d9338321a469f9509355073c4e6e859980e6236a02f2",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "AFMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCFUXQLm9NMhzQQ/ectCpUsIHvAbn2/yQRJm/WdJP/FcWuwn94h1exTZWiKwp491yhOI2n6sOteYwozyuuIChEsE"
        },
        {
            "signing_algorithm": "ed448",
            "encryption_algorithm": "none",
            "signing_key": "e5c6a797962df8156f6b6e20f4f7d4f8cfa39302d190b9e6a1b61d0e34489d8be5d39e040e1749875ef4c4fde969d219bb2b1bbf47b40de682",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "AVMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCG9fSIB8gxUcWhPLfID/uxRVFhnG3aLmORn8AI+EXlehnsR332TWxx2zgWjXzddWKPSbfyvu4I9AQCgKhuWWRckB4xalCsQkBaFURMNTKo+R0Yw4Tj8+BOGge6OdCVFyC8ePqhfpEXnHzYJVl/SDmvuLQA="
        },
        {
            "signing_algorithm": "hmac-sha256",
            "encryption_algorithm": "none",
            "signing_key": "4e9c51d372f32eb4bef32cc76b4713efaddb2942a8d303cfdd579152fe95afe5",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "AlMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCExoHfWh2yG49bYeDSNtQgfppj8lfmHkhgzjuos/ZiXnQ=="
        },
        {
            "signing_algorithm": "hmac-sha512",
            "encryption_algorithm": "none",
            "signing_key": "01f95589d68e68b9449dbff3a081facb530bac866424c4650c0808dee3fa30cdec9b0dd3812030bbab537475a87979ca5c43ef9bc04a32e26fdf277a21fc9607",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "A1MAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCGti/2vLMpg29xeOZZC2RF9u7xPeLcncrSakchcayEC6rwb8uJ9xSsj8CaP9iLpHoXcMxtQFICSFSkZrtYlqmBs"
        },
        {
            "signing_algorithm": "blake2b-256",
            "encryption_algorithm": "none",
            "signing_key": "55d8e92e178685fdefcba69c5eaf4e6acf408a244a51a8ad060f651bbb5b2de7",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "BFMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCE4Vy183curBv/LRUOzp2LPNFizgZqdIZViRtHjb9bw5g=="
        },
        {
            "signing_algorithm": "blake2b-512",
            "encryption_algorithm": "none",
            "signing_key": "1c59e29c2e8d30a53f43ec61d87783ba8c9b0bd8f64fcc6a4e5c2d8ff7ef23cb10d6b191f6bf19216a18e52f1c759eeba821e4f6795e3e54e8bb97ca4b9789f1",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "BVMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCGCr7sT1wafzWCG3TNHodLitOFqdCvyTV6jvBWRmZNw4/edlbbcOF92G040neVMLoW6Cm/57NQWch6I6RHR7Kyb"
        },
        {
            "signing_algorithm": "blake3",
            "encryption_algorithm": "none",
            "signing_key": "6961593355194644436fa125677ac728a9adec00f069aaad222c9aaae6fe380e",
            "encrypt_key": "",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "BlMAAAAAAAAApmNpbnQYKmNtYXChY2tleWV2YWx1ZWRib29s9WR0ZXh0bUhlbGxvLCBXb3JsZCFlZmxvYXT7QAkeuFHrhR9lc2xpY2WBbUhlbGxvLCBXb3JsZCGvDqcL2PTSudAarPmxQmjBVsMY36lwiKeW4+S2hDYgnA=="
        },
        {
            "signing_algorithm": "blake2b-256",
            "encryption_algorithm": "xchacha20-poly1305",
            "signing_key": "b9bc4f6daea7cc615b1d027d3b771e50bc1aa953886df2e49d8b008885f405eb",
            "encrypt_key": "b9bc4f6daea7cc615b1d027d3b771e50bc1aa953886df2e49d8b008885f405eb",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "09RcvMw4PPx7782unYIg1Ex0mqWXwQmv/FMjDtVoy/3SPxybpQeGM9LjiCu3Bt7ztND3pVyr7q3doyHEqEXHkTx+KzbByD1SJkMeUmSrFX+QiR9BjLcfWAOv0OrgeptcCNZd0AXocjAJlKEBCiW8rw1i37KXdvfhdDzUCaNg4cq7KbzKSGPgkHvO3A0PKGHlsxw177LEMe8HnxHyftEbxw1l5kc="
        },
        {
            "signing_algorithm": "blake2b-256",
            "encryption_algorithm": "aes-ecb",
            "signing_key": "3d0c84d2b824f0ab721c87a964d8a285aa037718a5f2b93c6659e661a47ecbd0",
            "encrypt_key": "3d0c84d2b824f0ab721c87a964d8a285aa037718a5f2b93c6659e661a47ecbd0",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "EeTT7GwlqX9tuV0j+7AfWG5JZTsMwhWuXR0DmDUNduSds9II9SKmuIFuyfojMmHlVg3fFLHJNwURAk/T6dZ9NXReGXsFwoOIc8CmZIKAzBIjob6lCoQXHRkifwd81nNBdGD5GPq70DgT12X+O1O8fNWlIpjyCEBYTTWVTQK03EA="
        },
        {
            "signing_algorithm": "blake2b-256",
            "encryption_algorithm": "aes-cbc",
            "signing_key": "75723048c6ea9f638c8f7273eda66f8b731103b728ce6e076939242d24471813",
            "encrypt_key": "75723048c6ea9f638c8f7273eda66f8b731103b728ce6e076939242d24471813",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "jIPl3a/9CpTsgtc/RK1qPp8TOTmT5eD9nbcCwqPIdVbljJPQBerJWJ4/HVCMyoTdWIkWsu5M1NrOyixoQWvEG0NgKmxLfS2K7SUd0oVkTGD42PFLdewP+SIHce2P5noOr6FcvG3/wvXGP0jKdns+uNGRu7z7vphyf0XWZG2smmW+SEUQnolsVmOWZEDbDDOg"
        },
        {
            "signing_algorithm": "blake2b-256",
            "encryption_algorithm": "aes-ctr",
            "signing_key": "d6134fe067c59aa34c7cc32bf922edbf5efaf0a56ce809b3a56ebd11ffd5ba79",
            "encrypt_key": "d6134fe067c59aa34c7cc32bf922edbf5efaf0a56ce809b3a56ebd11ffd5ba79",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "sjTQFVvCAQC4TiLdBbGSKdAsExx72iN89GPRO1efkfkFLTAcHn8BTrchsWvk6crSeg4UYlc/1lFfsj076zK/fYjaDLPqLCNqGg0V9sDcq0wZdT/nefOpwEW6fHUSb6u/DldAwate7NPGo+P/Q3JomfBmQyFQkJ433hLb69qrtgfZwuAQvjeY5S7B68k="
        },
        {
            "signing_algorithm": "blake2b-256",
            "encryption_algorithm": "aes-gcm",
            "signing_key": "30fb415646afa0124498beda31c2fcc36edf511a817e1e59295cd4bbfd7f4523",
            "encrypt_key": "30fb415646afa0124498beda31c2fcc36edf511a817e1e59295cd4bbfd7f4523",
            "test_data": {
                "bool": true,
                "float": 3.14,
                "int": 42,
                "map": {
                    "key": "value"
                },
                "slice": [
                    "Hello, World!"
                ],
                "text": "Hello, World!"
            },
            "token": "4M0sINgfWkn8ZxXqpSPKO6ZEJGoV+1ruwI9XINhxBbbOlEgJ2NNpBhs4r58NXbqMxWI2RKscM4fSiCR9Rp+CYic6CIJnylOWsKtpeT7ZvkvpUejoGmKn+okIDQguPGkXB787pqwItv+T+o6vLbROz1/r4QbWL6zS/nwd1SsaS3ol1nmc4JuWhPKaz4olNNTMaljc9ou8lAs="
        }
    ]
}

const hexToUint8Array = (hex) => {
    if (hex === "") {
        return new Uint8Array(0)
    }
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string")
    }
    return new Uint8Array(
        hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)),
    )
}

describe("FWT (Fast Web Token) Interop Tests", () => {
    suites.suites.forEach((suite, index) => {
        test(`Test Suite ${index + 1}: ${suite.signing_algorithm} / ${suite.encryption_algorithm}`, async () => {
            let signer, verifier, encrypter, decrypter, signatureType

            const signingKey = hexToUint8Array(suite.signing_key)
            const encryptKey = hexToUint8Array(suite.encrypt_key)

            switch (suite.signing_algorithm) {
                case "ed25519":
                    signer = await fwt.newEd25519Signer(signingKey)
                    verifier = await fwt.newEd25519Verifier(
                        ed25519.getPublicKey(signingKey),
                    )
                    signatureType = fwt.SignatureType.SignatureTypeEd25519
                    break
                case "ed448":
                    signer = await fwt.newEd448Signer(signingKey)
                    verifier = await fwt.newEd448Verifier(
                        ed448.getPublicKey(signingKey),
                    )
                    signatureType = fwt.SignatureType.SignatureTypeEd448
                    break
                case "hmac-sha256":
                    signer = await fwt.newHMACSha256Signer(signingKey)
                    verifier = await fwt.newHMACSha256Verifier(signingKey)
                    signatureType = fwt.SignatureType.SignatureTypeHMACSha256
                    break
                case "hmac-sha512":
                    signer = await fwt.newHMACSha512Signer(signingKey)
                    verifier = await fwt.newHMACSha512Verifier(signingKey)
                    signatureType = fwt.SignatureType.SignatureTypeHMACSha512
                    break
                case "blake2b-256":
                    signer = await fwt.newBlake2b256Signer(signingKey)
                    verifier = await fwt.newBlake2b256Verifier(signingKey)
                    signatureType = fwt.SignatureType.SignatureTypeBlake2b256
                    break
                case "blake2b-512":
                    signer = await fwt.newBlake2b512Signer(signingKey)
                    verifier = await fwt.newBlake2b512Verifier(signingKey)
                    signatureType = fwt.SignatureType.SignatureTypeBlake2b512
                    break
                case "blake3":
                    signer = await fwt.newBlake3Signer(signingKey)
                    verifier = await fwt.newBlake3Verifier(signingKey)
                    signatureType = fwt.SignatureType.SignatureTypeBlake3
                    break
                default:
                    throw new Error(
                        `Unsupported signing algorithm: ${suite.signing_algorithm}`,
                    )
            }

            switch (suite.encryption_algorithm) {
                case "none":
                    break
                case "xchacha20-poly1305":
                    encrypter = await fwt.newXChaCha20Poly1305Encrypter(encryptKey)
                    decrypter = await fwt.newXChaCha20Poly1305Decrypter(encryptKey)
                    break
                case "aes-ecb":
                    encrypter = await fwt.newAESECBEncrypter(encryptKey)
                    decrypter = await fwt.newAESECBDecrypter(encryptKey)
                    break
                case "aes-cbc":
                    encrypter = await fwt.newAESCBCEncrypter(encryptKey)
                    decrypter = await fwt.newAESCBCDecrypter(encryptKey)
                    break
                case "aes-ctr":
                    encrypter = await fwt.newAESCTREncrypter(encryptKey)
                    decrypter = await fwt.newAESCTRDecrypter(encryptKey)
                    break
                case "aes-gcm":
                    encrypter = await fwt.newAESGCMEncrypter(encryptKey)
                    decrypter = await fwt.newAESGCMDecrypter(encryptKey)
                    break
                default:
                    throw new Error(
                        `Unsupported encryption algorithm: ${suite.encryption_algorithm}`,
                    )
            }

            if (!signer || !verifier) {
                console.warn(
                    `Skipping test for ${suite.signing_algorithm} - not implemented`,
                )
                return
            }

            signer = new fwt.Signer(signer, encrypter, signatureType)
            verifier = new fwt.Verifier(verifier, decrypter, signatureType)

            // Test verifying
            const verified = await verifier.verifyAndUnmarshal(suite.token)
            expect(verified).toEqual(suite.test_data)
        })
    })
})
