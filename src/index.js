import { ed448 } from "@noble/curves/ed448"
import { ed25519 } from "@noble/curves/ed25519"
import { blake2b } from "@noble/hashes/blake2b"
import { blake3 } from "@noble/hashes/blake3"
import { hmac } from "@noble/hashes/hmac"
import { sha256, sha512 } from "@noble/hashes/sha2"
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305"
import aesjs from "aes-js"
import * as cbor from "cbor-x"

export const defaultCtx = "github.com/DeltaLaboratory/fwt"

// SignatureType enum
export const SignatureType = {
    SignatureTypeEd25519: 0,
    SignatureTypeEd448: 1,
    SignatureTypeHMACSha256: 2,
    SignatureTypeHMACSha512: 3,
    SignatureTypeBlake2b256: 4,
    SignatureTypeBlake2b512: 5,
    SignatureTypeBlake3: 6,
}

export class Signer {
    constructor(signer, encryptor, signatureType) {
        this.signatureType = signatureType
        this.signer = signer
        this.encryptor = encryptor
    }

    async sign(data) {
        const marshaled = cbor.encode(data)
        const signature = await this.signer(marshaled)

        let token = new Uint8Array(1 + 8 + marshaled.length + signature.length)
        token[0] = this.signatureType
        for (let i = 0; i < 8; i++) {
            token[1 + i] = (marshaled.length >> (8 * i)) & 0xff
        }

        token.set(marshaled, 9)
        token.set(signature, 9 + marshaled.length)

        if (this.encryptor) {
            const encrypted = await this.encryptor(token)
            return btoa(String.fromCharCode.apply(null, encrypted))
        }
        return btoa(String.fromCharCode.apply(null, token))
    }
}

export class Verifier {
    constructor(verifier, decrypter, signatureType) {
        this.signatureType = signatureType
        this.verifier = verifier
        this.decrypter = decrypter
    }

    async verify(token) {
        let tokenDecoded = new Uint8Array(
            atob(token)
                .split("")
                .map((char) => char.charCodeAt(0)),
        )

        if (this.decrypter) {
            tokenDecoded = await this.decrypter(tokenDecoded)
        }

        if (tokenDecoded.length < 9) {
            throw new Error("Invalid token: too short")
        }

        const sigType = tokenDecoded[0]
        if (sigType !== this.signatureType) {
            throw new Error(
                `Invalid token: invalid signature type: allowed ${this.signatureType}, got ${sigType}`,
            )
        }

        let marshaledLen = 0
        for (let i = 0; i < 8; i++) {
            marshaledLen |= tokenDecoded[1 + i] << (8 * i)
        }

        if (marshaledLen < 0) {
            throw new Error("Invalid token: invalid marshaled length")
        }

        if (tokenDecoded.length < 1 + 8 + marshaledLen) {
            throw new Error("Invalid signature")
        }

        return this.verifier(
            tokenDecoded.slice(9, 9 + marshaledLen),
            tokenDecoded.slice(9 + marshaledLen),
        )
    }

    async verifyAndUnmarshal(token) {
        let tokenDecoded = new Uint8Array(
            atob(token)
                .split("")
                .map((char) => char.charCodeAt(0)),
        )

        if (this.decrypter) {
            tokenDecoded = await this.decrypter(tokenDecoded)
        }

        if (tokenDecoded.length < 9) {
            throw new Error("Invalid token: too short")
        }

        const sigType = tokenDecoded[0]
        if (sigType !== this.signatureType) {
            throw new Error("Invalid token: invalid signature type")
        }

        let marshaledLen = 0
        for (let i = 0; i < 8; i++) {
            marshaledLen |= tokenDecoded[1 + i] << (8 * i)
        }

        if (marshaledLen < 0) {
            throw new Error("Invalid token: invalid marshaled length")
        }

        if (tokenDecoded.length < 1 + 8 + marshaledLen) {
            throw new Error("Invalid signature")
        }

        await this.verifier(
            tokenDecoded.slice(9, 9 + marshaledLen),
            tokenDecoded.slice(9 + marshaledLen),
        )

        return cbor.decode(tokenDecoded.slice(9, 9 + marshaledLen))
    }
}

function pkcs7Pad(data, blockSize) {
    const padder = blockSize - (data.length % blockSize)
    const padding = new Uint8Array(padder).fill(padder)
    return new Uint8Array([...data, ...padding])
}

function pkcs7Unpad(data) {
    const padLength = data[data.length - 1]
    return data.slice(0, -padLength)
}

function randomBytes(length) {
    return new Uint8Array(crypto.getRandomValues(new Uint8Array(length)))
}

// hashKey hashes the key to the specified size using the specified algorithm.
async function hashKey(key, size, algo = "blake2b") {
    if (algo === "blake2b") {
        if (key.length > size) {
            return blake2b(key, { dkLen: size })
        }
        return key
    } else if (algo === "blake3") {
        if (key.length === size) {
            return key
        }
        return blake3(key, { dkLen: size })
    }
    throw new Error("Unsupported algorithm")
}

// constantComparison performs a constant time comparison of two byte arrays.
function constantComparison(a, b) {
    if (a.length !== b.length) {
        return false
    }

    let result = 0
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i]
    }
    return result === 0
}

export async function newEd25519Signer(key) {
    return async function (data) {
        return ed25519.sign(data, key)
    }
}

export async function newEd25519Verifier(key) {
    return async function (data, sig) {
        if (ed25519.verify(sig, data, key, { zip215: false })) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newEd448Signer(key, context = defaultCtx) {
    const encoder = new TextEncoder()
    const ctx = encoder.encode(context)
    return async function (data) {
        return ed448.sign(data, key, { context: ctx })
    }
}

export async function newEd448Verifier(key, context = defaultCtx) {
    const encoder = new TextEncoder()
    const ctx = encoder.encode(context)
    return async function (data, sig) {
        if (ed448.verify(sig, data, key, { context: ctx, zip215: false })) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newHMACSha256Signer(key) {
    return async function (data) {
        return hmac(sha256, key, data)
    }
}

export async function newHMACSha256Verifier(key) {
    return async function (data, sig) {
        const digest = hmac(sha256, key, data)
        if (constantComparison(digest, sig)) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newHMACSha512Signer(key) {
    return async function (data) {
        return hmac(sha512, key, data)
    }
}

export async function newHMACSha512Verifier(key) {
    return async function (data, sig) {
        const digest = hmac(sha512, key, data)
        if (constantComparison(digest, sig)) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newBlake2b256Signer(key) {
    key = await hashKey(key, 64)
    return async function (data) {
        return blake2b(data, {
            key: key,
            dkLen: 32,
        })
    }
}

export async function newBlake2b256Verifier(key) {
    key = await hashKey(key, 64)
    return async function (data, sig) {
        const digest = blake2b(data, {
            key: key,
            dkLen: 32,
        })
        if (constantComparison(digest, sig)) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newBlake2b512Signer(key) {
    key = await hashKey(key, 64)
    return async function (data) {
        return blake2b(data, {
            key: key,
            dkLen: 64,
        })
    }
}

export async function newBlake2b512Verifier(key) {
    key = await hashKey(key, 64)
    return async function (data, sig) {
        const digest = blake2b(data, {
            key: key,
            dkLen: 64,
        })
        if (constantComparison(digest, sig)) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newBlake3Signer(key) {
    key = await hashKey(key, 32, "blake3")
    return async function (data) {
        return blake3(data, {
            key: key,
            dkLen: 32,
        })
    }
}

export async function newBlake3Verifier(key) {
    key = await hashKey(key, 32, "blake3")
    return async function (data, sig) {
        const digest = blake3(data, {
            key: key,
            dkLen: 32,
        })
        if (constantComparison(digest, sig)) {
            return
        }
        throw new Error("Invalid signature")
    }
}

export async function newXChaCha20Poly1305Encrypter(key) {
    return async (data) => {
        const aead = new XChaCha20Poly1305(key)
        const nonce = randomBytes(aead.nonceLength)
        const encrypted = aead.seal(nonce, data)
        const concat = new Uint8Array(nonce.length + encrypted.length)
        concat.set(nonce)
        concat.set(encrypted, nonce.length)
        return concat
    }
}

export async function newXChaCha20Poly1305Decrypter(key) {
    return async (data) => {
        const aead = new XChaCha20Poly1305(key)
        if (data.length < aead.nonceLength) {
            throw new Error("Invalid data")
        }
        const nonce = data.slice(0, aead.nonceLength)
        const ciphertext = data.slice(aead.nonceLength)
        return aead.open(nonce, ciphertext)
    }
}

// You may be already know it: ECB mode is insecure. Use it only for demonstration purposes.
export async function newAESECBEncrypter(key) {
    return async function (data) {
        const aesCbc = new aesjs.ModeOfOperation.ecb(key)
        const padded = pkcs7Pad(data, 16)
        return aesCbc.encrypt(padded)
    }
}

// You may be already know it: ECB mode is insecure. Use it only for demonstration purposes.
export async function newAESECBDecrypter(key) {
    return async function (data) {
        const aesCbc = new aesjs.ModeOfOperation.ecb(key)
        const decrypted = aesCbc.decrypt(data)
        return pkcs7Unpad(decrypted)
    }
}

export async function newAESCBCEncrypter(key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-CBC" },
        false,
        ["encrypt"],
    )
    return async function (data) {
        const iv = randomBytes(16)
        const padded = pkcs7Pad(data, 16)
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv },
            cryptoKey,
            padded,
        )
        return new Uint8Array([...iv, ...new Uint8Array(encrypted)])
    }
}

export async function newAESCBCDecrypter(key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-CBC" },
        false,
        ["decrypt"],
    )
    return async function (data) {
        const iv = data.slice(0, 16)
        const encrypted = data.slice(16)
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv },
            cryptoKey,
            encrypted,
        )
        return pkcs7Unpad(new Uint8Array(decrypted))
    }
}

export async function newAESCTREncrypter(key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-CTR" },
        false,
        ["encrypt"],
    )
    return async function (data) {
        const nonce = randomBytes(16)
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-CTR", counter: nonce, length: 64 },
            cryptoKey,
            data,
        )
        return new Uint8Array([...nonce, ...new Uint8Array(encrypted)])
    }
}

export async function newAESCTRDecrypter(key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-CTR" },
        false,
        ["decrypt"],
    )
    return async function (data) {
        const nonce = data.slice(0, 16)
        const encrypted = data.slice(16)
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-CTR", counter: nonce, length: 64 },
            cryptoKey,
            encrypted,
        )
        return new Uint8Array(decrypted)
    }
}

export async function newAESGCMEncrypter(key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-GCM" },
        false,
        ["encrypt"],
    )
    return async function (data, aad = new Uint8Array(0), iv = null) {
        const nonce = iv || randomBytes(12)
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
            cryptoKey,
            data,
        )
        return new Uint8Array([...nonce, ...new Uint8Array(encrypted)])
    }
}

export async function newAESGCMDecrypter(key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-GCM" },
        false,
        ["decrypt"],
    )
    return async function (data, aad = new Uint8Array(0)) {
        const nonce = data.slice(0, 12)
        const encrypted = data.slice(12)
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
            cryptoKey,
            encrypted,
        )
        return new Uint8Array(decrypted)
    }
}

// TODO: add HPKE encryption/decryption functions
