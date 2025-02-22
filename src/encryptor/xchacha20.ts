import { xchacha20poly1305 } from "@noble/ciphers/chacha"

import {
    AuthenticationFailError,
    type DecrypterFactory,
    type DecrypterFunc,
    type EncryptorFactory,
    type EncryptorFunc,
    InvalidInputError,
    InvalidKeyError,
    type Result,
} from "../types"
import { getRandomValues } from "../utils/utils"

export async function newXChaCha20Poly1305Encrypter(
    key: Uint8Array,
): Promise<EncryptorFactory> {
    return async (): Promise<Result<EncryptorFunc>> => {
        if (key.length != 32) {
            return {
                ok: false,
                error: InvalidKeyError,
            }
        }

        return {
            ok: true,
            value: async (data: Uint8Array): Promise<Result<Uint8Array>> => {
                const nonce = getRandomValues(xchacha20poly1305.nonceLength)
                const aead = xchacha20poly1305(key, nonce)
                const encrypted = aead.encrypt(data)
                const concat = new Uint8Array(nonce.length + encrypted.length)
                concat.set(nonce)
                concat.set(encrypted, nonce.length)
                return {
                    ok: true,
                    value: concat,
                }
            },
        }
    }
}

export async function newXChaCha20Poly1305Decrypter(
    key: Uint8Array,
): Promise<DecrypterFactory> {
    return async (): Promise<Result<DecrypterFunc>> => {
        if (key.length != 32) {
            return {
                ok: false,
                error: InvalidKeyError,
            }
        }

        return {
            ok: true,
            value: async (data: Uint8Array): Promise<Result<Uint8Array>> => {
                if (data.length < xchacha20poly1305.nonceLength) {
                    return {
                        ok: false,
                        error: InvalidInputError,
                    }
                }

                const nonce = data.subarray(0, xchacha20poly1305.nonceLength)
                const ciphertext = data.subarray(xchacha20poly1305.nonceLength)

                const aead = xchacha20poly1305(key, nonce)
                try {
                    return {
                        ok: true,
                        value: aead.decrypt(ciphertext),
                    }
                } catch (e) {
                    return {
                        ok: false,
                        error: AuthenticationFailError,
                    }
                }
            },
        }
    }
}
