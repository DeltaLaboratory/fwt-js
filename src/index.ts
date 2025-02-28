import { decode, encode } from "cbor-x"

import {
    type DecryptorFactory,
    type DecryptorFunc,
    type EncryptorFactory,
    type EncryptorFunc,
    InvalidInputError,
    InvalidSignatureError,
    type Result,
    SignatureType,
    type SignerFactory,
    type SignerFunc,
    type VerifierFactory,
    type VerifierFunc,
} from "./types"
import { base64URLDecode, base64URLEncode } from "./utils/base64"
import { decodeVLQ, encodeVLQ } from "./utils/vlq"

export class Signer {
    private readonly signatureType: SignatureType
    private readonly signer: SignerFunc
    private readonly encryptor?: EncryptorFunc

    private constructor(
        signatureType: SignatureType,
        signer: SignerFunc,
        encryptor?: EncryptorFunc,
    ) {
        this.signatureType = signatureType
        this.signer = signer
        this.encryptor = encryptor
    }

    static async new(
        signer: SignerFactory,
        encryptor?: EncryptorFactory,
    ): Promise<Result<Signer>> {
        const signerRet = await signer()
        if (!signerRet.ok) {
            return {
                ok: false,
                error: new Error("failed to create signer", {
                    cause: signerRet.error,
                }),
            }
        }

        if (!encryptor) {
            return {
                ok: true,
                value: new Signer(
                    signerRet.value[0],
                    signerRet.value[1],
                    undefined,
                ),
            }
        }

        const encryptorRet = await encryptor()
        if (!encryptorRet.ok) {
            return {
                ok: false,
                error: new Error("failed to create encryptor", {
                    cause: encryptorRet.error,
                }),
            }
        }

        return {
            ok: true,
            value: new Signer(
                signerRet.value[0],
                signerRet.value[1],
                encryptorRet.value,
            ),
        }
    }

    async sign(data: unknown): Promise<Result<string>> {
        let encoded: Uint8Array
        try {
            encoded = new Uint8Array(encode(data))
        } catch (e) {
            return {
                ok: false,
                error: new Error("failed to marshal data", {
                    cause: e,
                }),
            }
        }

        const signature = await this.signer(encoded)
        if (!signature.ok) {
            return {
                ok: false,
                error: new Error("failed to sign data", {
                    cause: signature.error,
                }),
            }
        }

        const buffer = new Uint8Array(
            1 + 10 + encoded.length + signature.value.length,
        )
        buffer[0] = this.signatureType

        const vlqLength = encodeVLQ(buffer.subarray(1), BigInt(encoded.length))
        if (!vlqLength.ok) {
            return {
                ok: false,
                error: new Error("failed to write data length", {
                    cause: vlqLength.error,
                }),
            }
        }

        buffer.set(encoded, 1 + vlqLength.value)
        buffer.set(signature.value, 1 + vlqLength.value + encoded.length)

        if (this.encryptor) {
            const encrypted = await this.encryptor(
                buffer.slice(
                    0,
                    1 +
                        vlqLength.value +
                        encoded.length +
                        signature.value.length,
                ),
            )
            if (!encrypted.ok) {
                return {
                    ok: false,
                    error: new Error("failed to encrypt data", {
                        cause: encrypted.error,
                    }),
                }
            }

            return {
                ok: true,
                value: base64URLEncode(encrypted.value),
            }
        }

        return {
            ok: true,
            value: base64URLEncode(
                buffer.slice(
                    0,
                    1 +
                        vlqLength.value +
                        encoded.length +
                        signature.value.length,
                ),
            ),
        }
    }
}

export class Verifier {
    private readonly signatureType: SignatureType
    private readonly verifier: VerifierFunc
    private readonly decrypter?: DecryptorFunc

    private constructor(
        signatureType: SignatureType,
        verifier: VerifierFunc,
        decrypter?: DecryptorFunc,
    ) {
        this.signatureType = signatureType
        this.verifier = verifier
        this.decrypter = decrypter
    }

    static async new(
        verifier: VerifierFactory,
        decrypter?: DecryptorFactory,
    ): Promise<Result<Verifier>> {
        const verifierRet = await verifier()
        if (!verifierRet.ok) {
            return {
                ok: false,
                error: new Error("failed to create verifier", {
                    cause: verifierRet.error,
                }),
            }
        }

        if (!decrypter) {
            return {
                ok: true,
                value: new Verifier(
                    verifierRet.value[0],
                    verifierRet.value[1],
                    undefined,
                ),
            }
        }

        const decrypterRet = await decrypter()
        if (!decrypterRet.ok) {
            return {
                ok: false,
                error: new Error("failed to create decrypter", {
                    cause: decrypterRet.error,
                }),
            }
        }

        return {
            ok: true,
            value: new Verifier(
                verifierRet.value[0],
                verifierRet.value[1],
                decrypterRet.value,
            ),
        }
    }

    private async decodeToken(token: string): Promise<
        Result<{
            decoded: Uint8Array
            vlqLength: number
            dataBoundary: number
        }>
    > {
        let decoded: Uint8Array
        try {
            decoded = base64URLDecode(token)
        } catch (e) {
            return {
                ok: false,
                error: new Error("failed to decode token", {
                    cause: e,
                }),
            }
        }

        if (this.decrypter) {
            const decrypted = await this.decrypter(decoded)
            if (!decrypted.ok) {
                return {
                    ok: false,
                    error: new Error("failed to decrypt token", {
                        cause: decrypted.error,
                    }),
                }
            }

            decoded = decrypted.value
        }

        if (decoded.length < 3) {
            return {
                ok: false,
                error: InvalidInputError,
            }
        }

        if (decoded[0] != this.signatureType) {
            return {
                ok: false,
                error: InvalidInputError,
            }
        }

        const vlqLength = decodeVLQ(decoded.slice(1))
        if (!vlqLength.ok) {
            return {
                ok: false,
                error: InvalidInputError,
            }
        }

        const dataBoundary =
            1 +
            vlqLength.value.bytesRead +
            Number(BigInt.asUintN(64, vlqLength.value.value))
        if (decoded.length < dataBoundary) {
            return {
                ok: false,
                error: InvalidInputError,
            }
        }

        return {
            ok: true,
            value: {
                decoded: decoded,
                vlqLength: vlqLength.value.bytesRead,
                dataBoundary: dataBoundary,
            },
        }
    }

    async verify(token: string): Promise<Result<undefined>> {
        // noinspection DuplicatedCode
        const decoded = await this.decodeToken(token)
        if (!decoded.ok) {
            return {
                ok: false,
                error: new Error("failed to decode token", {
                    cause: decoded.error,
                }),
            }
        }

        const verify = await this.verifier(
            decoded.value.decoded.slice(
                1 + decoded.value.vlqLength,
                decoded.value.dataBoundary,
            ),
            decoded.value.decoded.slice(decoded.value.dataBoundary),
        )
        if (!verify.ok) {
            return {
                ok: false,
                error: InvalidSignatureError,
            }
        }

        return {
            ok: true,
            value: undefined,
        }
    }

    async verifyAndUnmarshal<T>(token: string): Promise<Result<T>> {
        // noinspection DuplicatedCode
        const decoded = await this.decodeToken(token)
        if (!decoded.ok) {
            return {
                ok: false,
                error: new Error("failed to decode token", {
                    cause: decoded.error,
                }),
            }
        }

        const verify = await this.verifier(
            decoded.value.decoded.slice(
                1 + decoded.value.vlqLength,
                decoded.value.dataBoundary,
            ),
            decoded.value.decoded.slice(decoded.value.dataBoundary),
        )
        if (!verify.ok) {
            return {
                ok: false,
                error: InvalidSignatureError,
            }
        }

        try {
            return {
                ok: true,
                value: decode(
                    decoded.value.decoded.slice(
                        1 + decoded.value.vlqLength,
                        decoded.value.dataBoundary,
                    ),
                ),
            }
        } catch (e) {
            return {
                ok: false,
                error: new Error("failed to decode token", {
                    cause: e,
                }),
            }
        }
    }
}
