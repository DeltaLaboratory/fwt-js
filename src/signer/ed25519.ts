import { ed25519 } from "@noble/curves/ed25519"

import {
    InvalidInputError,
    InvalidKeyError,
    InvalidSignatureError,
    type Result,
    SignatureType,
    type SignerFactory,
    type SignerFunc,
    type VerifierFactory,
    type VerifierFunc,
} from "../types"

export async function newEd25519Signer(
    key: Uint8Array,
): Promise<SignerFactory> {
    return async (): Promise<Result<[SignatureType, SignerFunc]>> => {
        if (key.length != 32) {
            return {
                ok: false,
                error: InvalidKeyError,
            }
        }

        return {
            ok: true,
            value: [
                SignatureType.Ed25519,
                async (data: Uint8Array): Promise<Result<Uint8Array>> => {
                    try {
                        return {
                            ok: true,
                            value: ed25519.sign(data, key),
                        }
                    } catch (e) {
                        return {
                            ok: false,
                            error: new Error("failed to sign data", {
                                cause: e,
                            }),
                        }
                    }
                },
            ],
        }
    }
}

export async function newEd25519Verifier(
    key: Uint8Array,
): Promise<VerifierFactory> {
    return async (): Promise<Result<[SignatureType, VerifierFunc]>> => {
        if (key.length != 32) {
            return {
                ok: false,
                error: InvalidKeyError,
            }
        }

        return {
            ok: true,
            value: [
                SignatureType.Ed25519,
                async (data, signature): Promise<Result<undefined>> => {
                    if (signature.length != 64) {
                        return {
                            ok: false,
                            error: InvalidInputError,
                        }
                    }

                    try {
                        if (
                            ed25519.verify(signature, data, key, {
                                zip215: false,
                            })
                        ) {
                            return { ok: true, value: undefined }
                        } else {
                            return {
                                ok: false,
                                error: InvalidSignatureError,
                            }
                        }
                    } catch (e) {
                        return {
                            ok: false,
                            error: new Error("failed to verify data", {
                                cause: e,
                            }),
                        }
                    }
                },
            ],
        }
    }
}
