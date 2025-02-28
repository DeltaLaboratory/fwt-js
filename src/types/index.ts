// Signature Type

export enum SignatureType {
    Ed25519 = 0,
    Ed448 = 1,
    HMACSha256 = 2,
    HMACSha512 = 3,
    Blake2b256 = 4,
    Blake2b512 = 5,
    Blake3 = 6,
}

// Errors

export const InvalidKeyError = new Error("invalid key")
export const InvalidInputError = new Error("invalid input data")
export const AuthenticationFailError = new Error("invalid authentication data")
export const InvalidSignatureError = new Error("invalid signature data")

// Type Definitions

export type Result<T> = { ok: true; value: T } | { ok: false; error: Error }

export type SignerFunc = (data: Uint8Array) => Promise<Result<Uint8Array>>
export type SignerFactory = () => Promise<Result<[SignatureType, SignerFunc]>>

export type VerifierFunc = (
    data: Uint8Array,
    signature: Uint8Array,
) => Promise<Result<undefined>>
export type VerifierFactory = () => Promise<
    Result<[SignatureType, VerifierFunc]>
>

export type EncryptorFunc = (data: Uint8Array) => Promise<Result<Uint8Array>>
export type EncryptorFactory = () => Promise<Result<EncryptorFunc>>

export type DecryptorFunc = (data: Uint8Array) => Promise<Result<Uint8Array>>
export type DecryptorFactory = () => Promise<Result<DecryptorFunc>>
