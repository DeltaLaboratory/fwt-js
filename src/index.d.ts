declare module "fwt-js" {
    export const defaultCtx: string

    export enum SignatureType {
        SignatureTypeEd25519 = 0,
        SignatureTypeEd448 = 1,
        SignatureTypeHMACSha256 = 2,
        SignatureTypeHMACSha512 = 3,
        SignatureTypeBlake2b256 = 4,
        SignatureTypeBlake2b512 = 5,
        SignatureTypeBlake3 = 6,
    }

    export class Signer {
        constructor(
            signer: SignerFunc,
            encryptor: EncryptorFunc | null,
            signatureType: SignatureType,
        )

        sign(data: any): Promise<string>
    }

    export class Verifier {
        constructor(
            verifier: VerifierFunc,
            decrypter: DecrypterFunc | null,
            signatureType: SignatureType,
        )

        verify(token: string): Promise<void>
        verifyAndUnmarshal<T>(token: string): Promise<T>
    }

    type SignerFunc = (data: Uint8Array) => Promise<Uint8Array>
    type VerifierFunc = (data: Uint8Array, sig: Uint8Array) => Promise<void>

    export function newEd25519Signer(key: Uint8Array): Promise<SignerFunc>
    export function newEd25519Verifier(key: Uint8Array): Promise<VerifierFunc>

    export function newEd448Signer(
        key: Uint8Array,
        context?: string,
    ): Promise<SignerFunc>
    export function newEd448Verifier(
        key: Uint8Array,
        context?: string,
    ): VerifierFunc

    export function newHMACSha256Signer(key: Uint8Array): Promise<SignerFunc>
    export function newHMACSha256Verifier(
        key: Uint8Array,
    ): Promise<VerifierFunc>

    export function newHMACSha512Signer(key: Uint8Array): Promise<SignerFunc>
    export function newHMACSha512Verifier(
        key: Uint8Array,
    ): Promise<VerifierFunc>

    export function newBlake2b256Signer(key: Uint8Array): Promise<SignerFunc>
    export function newBlake2b256Verifier(
        key: Uint8Array,
    ): Promise<VerifierFunc>

    export function newBlake2b512Signer(key: Uint8Array): Promise<SignerFunc>
    export function newBlake2b512Verifier(
        key: Uint8Array,
    ): Promise<VerifierFunc>

    export function newBlake3Signer(key: Uint8Array): Promise<SignerFunc>
    export function newBlake3Verifier(key: Uint8Array): Promise<VerifierFunc>

    type EncryptorFunc = (data: Uint8Array) => Promise<Uint8Array>
    type DecrypterFunc = (data: Uint8Array) => Promise<Uint8Array>

    export function newXChaCha20PolyEncryptor(
        key: Uint8Array,
    ): Promise<EncryptorFunc>
    export function newXChaCha20PolyDecrypter(
        key: Uint8Array,
    ): Promise<DecrypterFunc>

    export function newAESECBEncryptor(key: Uint8Array): Promise<EncryptorFunc>
    export function newAESECBDecrypter(key: Uint8Array): Promise<DecrypterFunc>

    export function newAESCBCEncryptor(key: Uint8Array): Promise<EncryptorFunc>
    export function newAESCBCDecrypter(key: Uint8Array): Promise<DecrypterFunc>

    export function newAESCTREncryptor(key: Uint8Array): Promise<EncryptorFunc>
    export function newAESCTRDecrypter(key: Uint8Array): Promise<DecrypterFunc>

    export function newAESGCMEncryptor(key: Uint8Array): Promise<EncryptorFunc>
    export function newAESGCMDecrypter(key: Uint8Array): Promise<DecrypterFunc>
}
