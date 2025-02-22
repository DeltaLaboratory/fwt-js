export function base64URLEncode(buffer: Uint8Array): string {
    return Buffer.from(buffer).toString("base64url").replace(/=+$/, "")
}

export function base64URLDecode(value: string): Uint8Array {
    const padded = value.padEnd(
        value.length + ((4 - (value.length % 4)) % 4),
        "=",
    )
    return new Uint8Array(Buffer.from(padded, "base64url"))
}
