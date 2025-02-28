export function base64URLEncode(buffer: Uint8Array): string {
    const base64 = btoa(
        Array.from(buffer)
            .map((b) => String.fromCharCode(b))
            .join(""),
    )
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function base64URLDecode(value: string): Uint8Array {
    const padded = value.padEnd(
        value.length + ((4 - (value.length % 4)) % 4),
        "=",
    )
    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/")
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }

    return bytes
}
