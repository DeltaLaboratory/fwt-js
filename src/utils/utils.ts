export function getRandomValues(n: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(n))
}

export function constantComparison(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false
    }

    let result = 0
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i]
    }
    return result === 0
}
