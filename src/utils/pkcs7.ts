export function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
    const padder = blockSize - (data.length % blockSize)
    const padding = new Uint8Array(padder).fill(padder)
    return new Uint8Array([...data, ...padding])
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
    const padLength = data[data.length - 1]
    return data.slice(0, -padLength)
}
