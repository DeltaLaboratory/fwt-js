import { type Result } from "../types"

export function decodeVLQ(buffer: Uint8Array): Result<{
    value: bigint
    bytesRead: number
}> {
    if (buffer.length === 0) {
        return {
            ok: false,
            error: new Error("empty buffer"),
        }
    }

    let bytesRead = 0
    let c = buffer[bytesRead]
    bytesRead++
    // The first 7 bits of the value.
    let value = BigInt(c & 0x7f)

    // Continue if the continuation bit (0x80) is set
    while (c & 0x80) {
        if (bytesRead >= buffer.length) {
            return {
                ok: false,
                error: new Error("incomplete VLQ data"),
            }
        }
        // Git's VLQ encoding adds 1 before shifting.
        value = value + 1n
        c = buffer[bytesRead]
        bytesRead++
        // Shift the previous value 7 bits to the left and add the next 7 bits.
        value = (value << 7n) + BigInt(c & 0x7f)

        // Check if value exceeds uint64 max
        if (value > 18446744073709551615n) {
            return {
                ok: false,
                error: new Error("value exceeds uint64 maximum"),
            }
        }
    }

    return { ok: true, value: { value, bytesRead } }
}

export function encodeVLQ(
    buffer: Uint8Array,
    inputValue: bigint,
): Result<number> {
    if (buffer.length === 0) {
        return {
            ok: false,
            error: new Error("insufficient buffer"),
        }
    }

    if (inputValue > 18446744073709551615n) {
        return {
            ok: false,
            error: new Error("value exceeds uint64 maximum"),
        }
    }

    // Use Uint8Array instead of regular array for better performance
    const tmp = new Uint8Array(10) // Max 10 bytes needed for uint64 VLQ
    let pos = tmp.length - 1 // start at the end

    // Encode the least significant 7 bits.
    tmp[pos] = Number(inputValue & 0x7fn)
    let value = inputValue >> 7n

    // Continue encoding while there are more bits.
    while (value > 0n) {
        pos--
        if (pos < 0) {
            return {
                ok: false,
                error: new Error("value too large to encode"),
            }
        }
        // Git's VLQ encoding decrements the remaining value before encoding the next 7 bits.
        value = value - 1n
        tmp[pos] = 0x80 | Number(value & 0x7fn)
        value = value >> 7n
    }

    const numBytes = tmp.length - pos
    if (buffer.length < numBytes) {
        return {
            ok: false,
            error: new Error("insufficient buffer"),
        }
    }

    // Copy the encoded bytes into the supplied buffer.
    buffer.set(tmp.subarray(pos, tmp.length), 0)

    return {
        ok: true,
        value: numBytes,
    }
}
