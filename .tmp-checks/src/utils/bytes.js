export function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }
    return result;
}
export function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
export function hexToBytes(hex) {
    const normalized = hex.trim().replace(/^0x/, '').toLowerCase();
    if (normalized.length === 0) {
        return new Uint8Array();
    }
    if (normalized.length % 2 !== 0 || /[^0-9a-f]/.test(normalized)) {
        throw new Error('Invalid hex string');
    }
    const result = new Uint8Array(normalized.length / 2);
    for (let index = 0; index < result.length; index += 1) {
        result[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
    }
    return result;
}
export function utf8ToBytes(value) {
    return new TextEncoder().encode(value);
}
export function bytesToBigInt(bytes) {
    let result = 0n;
    for (const byte of bytes) {
        result = (result << 8n) | BigInt(byte);
    }
    return result;
}
export function bigintToBytes(value, size) {
    if (value < 0n) {
        throw new Error('Negative bigint values are not supported');
    }
    const bytes = [];
    let remaining = value;
    while (remaining > 0n) {
        bytes.unshift(Number(remaining & 0xffn));
        remaining >>= 8n;
    }
    const raw = Uint8Array.from(bytes.length > 0 ? bytes : [0]);
    if (size === undefined) {
        return raw;
    }
    if (raw.length > size) {
        throw new Error('BigInt does not fit in requested size');
    }
    const result = new Uint8Array(size);
    result.set(raw, size - raw.length);
    return result;
}
export function equalBytes(left, right) {
    if (left.length !== right.length) {
        return false;
    }
    let delta = 0;
    for (let index = 0; index < left.length; index += 1) {
        delta |= left[index] ^ right[index];
    }
    return delta === 0;
}
export function xorBytes(arrays) {
    if (arrays.length === 0) {
        return new Uint8Array();
    }
    const size = arrays[0].length;
    const result = new Uint8Array(size);
    for (const array of arrays) {
        if (array.length !== size) {
            throw new Error('XOR inputs must have equal length');
        }
        for (let index = 0; index < size; index += 1) {
            result[index] ^= array[index];
        }
    }
    return result;
}
export function base64UrlEncode(bytes) {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}
export function numberToBytes(value, size) {
    if (!Number.isInteger(value) || value < 0) {
        throw new Error('Expected a non-negative integer');
    }
    const result = new Uint8Array(size);
    let remaining = value;
    for (let index = size - 1; index >= 0; index -= 1) {
        result[index] = remaining & 0xff;
        remaining >>>= 8;
    }
    if (remaining !== 0) {
        throw new Error('Integer does not fit in requested size');
    }
    return result;
}
