import { ZkbytesError } from "./errors.js";

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export function encodeBase32(bytes: Uint8Array): string {
  let accumulator = 0;
  let bits = 0;
  let output = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(accumulator >> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}

export function decodeSeed(seed: string): Uint8Array {
  if (!/^[a-z2-7]{25}[aeimquy4]$/u.test(seed)) {
    throw new ZkbytesError("INVALID_ENCODING", "The seed is not canonically encoded.");
  }
  let accumulator = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const character of seed) {
    accumulator = (accumulator << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  const decoded = Uint8Array.from(bytes);
  if (decoded.length !== 16 || bits !== 2 || accumulator !== 0 || encodeBase32(decoded) !== seed) {
    throw new ZkbytesError("INVALID_ENCODING", "The seed is not canonically encoded.");
  }
  return decoded;
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function decodeBase64(value: string, expectedLength?: number): Uint8Array {
  let binary: string;
  try {
    binary = atob(value);
  } catch (error) {
    throw new ZkbytesError("INVALID_ENCODING", "A binary value is not valid Base64.", { cause: error });
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (
    encodeBase64(bytes) !== value ||
    (expectedLength !== undefined && bytes.length !== expectedLength)
  ) {
    throw new ZkbytesError("INVALID_ENCODING", "A binary value is not canonically encoded.");
  }
  return bytes;
}

export function decodeHex(value: string): Uint8Array {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (normalized.length % 2 !== 0 || !/^[0-9a-f]*$/iu.test(normalized)) {
    throw new ZkbytesError("INVALID_ENCODING", "The hexadecimal value is invalid.");
  }
  return Uint8Array.from(normalized.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

export function encodeHex(bytes: Uint8Array, prefix = false): string {
  const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return prefix ? `0x${value}` : value;
}

export function concatenate(...arrays: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((length, array) => length + array.length, 0));
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

