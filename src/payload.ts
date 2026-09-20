import { BYTE_LENGTHS } from "./constants.js";
import { decodeBase64, encodeBase64 } from "./encoding.js";
import { ZkbytesError } from "./errors.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export async function encryptPayload(
  plaintext: string,
  aesKey: Uint8Array = randomBytes(BYTE_LENGTHS.aesKey),
): Promise<{ encryptedPayload: string; aesKey: Uint8Array }> {
  if (aesKey.length !== BYTE_LENGTHS.aesKey) {
    throw new ZkbytesError("INVALID_ARGUMENT", "The AES key must contain 32 bytes.");
  }
  const iv = randomBytes(BYTE_LENGTHS.aesIv);
  try {
    const key = await crypto.subtle.importKey("raw", asArrayBuffer(aesKey), "AES-GCM", false, ["encrypt"]);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: asArrayBuffer(iv), tagLength: 128 },
        key,
        asArrayBuffer(encoder.encode(plaintext)),
      ),
    );
    return { encryptedPayload: `${encodeBase64(iv)}:${encodeBase64(ciphertext)}`, aesKey };
  } catch (error) {
    throw new ZkbytesError("ENCRYPTION_FAILED", "Payload encryption failed.", { cause: error });
  }
}

export async function decryptPayload(encryptedPayload: string, aesKey: Uint8Array): Promise<string> {
  if (aesKey.length !== BYTE_LENGTHS.aesKey) {
    throw new ZkbytesError("INVALID_ARGUMENT", "The AES key must contain 32 bytes.");
  }
  const parts = encryptedPayload.split(":");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new ZkbytesError("INVALID_ITEM", "The encrypted payload format is invalid.");
  }
  try {
    const iv = decodeBase64(parts[0], BYTE_LENGTHS.aesIv);
    const ciphertext = decodeBase64(parts[1]);
    if (ciphertext.length < 16) throw new Error("Missing authentication tag.");
    const key = await crypto.subtle.importKey("raw", asArrayBuffer(aesKey), "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asArrayBuffer(iv), tagLength: 128 },
      key,
      asArrayBuffer(ciphertext),
    );
    return decoder.decode(plaintext);
  } catch (error) {
    throw new ZkbytesError("DECRYPTION_FAILED", "Payload authentication or decryption failed.", { cause: error });
  }
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 1) {
    throw new ZkbytesError("INVALID_ARGUMENT", "Random byte length must be a positive integer.");
  }
  return crypto.getRandomValues(new Uint8Array(length));
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}
