import { ed25519 } from "@noble/curves/ed25519.js";

import { BYTE_LENGTHS, SIGNATURE_SCHEME } from "./constants.js";
import { decodeBase64, encodeBase64 } from "./encoding.js";
import { ZkbytesError } from "./errors.js";
import type { SigningKeyDescriptor } from "./types.js";

const ED25519_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

export function signingDescriptor(publicKey: Uint8Array): SigningKeyDescriptor {
  validateEd25519PublicKey(publicKey);
  return { publicKey: encodeBase64(publicKey), signatureScheme: SIGNATURE_SCHEME };
}

export function signEd25519(message: Uint8Array, privateKey: Uint8Array): string {
  if (privateKey.length !== BYTE_LENGTHS.ed25519PrivateKey) {
    throw new ZkbytesError("INVALID_ARGUMENT", "An Ed25519 private key must contain 32 bytes.");
  }
  return encodeBase64(ed25519.sign(message, privateKey));
}

export function verifyEd25519(
  message: Uint8Array,
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    validateEd25519PublicKey(publicKey);
    if (signature.length !== BYTE_LENGTHS.ed25519Signature) return false;
    validateEd25519Point(signature.subarray(0, 32));
    if (readLittleEndian(signature.subarray(32)) >= ED25519_ORDER) return false;
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

export function verifyEd25519Base64(
  message: Uint8Array,
  publicKey: string,
  signature: string,
): boolean {
  try {
    return verifyEd25519(
      message,
      decodeBase64(publicKey, BYTE_LENGTHS.ed25519PublicKey),
      decodeBase64(signature, BYTE_LENGTHS.ed25519Signature),
    );
  } catch {
    return false;
  }
}

export function validateEd25519PublicKey(publicKey: Uint8Array): void {
  if (publicKey.length !== BYTE_LENGTHS.ed25519PublicKey) {
    throw new ZkbytesError("INVALID_ENCODING", "An Ed25519 public key must contain 32 bytes.");
  }
  validateEd25519Point(publicKey);
}

function validateEd25519Point(bytes: Uint8Array): void {
  const point = ed25519.Point.fromBytes(bytes, false);
  if (point.equals(ed25519.Point.ZERO) || point.isSmallOrder() || !point.isTorsionFree()) {
    throw new ZkbytesError("INVALID_ENCODING", "An Ed25519 point is not in the prime-order subgroup.");
  }
}

function readLittleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

