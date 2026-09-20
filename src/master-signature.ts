import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { BYTE_LENGTHS, KEY_DERIVATION_PROFILE } from "./constants.js";
import { concatenate, decodeHex, equalBytes } from "./encoding.js";
import { ZkbytesError } from "./errors.js";

const textEncoder = new TextEncoder();
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_ORDER = SECP256K1_ORDER >> 1n;

export function createSeedSigningMessage(seed: string): string {
  return [
    "zkbytes item key derivation v1",
    `Profile: ${KEY_DERIVATION_PROFILE}`,
    `Seed: ${seed}`,
  ].join("\n");
}

export function normalizeAndVerifyMasterSignature(
  value: string | Uint8Array,
  message: string,
  expectedAddress: string,
): Uint8Array {
  const normalized = normalizeMasterSignature(value);
  const digest = eip191Digest(textEncoder.encode(message));
  const recoveredSignature = concatenate(
    Uint8Array.of((normalized[64] ?? 27) - 27),
    normalized.subarray(0, 64),
  );
  let publicKey: Uint8Array;
  try {
    publicKey = secp256k1.Signature.fromBytes(recoveredSignature, "recovered")
      .recoverPublicKey(digest)
      .toBytes(false);
  } catch (error) {
    throw new ZkbytesError("INVALID_MASTER_SIGNATURE", "The wallet signature is invalid.", { cause: error });
  }
  const address = keccak_256(publicKey.subarray(1)).subarray(12);
  if (!equalBytes(address, decodeEthereumAddress(expectedAddress))) invalidMasterSignature();
  return normalized;
}

export function normalizeMasterSignature(value: string | Uint8Array): Uint8Array {
  const bytes = typeof value === "string" ? decodeHex(value) : new Uint8Array(value);
  if (bytes.length !== BYTE_LENGTHS.masterSignature) invalidMasterSignature();
  const normalized = new Uint8Array(bytes);
  const recovery = normalized[64];
  if (recovery === 0 || recovery === 1) normalized[64] = recovery + 27;
  if (normalized[64] !== 27 && normalized[64] !== 28) invalidMasterSignature();

  const r = readBigEndian(normalized.subarray(0, 32));
  const s = readBigEndian(normalized.subarray(32, 64));
  if (r <= 0n || r >= SECP256K1_ORDER || s <= 0n || s > SECP256K1_HALF_ORDER) {
    invalidMasterSignature();
  }

  return normalized;
}

export function eip191Digest(message: Uint8Array): Uint8Array {
  const prefix = textEncoder.encode(`\x19Ethereum Signed Message:\n${message.length}`);
  return keccak_256(concatenate(prefix, message));
}

function decodeEthereumAddress(value: string): Uint8Array {
  const bytes = decodeHex(value);
  if (bytes.length !== 20) {
    throw new ZkbytesError("INVALID_ARGUMENT", "The expected Ethereum address must contain 20 bytes.");
  }
  return bytes;
}

function readBigEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function invalidMasterSignature(): never {
  throw new ZkbytesError("INVALID_MASTER_SIGNATURE", "The wallet signature is not canonical.");
}
