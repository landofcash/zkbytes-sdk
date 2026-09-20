import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import canonicalize from "canonicalize";
import { x25519 } from "@noble/curves/ed25519.js";

import { BYTE_LENGTHS, KEY_DERIVATION_PROFILE, WRAPPING_ALGORITHM } from "./constants.js";
import { concatenate, decodeBase64, encodeBase64 } from "./encoding.js";
import { ZkbytesError } from "./errors.js";
import type { EncryptedKeyDescriptor } from "./types.js";

const encoder = new TextEncoder();
const HPKE_INFO = encoder.encode("zkbytes.hpke.key-wrap.v1");
const X25519_PRIME = (1n << 255n) - 19n;
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

export async function wrapAesKey(
  seed: string,
  recipientPublicKeyBase64: string,
  aesKey: Uint8Array,
): Promise<EncryptedKeyDescriptor> {
  if (aesKey.length !== BYTE_LENGTHS.aesKey) {
    throw new ZkbytesError("INVALID_ARGUMENT", "The AES key must contain 32 bytes.");
  }
  const recipientBytes = decodeBase64(recipientPublicKeyBase64, 32);
  validateX25519PublicKey(recipientBytes);
  const descriptor = {
    publicKey: recipientPublicKeyBase64,
    wrappingAlgorithm: WRAPPING_ALGORITHM,
  } as const;
  try {
    const recipientPublicKey = await suite.kem.deserializePublicKey(recipientBytes);
    const sender = await suite.createSenderContext({
      recipientPublicKey,
      info: HPKE_INFO,
    });
    const ciphertext = new Uint8Array(await sender.seal(aesKey, wrappingAad(seed, descriptor)));
    const envelope = concatenate(new Uint8Array(sender.enc), ciphertext);
    if (envelope.length !== BYTE_LENGTHS.hpkeEnvelope) throw new Error("Unexpected envelope length.");
    return { ...descriptor, encryptedKey: encodeBase64(envelope) };
  } catch (error) {
    throw new ZkbytesError("ENCRYPTION_FAILED", "AES-key wrapping failed.", { cause: error });
  }
}

export async function unwrapAesKey(
  seed: string,
  entry: EncryptedKeyDescriptor,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  if (recipientPrivateKey.length !== BYTE_LENGTHS.x25519PrivateKey) {
    throw new ZkbytesError("INVALID_ARGUMENT", "An X25519 private key must contain 32 bytes.");
  }
  if (entry.wrappingAlgorithm !== WRAPPING_ALGORITHM) {
    throw new ZkbytesError("UNSUPPORTED_PROFILE", "The key-wrapping profile is unsupported.");
  }
  const envelope = decodeBase64(entry.encryptedKey, BYTE_LENGTHS.hpkeEnvelope);
  const publicKey = decodeBase64(entry.publicKey, BYTE_LENGTHS.x25519PublicKey);
  validateX25519PublicKey(publicKey);
  try {
    const recipientKey = await suite.kem.deserializePrivateKey(recipientPrivateKey);
    const recipient = await suite.createRecipientContext({
      recipientKey,
      enc: envelope.subarray(0, BYTE_LENGTHS.hpkeEncapsulation),
      info: HPKE_INFO,
    });
    const plaintext = new Uint8Array(
      await recipient.open(
        envelope.subarray(BYTE_LENGTHS.hpkeEncapsulation),
        wrappingAad(seed, entry),
      ),
    );
    if (plaintext.length !== BYTE_LENGTHS.aesKey) throw new Error("Unexpected plaintext length.");
    return plaintext;
  } catch (error) {
    throw new ZkbytesError("DECRYPTION_FAILED", "AES-key authentication or unwrapping failed.", { cause: error });
  }
}

export async function x25519PublicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
  if (privateKey.length !== BYTE_LENGTHS.x25519PrivateKey) {
    throw new ZkbytesError("INVALID_ARGUMENT", "An X25519 private key must contain 32 bytes.");
  }
  try {
    return x25519.getPublicKey(privateKey);
  } catch (error) {
    throw new ZkbytesError("INVALID_ARGUMENT", "The X25519 private key is invalid.", { cause: error });
  }
}

export function validateX25519PublicKey(key: Uint8Array): void {
  if (key.length !== 32) {
    throw new ZkbytesError("INVALID_ENCODING", "An X25519 public key must contain 32 bytes.");
  }
  let coordinate = 0n;
  for (let index = key.length - 1; index >= 0; index--) {
    coordinate = (coordinate << 8n) | BigInt(key[index] ?? 0);
  }
  if (coordinate >= X25519_PRIME) {
    throw new ZkbytesError("INVALID_ENCODING", "The X25519 public key is not canonical.");
  }
}

function wrappingAad(
  seed: string,
  entry: Pick<EncryptedKeyDescriptor, "publicKey" | "wrappingAlgorithm">,
): Uint8Array {
  const value = canonicalize({
    version: 1,
    seed,
    keyDerivationProfile: KEY_DERIVATION_PROFILE,
    recipientPublicKey: entry.publicKey,
    recipientKeyType: "x25519",
    wrappingAlgorithm: entry.wrappingAlgorithm,
  });
  if (value === undefined) throw new ZkbytesError("INVALID_ITEM", "HPKE context cannot be canonicalized.");
  return encoder.encode(value);
}
