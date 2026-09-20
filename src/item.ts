import canonicalize from "canonicalize";

import {
  BYTE_LENGTHS,
  KEY_DERIVATION_PROFILE,
  LIMITS,
  SIGNATURE_SCHEME,
  WRAPPING_ALGORITHM,
} from "./constants.js";
import { signSeedAndDerive } from "./derivation.js";
import { decodeBase64, decodeSeed, encodeBase32, encodeBase64 } from "./encoding.js";
import { ZkbytesError } from "./errors.js";
import {
  unwrapAesKey,
  validateX25519PublicKey,
  wrapAesKey,
  x25519PublicKeyFromPrivate,
} from "./hpke.js";
import { hasExactKeys, isRecord } from "./json.js";
import { decryptPayload, encryptPayload, randomBytes } from "./payload.js";
import {
  signEd25519,
  signingDescriptor,
  validateEd25519PublicKey,
  verifyEd25519Base64,
} from "./signatures.js";
import type {
  EncryptedKeyDescriptor,
  PrepareItemOptions,
  PreparedItem,
  SigningKeyDescriptor,
  StorageItem,
} from "./types.js";

const encoder = new TextEncoder();

export async function prepareItem(options: PrepareItemOptions): Promise<PreparedItem> {
  if (typeof options.plaintext !== "string") invalidArgument("Plaintext must be a string.");
  const seed = options.seed ?? encodeBase32(randomBytes(BYTE_LENGTHS.seed));
  decodeSeed(seed);
  const expiresAt = canonicalTimestamp(options.expiresAt);
  if (Date.parse(expiresAt) <= Date.now()) invalidArgument("Expiration must be in the future.");

  const keys = await signSeedAndDerive(seed, options.signer);
  const aesKey = randomBytes(BYTE_LENGTHS.aesKey);
  try {
    const { encryptedPayload } = await encryptPayload(options.plaintext, aesKey);
    if (encryptedPayload.length > LIMITS.encryptedPayloadCharacters) {
      invalidArgument("The encrypted payload exceeds the protocol limit.");
    }

    const recipientPublicKeys = [
      encodeBase64(keys.encryptionPublicKey),
      ...(options.recipientPublicKeys ?? []),
    ];
    requireUnique(recipientPublicKeys);
    if (recipientPublicKeys.length > LIMITS.encryptedKeys) {
      invalidArgument("Too many encrypted-key recipients were supplied.");
    }
    const encryptedKeys = await Promise.all(
      recipientPublicKeys.map(async (publicKey) => wrapAesKey(seed, publicKey, aesKey)),
    );

    const creator = signingDescriptor(keys.signingPublicKey);
    const managers = options.managers === undefined ? [creator] : [...options.managers];
    validateManagerList(managers);
    const item: StorageItem = {
      version: 1,
      encryptedPayload,
      itemSignature: { value: "" },
      seed,
      keyDerivationProfile: KEY_DERIVATION_PROFILE,
      encryptedKeys,
      expiresAt,
      creator,
      managers,
    };
    item.itemSignature.value = signEd25519(createItemSigningMessage(item), keys.signingPrivateKey);
    return { item, keys };
  } catch (error) {
    keys.signingPrivateKey.fill(0);
    keys.encryptionPrivateKey.fill(0);
    throw error;
  } finally {
    aesKey.fill(0);
  }
}

export function createItemSigningMessage(item: StorageItem): Uint8Array {
  const canonical = canonicalize({
    purpose: "zkbytes.item.v1",
    item: {
      version: item.version,
      encryptedPayload: item.encryptedPayload,
      seed: item.seed,
      keyDerivationProfile: item.keyDerivationProfile,
      encryptedKeys: item.encryptedKeys,
      expiresAt: item.expiresAt,
      creator: item.creator,
      managers: item.managers,
    },
  });
  if (canonical === undefined) throw new ZkbytesError("INVALID_ITEM", "The item cannot be canonicalized.");
  return encoder.encode(canonical);
}

export function validateStorageItem(value: unknown): StorageItem {
  if (!isRecord(value) || !hasExactKeys(value, [
    "version", "encryptedPayload", "itemSignature", "seed", "keyDerivationProfile",
    "encryptedKeys", "expiresAt", "creator", "managers",
  ])) invalidItem();
  if (
    value.version !== 1 ||
    typeof value.encryptedPayload !== "string" ||
    value.encryptedPayload.length < 1 ||
    value.encryptedPayload.length > LIMITS.encryptedPayloadCharacters ||
    typeof value.seed !== "string" ||
    value.keyDerivationProfile !== KEY_DERIVATION_PROFILE ||
    typeof value.expiresAt !== "string" ||
    !Array.isArray(value.encryptedKeys) ||
    !Array.isArray(value.managers)
  ) invalidItem();
  decodeSeed(value.seed);
  canonicalTimestamp(value.expiresAt);
  if (value.encryptedKeys.length < 1 || value.encryptedKeys.length > LIMITS.encryptedKeys) invalidItem();
  if (value.managers.length > LIMITS.managers) invalidItem();

  const encryptedKeys = value.encryptedKeys.map(validateEncryptedKey);
  const creator = validateSigningDescriptor(value.creator);
  const managers = value.managers.map(validateSigningDescriptor);
  requireUnique(encryptedKeys.map((entry) => entry.publicKey));
  requireUnique(managers.map((manager) => manager.publicKey));

  if (!isRecord(value.itemSignature) || !hasExactKeys(value.itemSignature, ["value"]) ||
      typeof value.itemSignature.value !== "string") invalidItem();
  decodeBase64(value.itemSignature.value, BYTE_LENGTHS.ed25519Signature);

  const item: StorageItem = {
    version: 1,
    encryptedPayload: value.encryptedPayload,
    itemSignature: { value: value.itemSignature.value },
    seed: value.seed,
    keyDerivationProfile: KEY_DERIVATION_PROFILE,
    encryptedKeys,
    expiresAt: value.expiresAt,
    creator,
    managers,
  };
  if (!verifyEd25519Base64(createItemSigningMessage(item), creator.publicKey, item.itemSignature.value)) {
    throw new ZkbytesError("INVALID_SIGNATURE", "The item signature is invalid.");
  }
  return item;
}

export async function decryptStorageItem(
  itemInput: unknown,
  expectedCreator: SigningKeyDescriptor,
  recipientPrivateKey: Uint8Array,
): Promise<{ plaintext: string; item: StorageItem; expired: boolean }> {
  const item = validateStorageItem(itemInput);
  const trustedCreator = validateSigningDescriptor(expectedCreator);
  if (
    item.creator.publicKey !== trustedCreator.publicKey ||
    item.creator.signatureScheme !== trustedCreator.signatureScheme
  ) {
    throw new ZkbytesError("INVALID_SIGNATURE", "The item creator does not match the trusted creator.");
  }
  const publicKey = encodeBase64(await x25519PublicKeyFromPrivate(recipientPrivateKey));
  const entry = item.encryptedKeys.find((candidate) => candidate.publicKey === publicKey);
  if (!entry) throw new ZkbytesError("DECRYPTION_FAILED", "No encrypted key exists for this recipient.");
  const aesKey = await unwrapAesKey(item.seed, entry, recipientPrivateKey);
  try {
    return {
      plaintext: await decryptPayload(item.encryptedPayload, aesKey),
      item,
      expired: Date.parse(item.expiresAt) <= Date.now(),
    };
  } finally {
    aesKey.fill(0);
  }
}

export function canonicalTimestamp(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) invalidArgument("The timestamp is invalid.");
  const canonical = new Date(Math.floor(date.getTime() / 1_000) * 1_000)
    .toISOString()
    .replace(".000Z", "Z");
  if (typeof value === "string" && canonical !== value) {
    invalidArgument("The timestamp must be canonical UTC with second precision.");
  }
  return canonical;
}

function validateEncryptedKey(value: unknown): EncryptedKeyDescriptor {
  if (!isRecord(value) || !hasExactKeys(value, ["publicKey", "wrappingAlgorithm", "encryptedKey"]) ||
      typeof value.publicKey !== "string" || value.wrappingAlgorithm !== WRAPPING_ALGORITHM ||
      typeof value.encryptedKey !== "string") invalidItem();
  validateX25519PublicKey(decodeBase64(value.publicKey, BYTE_LENGTHS.x25519PublicKey));
  decodeBase64(value.encryptedKey, BYTE_LENGTHS.hpkeEnvelope);
  return {
    publicKey: value.publicKey,
    wrappingAlgorithm: WRAPPING_ALGORITHM,
    encryptedKey: value.encryptedKey,
  };
}

export function validateSigningDescriptor(value: unknown): SigningKeyDescriptor {
  if (!isRecord(value) || !hasExactKeys(value, ["publicKey", "signatureScheme"]) ||
      typeof value.publicKey !== "string" || value.signatureScheme !== SIGNATURE_SCHEME) invalidItem();
  validateEd25519PublicKey(decodeBase64(value.publicKey, BYTE_LENGTHS.ed25519PublicKey));
  return { publicKey: value.publicKey, signatureScheme: SIGNATURE_SCHEME };
}

function validateManagerList(managers: readonly SigningKeyDescriptor[]): void {
  if (managers.length > LIMITS.managers) invalidArgument("Too many managers were supplied.");
  managers.forEach(validateSigningDescriptor);
  requireUnique(managers.map((manager) => manager.publicKey));
}

function requireUnique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) invalidArgument("Public key entries must be unique.");
}

function invalidItem(): never {
  throw new ZkbytesError("INVALID_ITEM", "The storage item is invalid.");
}

function invalidArgument(message: string): never {
  throw new ZkbytesError("INVALID_ARGUMENT", message);
}
