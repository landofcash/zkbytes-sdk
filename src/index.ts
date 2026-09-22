export {
  BYTE_LENGTHS,
  KEY_DERIVATION_PROFILE,
  LIMITS,
  SIGNATURE_SCHEME,
  WRAPPING_ALGORITHM,
} from "./constants.js";
export { ZkbytesClient, type ZkbytesClientOptions } from "./client.js";
export { clearItemKeys, deriveItemKeys, signSeedAndDerive } from "./derivation.js";
export { decodeBase64, decodeSeed, encodeBase32, encodeBase64 } from "./encoding.js";
export { ZkbytesApiError, ZkbytesError, type ZkbytesErrorCode } from "./errors.js";
export {
  unwrapAesKey, validateX25519PublicKey, wrapAesKey, x25519PublicKeyFromPrivate,
  sealSeed, openSealedSeed, SEALED_SEED_VERSION, SEALED_SEED_BYTES,
} from "./hpke.js";
export {
  canonicalTimestamp,
  createItemSigningMessage,
  decryptStorageItem,
  prepareItem,
  validateSigningDescriptor,
  validateStorageItem,
} from "./item.js";
export { parseStrictJson } from "./json.js";
export { decryptPayload, encryptPayload, randomBytes } from "./payload.js";
export {
  signEd25519,
  signingDescriptor,
  validateEd25519PublicKey,
  verifyEd25519,
  verifyEd25519Base64,
} from "./signatures.js";
export {
  createSeedSigningMessage,
  eip191Digest,
  normalizeAndVerifyMasterSignature,
  normalizeMasterSignature,
} from "./master-signature.js";
export type * from "./types.js";
