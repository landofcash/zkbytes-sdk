import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { ed25519 } from "@noble/curves/ed25519.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { KEY_DERIVATION_PROFILE } from "./constants.js";
import type { ItemKeyPair, MasterMessageSigner } from "./types.js";
import {
  createSeedSigningMessage,
  normalizeAndVerifyMasterSignature,
  normalizeMasterSignature,
} from "./master-signature.js";

const encoder = new TextEncoder();
const DERIVATION_SALT = encoder.encode("zkbytes.item-keys.v1");
const SIGNING_INFO = encoder.encode(`${KEY_DERIVATION_PROFILE}:signing:ed25519`);
const ENCRYPTION_INFO = encoder.encode(`${KEY_DERIVATION_PROFILE}:encryption:x25519`);

const hpkeSuite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

export async function signSeedAndDerive(
  seed: string,
  signer: MasterMessageSigner,
): Promise<ItemKeyPair> {
  const message = createSeedSigningMessage(seed);
  const supplied = await signer.signMessage(message);
  const signature = normalizeAndVerifyMasterSignature(supplied, message, signer.address);
  try {
    return await deriveItemKeys(signature);
  } finally {
    signature.fill(0);
  }
}

export async function deriveItemKeys(signatureBytes: Uint8Array): Promise<ItemKeyPair> {
  const signature = normalizeMasterSignature(signatureBytes);
  const rootPrk = extract(sha256, signature, DERIVATION_SALT);
  const signingPrivateKey = expand(sha256, rootPrk, SIGNING_INFO, 32);
  const encryptionIkm = expand(sha256, rootPrk, ENCRYPTION_INFO, 32);
  try {
    const encryptionPair = await hpkeSuite.kem.deriveKeyPair(encryptionIkm);
    return {
      signingPrivateKey,
      signingPublicKey: ed25519.getPublicKey(signingPrivateKey),
      encryptionPrivateKey: new Uint8Array(
        await hpkeSuite.kem.serializePrivateKey(encryptionPair.privateKey),
      ),
      encryptionPublicKey: new Uint8Array(
        await hpkeSuite.kem.serializePublicKey(encryptionPair.publicKey),
      ),
    };
  } finally {
    signature.fill(0);
    rootPrk.fill(0);
    encryptionIkm.fill(0);
  }
}

export function clearItemKeys(keys: ItemKeyPair): void {
  keys.signingPrivateKey.fill(0);
  keys.encryptionPrivateKey.fill(0);
}
