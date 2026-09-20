import canonicalize from "canonicalize";
import * as IndependentHpke from "hpke";
import { describe, expect, it } from "vitest";

import {
  KEY_DERIVATION_PROFILE,
  WRAPPING_ALGORITHM,
  canonicalTimestamp,
  createItemSigningMessage,
  createSeedSigningMessage,
  decodeBase64,
  decryptStorageItem,
  deriveItemKeys,
  encodeBase32,
  encodeBase64,
  normalizeAndVerifyMasterSignature,
  normalizeMasterSignature,
  prepareItem,
  randomBytes,
  unwrapAesKey,
  validateStorageItem,
  wrapAesKey,
  x25519PublicKeyFromPrivate,
  type MasterMessageSigner,
} from "../src/index.js";

const seed = "aaisem2ekvthpcezvk54zxpo74";
const fixtureSignature =
  "4D2KMp9y3XolhxKKFigvuOqlQDFrHSeYFFrL3YdoLORspXrcIgdyS72aEn8UaersRfyc0FlBQxkB28n63sdR1hw=";
const fixtureAddress = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
const fixtureSigningPublicKey = "AFsUI2tEGFBNVqAYxog6Pxg0JEzfSXtc1rgkkGztjkA=";
const fixtureEncryptionPublicKey = "/+2NcGg4bgNM7wV2HJCMJbJ/qwvIDG0lD0x3XAoxBxw=";

const signer: MasterMessageSigner = {
  address: fixtureAddress,
  async signMessage(message) {
    expect(message).toBe(createSeedSigningMessage(seed));
    return decodeBase64(fixtureSignature);
  },
};

describe("fixed cryptographic profile", () => {
  it("matches the public wallet-signature and dual-key derivation fixture", async () => {
    const signature = normalizeAndVerifyMasterSignature(
      decodeBase64(fixtureSignature),
      createSeedSigningMessage(seed),
      fixtureAddress,
    );
    const keys = await deriveItemKeys(signature);

    expect(encodeBase64(keys.signingPublicKey)).toBe(fixtureSigningPublicKey);
    expect(encodeBase64(keys.encryptionPublicKey)).toBe(fixtureEncryptionPublicKey);
  });

  it("accepts provider-independent signature bytes and validates canonical signatures", () => {
    const message = createSeedSigningMessage(seed);
    const providerSignature = decodeBase64(fixtureSignature);
    providerSignature[64] = 1;
    expect(normalizeAndVerifyMasterSignature(providerSignature, message, fixtureAddress)[64]).toBe(28);

    const nonCanonical = decodeBase64(fixtureSignature);
    nonCanonical.fill(0xff, 32, 64);
    expect(() => normalizeMasterSignature(nonCanonical)).toThrow(/canonical/i);
  });

  it("normalizes Date inputs to protocol second precision", () => {
    expect(canonicalTimestamp(new Date("2030-01-01T00:00:00.987Z")))
      .toBe("2030-01-01T00:00:00Z");
    expect(() => canonicalTimestamp("2030-01-01T00:00:00.987Z")).toThrow(/canonical/i);
  });

  it("encodes the fixed seed bytes canonically", () => {
    expect(encodeBase32(Uint8Array.from([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]))).toBe(seed);
  });

  it("prepares, signs, verifies and decrypts an uploader item", async () => {
    const prepared = await prepareItem({
      plaintext: "secret message",
      expiresAt: "2030-01-01T00:00:00Z",
      signer,
      seed,
    });

    expect(prepared.item.creator.publicKey).toBe(fixtureSigningPublicKey);
    expect(prepared.item.managers).toEqual([prepared.item.creator]);
    expect(prepared.item.encryptedKeys[0]?.publicKey).toBe(fixtureEncryptionPublicKey);
    expect(decodeBase64(prepared.item.encryptedKeys[0]!.encryptedKey)).toHaveLength(80);
    expect(validateStorageItem(prepared.item)).toEqual(prepared.item);
    await expect(
      decryptStorageItem(prepared.item, prepared.item.creator, prepared.keys.encryptionPrivateKey),
    ).resolves.toMatchObject({ plaintext: "secret message", expired: false });
  });

  it("preserves an explicit empty manager list and supports an additional recipient", async () => {
    const recipientPrivateKey = randomBytes(32);
    const recipientPublicKey = encodeBase64(await x25519PublicKeyFromPrivate(recipientPrivateKey));
    const prepared = await prepareItem({
      plaintext: "shared secret",
      expiresAt: "2030-01-01T00:00:00Z",
      signer,
      seed,
      managers: [],
      recipientPublicKeys: [recipientPublicKey],
    });

    expect(prepared.item.managers).toEqual([]);
    await expect(
      decryptStorageItem(prepared.item, prepared.item.creator, recipientPrivateKey),
    ).resolves.toMatchObject({ plaintext: "shared secret" });
  });

  it("rejects mutations and an untrusted replacement creator", async () => {
    const prepared = await prepareItem({
      plaintext: "authentic",
      expiresAt: "2030-01-01T00:00:00Z",
      signer,
      seed,
    });
    const tampered = structuredClone(prepared.item);
    tampered.encryptedPayload += "x";
    expect(() => validateStorageItem(tampered)).toThrow(/signature/i);

    const other = structuredClone(prepared.item.creator);
    other.publicKey = encodeBase64(new Uint8Array(32).fill(7));
    await expect(
      decryptStorageItem(prepared.item, other, prepared.keys.encryptionPrivateKey),
    ).rejects.toThrow();
  });

  it("opens hpke-js envelopes with the independent implementation and vice versa", async () => {
    const keys = await deriveItemKeys(decodeBase64(fixtureSignature));
    const aesKey = randomBytes(32);
    const publicKey = encodeBase64(keys.encryptionPublicKey);
    const entry = await wrapAesKey(seed, publicKey, aesKey);
    const aad = wrappingAad(publicKey);
    const info = new TextEncoder().encode("zkbytes.hpke.key-wrap.v1");
    const independent = new IndependentHpke.CipherSuite(
      IndependentHpke.KEM_DHKEM_X25519_HKDF_SHA256,
      IndependentHpke.KDF_HKDF_SHA256,
      IndependentHpke.AEAD_AES_256_GCM,
    );
    const independentPrivate = await independent.DeserializePrivateKey(keys.encryptionPrivateKey);
    const envelope = decodeBase64(entry.encryptedKey);
    await expect(independent.Open(
      independentPrivate,
      envelope.subarray(0, 32),
      envelope.subarray(32),
      { info, aad },
    )).resolves.toEqual(aesKey);

    const independentPublic = await independent.DeserializePublicKey(keys.encryptionPublicKey);
    const sealed = await independent.Seal(independentPublic, aesKey, { info, aad });
    const reverseEntry = {
      publicKey,
      wrappingAlgorithm: WRAPPING_ALGORITHM,
      encryptedKey: encodeBase64(concat(sealed.encapsulatedSecret, sealed.ciphertext)),
    } as const;
    await expect(unwrapAesKey(seed, reverseEntry, keys.encryptionPrivateKey)).resolves.toEqual(aesKey);
  });

  it("uses the same RFC 8785 item signing input as the service", async () => {
    const prepared = await prepareItem({
      plaintext: "unicode: café 👋",
      expiresAt: "2030-01-01T00:00:00Z",
      signer,
      seed,
    });
    const expected = canonicalize({
      purpose: "zkbytes.item.v1",
      item: {
        version: prepared.item.version,
        encryptedPayload: prepared.item.encryptedPayload,
        seed: prepared.item.seed,
        keyDerivationProfile: prepared.item.keyDerivationProfile,
        encryptedKeys: prepared.item.encryptedKeys,
        expiresAt: prepared.item.expiresAt,
        creator: prepared.item.creator,
        managers: prepared.item.managers,
      },
    });
    expect(new TextDecoder().decode(createItemSigningMessage(prepared.item))).toBe(expected);
  });
});

function wrappingAad(publicKey: string): Uint8Array {
  return new TextEncoder().encode(canonicalize({
    version: 1,
    seed,
    keyDerivationProfile: KEY_DERIVATION_PROFILE,
    recipientPublicKey: publicKey,
    recipientKeyType: "x25519",
    wrappingAlgorithm: WRAPPING_ALGORITHM,
  })!);
}

function concat(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((length, value) => length + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}
