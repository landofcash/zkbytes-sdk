import { describe, expect, it } from "vitest";
import * as IndependentHpke from "hpke";
import {
  sealSeed, openSealedSeed, SEALED_SEED_VERSION, SEALED_SEED_BYTES,
  decodeSeed, encodeBase32, encodeBase64, randomBytes, x25519PublicKeyFromPrivate,
} from "../src/index.js";

async function fixture() {
  const privateKey = randomBytes(32);
  const publicKey = await x25519PublicKeyFromPrivate(privateKey);
  const seed = encodeBase32(randomBytes(16));
  return { privateKey, publicKey, seed };
}

describe("direct HPKE seed encryption", () => {
  it("round trips a raw seed in 65 bytes with fresh encapsulation each time", async () => {
    const { privateKey, publicKey, seed } = await fixture();
    try {
      const envelope = await sealSeed(seed, encodeBase64(publicKey));
      expect(envelope).toHaveLength(SEALED_SEED_BYTES);
      expect(envelope[0]).toBe(SEALED_SEED_VERSION);
      expect(await openSealedSeed(envelope, privateKey)).toBe(seed);
      expect(await sealSeed(seed, encodeBase64(publicKey))).not.toEqual(envelope);
    } finally { privateKey.fill(0); }
  });

  it("rejects wrong keys, tampering, unsupported versions and invalid inputs", async () => {
    const { privateKey, publicKey, seed } = await fixture();
    try {
      const envelope = await sealSeed(seed, encodeBase64(publicKey));
      for (const offset of [0, 1, 32, 33, 48, 64]) {
        const changed = envelope.slice();
        changed[offset]! ^= 1;
        await expect(openSealedSeed(changed, privateKey)).rejects.toThrow();
      }
      await expect(openSealedSeed(envelope, randomBytes(32))).rejects.toThrow();
      await expect(openSealedSeed(envelope.subarray(1), privateKey)).rejects.toThrow();
      await expect(openSealedSeed(new Uint8Array(66), privateKey)).rejects.toThrow();
      await expect(openSealedSeed(envelope, new Uint8Array(31))).rejects.toThrow();
      await expect(sealSeed("invalid", encodeBase64(publicKey))).rejects.toThrow();
      await expect(sealSeed(seed, encodeBase64(new Uint8Array(32)))).rejects.toThrow();
    } finally { privateKey.fill(0); }
  });

  it("interoperates with independent HPKE and binds the profile, version and recipient", async () => {
    const { privateKey, publicKey, seed } = await fixture();
    try {
      const independent = new IndependentHpke.CipherSuite(
        IndependentHpke.KEM_DHKEM_X25519_HKDF_SHA256,
        IndependentHpke.KDF_HKDF_SHA256,
        IndependentHpke.AEAD_AES_256_GCM,
      );
      const info = new TextEncoder().encode("zkbytes.hpke.sealed-seed.v3");
      const aad = Uint8Array.of(SEALED_SEED_VERSION, ...publicKey);
      const envelope = await sealSeed(seed, encodeBase64(publicKey));
      const key = await independent.DeserializePrivateKey(privateKey);
      expect(await independent.Open(key, envelope.subarray(1, 33), envelope.subarray(33), { info, aad }))
        .toEqual(decodeSeed(seed));
      const pub = await independent.DeserializePublicKey(publicKey);
      for (const context of [
        { info, aad },
        { info: new TextEncoder().encode("zkbytes.hpke.key-wrap.v1"), aad },
        { info, aad: Uint8Array.of(2, ...publicKey) },
        { info, aad: Uint8Array.of(SEALED_SEED_VERSION, ...randomBytes(32)) },
      ]) {
        const sealed = await independent.Seal(pub, decodeSeed(seed), context);
        const packed = Uint8Array.of(SEALED_SEED_VERSION, ...sealed.encapsulatedSecret, ...sealed.ciphertext);
        if (context.info === info && context.aad === aad) {
          expect(await openSealedSeed(packed, privateKey)).toBe(seed);
        } else {
          await expect(openSealedSeed(packed, privateKey)).rejects.toThrow();
        }
      }
    } finally { privateKey.fill(0); }
  });
});
