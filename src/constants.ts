export const KEY_DERIVATION_PROFILE =
  "zkbytes-wallet-eip191-hkdfsha256-ed25519-x25519-hpke-v1" as const;
export const WRAPPING_ALGORITHM =
  "zkbytes-hpke-x25519-hkdfsha256-aes256gcm-v1" as const;
export const SIGNATURE_SCHEME = "zkbytes-ed25519-v1" as const;

export const LIMITS = {
  encryptedPayloadCharacters: 15_728_640,
  encryptedKeys: 32,
  managers: 16,
} as const;

export const BYTE_LENGTHS = {
  seed: 16,
  aesKey: 32,
  aesIv: 12,
  ed25519PublicKey: 32,
  ed25519PrivateKey: 32,
  ed25519Signature: 64,
  x25519PublicKey: 32,
  x25519PrivateKey: 32,
  hpkeEncapsulation: 32,
  hpkeCiphertext: 48,
  hpkeEnvelope: 80,
  masterSignature: 65,
} as const;

