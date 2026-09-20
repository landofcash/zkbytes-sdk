import type {
  KEY_DERIVATION_PROFILE,
  SIGNATURE_SCHEME,
  WRAPPING_ALGORITHM,
} from "./constants.js";

export interface SigningKeyDescriptor {
  publicKey: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

export interface EncryptedKeyDescriptor {
  publicKey: string;
  wrappingAlgorithm: typeof WRAPPING_ALGORITHM;
  encryptedKey: string;
}

export interface StorageItem {
  version: 1;
  encryptedPayload: string;
  itemSignature: { value: string };
  seed: string;
  keyDerivationProfile: typeof KEY_DERIVATION_PROFILE;
  encryptedKeys: EncryptedKeyDescriptor[];
  expiresAt: string;
  creator: SigningKeyDescriptor;
  managers: SigningKeyDescriptor[];
}

export interface ItemKeyPair {
  signingPrivateKey: Uint8Array;
  signingPublicKey: Uint8Array;
  encryptionPrivateKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
}

export interface MasterMessageSigner {
  readonly address: string;
  signMessage(message: string): Promise<string | Uint8Array>;
}

export interface PrepareItemOptions {
  plaintext: string;
  expiresAt: string | Date;
  signer: MasterMessageSigner;
  seed?: string;
  recipientPublicKeys?: readonly string[];
  managers?: readonly SigningKeyDescriptor[];
}

export interface PreparedItem {
  item: StorageItem;
  keys: ItemKeyPair;
}

export interface UploadCompleted {
  version: 1;
  seed: string;
  downloadUrl: string;
  itemSignature: { value: string };
  createdAt: string;
  expiresAt: string;
}

export interface UploadPending {
  seed: string;
  state: "pending";
}

export type ObjectStatus =
  | UploadPending
  | { seed: string; state: "active"; createdAt: string; expiresAt: string }
  | { seed: string; state: "deleted"; deletedBy: { publicKey: string }; deletedAt: string }
  | { seed: string; state: "expired" };

export interface DeletionChallenge {
  version: 1;
  challengeId: string;
  seed: string;
  managerIndex: number;
  action: "delete";
  parameters: Record<string, never>;
  signatureScheme: typeof SIGNATURE_SCHEME;
  messageEncoding: "utf-8";
  message: string;
  issuedAt: string;
  expiresAt: string;
}

export interface DeletionAccepted {
  version: 1;
  seed: string;
  state: "deleted";
  deletedBy: { publicKey: string };
  deletedAt: string;
  physicalDeletion: "pending";
}

export interface ZkbytesReference {
  version: 1;
  service: "zkbytes";
  apiOrigin: string;
  downloadOrigin: string;
  seed: string;
  expiresAt: string;
  expectedCreator: SigningKeyDescriptor;
}

export type UploadRecovery =
  | { outcome: "not-found" }
  | { outcome: "pending"; status: UploadPending }
  | { outcome: "active"; status: Extract<ObjectStatus, { state: "active" }>; item: StorageItem }
  | { outcome: "deleted"; status: Extract<ObjectStatus, { state: "deleted" }> }
  | { outcome: "expired"; status: Extract<ObjectStatus, { state: "expired" }> };
