import { ed25519 } from "@noble/curves/ed25519.js";

import { SIGNATURE_SCHEME } from "./constants.js";
import { decodeSeed, encodeBase64 } from "./encoding.js";
import { ZkbytesApiError, ZkbytesError, type ZkbytesErrorCode } from "./errors.js";
import { canonicalTimestamp, validateSigningDescriptor, validateStorageItem } from "./item.js";
import { hasExactKeys, isRecord, parseStrictJson } from "./json.js";
import { signEd25519, signingDescriptor } from "./signatures.js";
import type {
  DeletionAccepted,
  DeletionChallenge,
  ObjectStatus,
  SigningKeyDescriptor,
  StorageItem,
  UploadCompleted,
  UploadPending,
  UploadRecovery,
  ZkbytesReference,
} from "./types.js";

export interface ZkbytesClientOptions {
  apiOrigin: string;
  downloadOrigin: string;
  fetch?: typeof fetch;
}

export class ZkbytesClient {
  public readonly apiOrigin: string;
  public readonly downloadOrigin: string;
  private readonly fetchImplementation: typeof fetch;

  public constructor(options: ZkbytesClientOptions) {
    this.apiOrigin = requireOrigin(options.apiOrigin, "apiOrigin");
    this.downloadOrigin = requireOrigin(options.downloadOrigin, "downloadOrigin");
    // Browser fetch requires the global receiver when invoked as a client method.
    this.fetchImplementation = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetchImplementation) {
      throw new ZkbytesError("INVALID_ARGUMENT", "A Fetch API implementation is required.");
    }
  }

  public downloadUrl(seed: string): string {
    decodeSeed(seed);
    return `${this.downloadOrigin}/${seed}`;
  }

  public statusUrl(seed: string): string {
    decodeSeed(seed);
    return `${this.apiOrigin}/v1/objects/${seed}/status`;
  }

  public createReference(item: StorageItem): ZkbytesReference {
    const validated = validateStorageItem(item);
    return {
      version: 1,
      service: "zkbytes",
      apiOrigin: this.apiOrigin,
      downloadOrigin: this.downloadOrigin,
      seed: validated.seed,
      expiresAt: validated.expiresAt,
      expectedCreator: validated.creator,
    };
  }

  public async upload(itemInput: unknown): Promise<UploadCompleted | UploadPending> {
    const item = validateStorageItem(itemInput);
    const response = await this.request(`${this.apiOrigin}/v1/objects`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(item),
    });
    const body = await parseResponse(response);
    if (response.status === 202) {
      if (!isRecord(body) || !hasExactKeys(body, ["seed", "state"]) ||
          body.seed !== item.seed || body.state !== "pending") invalidResponse();
      return { seed: item.seed, state: "pending" };
    }
    if (response.status !== 200 && response.status !== 201) await throwApiError(response, body);
    const completed = parseUploadCompleted(body);
    if (
      completed.seed !== item.seed ||
      completed.downloadUrl !== this.downloadUrl(item.seed) ||
      completed.itemSignature.value !== item.itemSignature.value ||
      completed.expiresAt !== item.expiresAt
    ) invalidResponse();
    return completed;
  }

  public async getStatus(seed: string): Promise<ObjectStatus> {
    decodeSeed(seed);
    const response = await this.request(this.statusUrl(seed), { method: "GET" });
    const body = await parseResponse(response);
    if (!response.ok) await throwApiError(response, body);
    return parseStatus(body, seed, response.status);
  }

  public async download(seed: string): Promise<StorageItem> {
    decodeSeed(seed);
    const response = await this.request(this.downloadUrl(seed), { method: "GET" });
    if (response.status !== 200) {
      throw new ZkbytesError("NETWORK_ERROR", "The encrypted item could not be downloaded.");
    }
    const item = validateStorageItem(parseStrictJson(new Uint8Array(await response.arrayBuffer())));
    if (item.seed !== seed) {
      throw new ZkbytesError("INVALID_ITEM", "The downloaded seed does not match the requested filename.");
    }
    return item;
  }

  public async downloadAndVerify(
    seed: string,
    expectedCreator: SigningKeyDescriptor,
  ): Promise<StorageItem> {
    const trustedCreator = validateSigningDescriptor(expectedCreator);
    const item = await this.download(seed);
    if (
      item.creator.publicKey !== trustedCreator.publicKey ||
      item.creator.signatureScheme !== trustedCreator.signatureScheme
    ) {
      throw new ZkbytesError("INVALID_SIGNATURE", "The item creator does not match the trusted creator.");
    }
    return item;
  }

  public async recoverUpload(
    seed: string,
    expectedCreator: SigningKeyDescriptor,
  ): Promise<UploadRecovery> {
    let status: ObjectStatus;
    try {
      status = await this.getStatus(seed);
    } catch (error) {
      if (error instanceof ZkbytesApiError && error.code === "OBJECT_NOT_FOUND") {
        return { outcome: "not-found" };
      }
      throw error;
    }
    if (status.state === "pending") return { outcome: "pending", status };
    if (status.state === "deleted") return { outcome: "deleted", status };
    if (status.state === "expired") return { outcome: "expired", status };
    return {
      outcome: "active",
      status,
      item: await this.downloadAndVerify(seed, expectedCreator),
    };
  }

  public async delete(
    seed: string,
    managerIndex: number,
    managerPrivateKey: Uint8Array,
  ): Promise<DeletionAccepted> {
    decodeSeed(seed);
    if (!Number.isInteger(managerIndex) || managerIndex < 0 || managerIndex > 255) {
      throw new ZkbytesError("INVALID_ARGUMENT", "The manager index is invalid.");
    }
    if (managerPrivateKey.length !== 32) {
      throw new ZkbytesError("INVALID_ARGUMENT", "The manager private key must contain 32 bytes.");
    }
    const manager = signingDescriptor(ed25519.getPublicKey(managerPrivateKey));
    const challengeResponse = await this.request(
      `${this.apiOrigin}/v1/objects/${seed}/challenges`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: 1, managerIndex, action: "delete", parameters: {} }),
      },
    );
    const challengeBody = await parseResponse(challengeResponse);
    if (!challengeResponse.ok) await throwApiError(challengeResponse, challengeBody);
    const challenge = parseDeletionChallenge(challengeBody);
    validateDeletionChallenge(challenge, this.apiOrigin, seed, managerIndex);
    const signature = signEd25519(new TextEncoder().encode(challenge.message), managerPrivateKey);

    const actionResponse = await this.request(`${this.apiOrigin}/v1/objects/${seed}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: 1, challengeId: challenge.challengeId, signature }),
    });
    const actionBody = await parseResponse(actionResponse);
    if (actionResponse.status !== 202) await throwApiError(actionResponse, actionBody);
    const accepted = parseDeletionAccepted(actionBody, seed);
    if (accepted.deletedBy.publicKey !== manager.publicKey) invalidResponse();
    return accepted;
  }

  private async request(input: string, init: RequestInit): Promise<Response> {
    try {
      return await this.fetchImplementation(input, init);
    } catch (error) {
      throw new ZkbytesError("NETWORK_ERROR", "The zkbytes request failed.", { cause: error });
    }
  }
}

function validateDeletionChallenge(
  challenge: DeletionChallenge,
  audience: string,
  seed: string,
  managerIndex: number,
): void {
  if (challenge.seed !== seed || challenge.managerIndex !== managerIndex) invalidResponse();
  const expected = [
    "zkbytes management v1",
    `Audience: ${audience}`,
    `Seed: ${seed}`,
    `Manager index: ${managerIndex}`,
    "Action: delete",
    `Challenge: ${challenge.challengeId}`,
    `Issued: ${challenge.issuedAt}`,
    `Expires: ${challenge.expiresAt}`,
  ].join("\n");
  if (challenge.message !== expected || Date.parse(challenge.expiresAt) <= Date.now()) {
    throw new ZkbytesError("INVALID_RESPONSE", "The deletion challenge is invalid or expired.");
  }
}

function parseUploadCompleted(value: unknown): UploadCompleted {
  if (!isRecord(value) || !hasExactKeys(value, [
    "version", "seed", "downloadUrl", "itemSignature", "createdAt", "expiresAt",
  ]) || value.version !== 1 || typeof value.seed !== "string" ||
      typeof value.downloadUrl !== "string" || typeof value.createdAt !== "string" ||
      typeof value.expiresAt !== "string" || !isRecord(value.itemSignature) ||
      !hasExactKeys(value.itemSignature, ["value"]) || typeof value.itemSignature.value !== "string") {
    invalidResponse();
  }
  decodeSeed(value.seed);
  canonicalTimestamp(value.createdAt);
  canonicalTimestamp(value.expiresAt);
  return value as unknown as UploadCompleted;
}

function parseStatus(value: unknown, seed: string, statusCode: number): ObjectStatus {
  if (!isRecord(value) || value.seed !== seed || typeof value.state !== "string") invalidResponse();
  if (value.state === "pending" && statusCode === 202 && hasExactKeys(value, ["seed", "state"])) {
    return { seed, state: "pending" };
  }
  if (value.state === "active" && hasExactKeys(value, ["seed", "state", "createdAt", "expiresAt"]) &&
      typeof value.createdAt === "string" && typeof value.expiresAt === "string") {
    canonicalTimestamp(value.createdAt);
    canonicalTimestamp(value.expiresAt);
    return { seed, state: "active", createdAt: value.createdAt, expiresAt: value.expiresAt };
  }
  if (value.state === "expired" && hasExactKeys(value, ["seed", "state"])) {
    return { seed, state: "expired" };
  }
  if (value.state === "deleted" && hasExactKeys(value, ["seed", "state", "deletedBy", "deletedAt"]) &&
      isRecord(value.deletedBy) && hasExactKeys(value.deletedBy, ["publicKey"]) &&
      typeof value.deletedBy.publicKey === "string" && typeof value.deletedAt === "string") {
    validateSigningDescriptor({ publicKey: value.deletedBy.publicKey, signatureScheme: SIGNATURE_SCHEME });
    canonicalTimestamp(value.deletedAt);
    return { seed, state: "deleted", deletedBy: { publicKey: value.deletedBy.publicKey }, deletedAt: value.deletedAt };
  }
  return invalidResponse();
}

function parseDeletionChallenge(value: unknown): DeletionChallenge {
  if (!isRecord(value) || !hasExactKeys(value, [
    "version", "challengeId", "seed", "managerIndex", "action", "parameters",
    "signatureScheme", "messageEncoding", "message", "issuedAt", "expiresAt",
  ]) || value.version !== 1 || typeof value.challengeId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value.challengeId) ||
      typeof value.seed !== "string" || !Number.isInteger(value.managerIndex) ||
      value.action !== "delete" || !isRecord(value.parameters) || Object.keys(value.parameters).length !== 0 ||
      value.signatureScheme !== SIGNATURE_SCHEME || value.messageEncoding !== "utf-8" ||
      typeof value.message !== "string" || typeof value.issuedAt !== "string" ||
      typeof value.expiresAt !== "string") invalidResponse();
  decodeSeed(value.seed);
  canonicalTimestamp(value.issuedAt);
  canonicalTimestamp(value.expiresAt);
  return value as unknown as DeletionChallenge;
}

function parseDeletionAccepted(value: unknown, seed: string): DeletionAccepted {
  if (!isRecord(value) || !hasExactKeys(value, [
    "version", "seed", "state", "deletedBy", "deletedAt", "physicalDeletion",
  ]) || value.version !== 1 || value.seed !== seed || value.state !== "deleted" ||
      value.physicalDeletion !== "pending" || typeof value.deletedAt !== "string" ||
      !isRecord(value.deletedBy) || !hasExactKeys(value.deletedBy, ["publicKey"]) ||
      typeof value.deletedBy.publicKey !== "string") invalidResponse();
  validateSigningDescriptor({ publicKey: value.deletedBy.publicKey, signatureScheme: SIGNATURE_SCHEME });
  canonicalTimestamp(value.deletedAt);
  return value as unknown as DeletionAccepted;
}

async function parseResponse(response: Response): Promise<unknown> {
  return parseStrictJson(new Uint8Array(await response.arrayBuffer()));
}

async function throwApiError(response: Response, value: unknown): Promise<never> {
  if (isRecord(value) && hasExactKeys(value, ["error"]) && isRecord(value.error) &&
      hasExactKeys(value.error, ["code", "message"]) && typeof value.error.code === "string" &&
      typeof value.error.message === "string") {
    if (!API_ERROR_CODES.has(value.error.code as ZkbytesErrorCode)) invalidResponse();
    const retryAfter = Number(response.headers.get("retry-after"));
    throw new ZkbytesApiError(
      value.error.code as ZkbytesErrorCode,
      value.error.message,
      response.status,
      Number.isInteger(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
    );
  }
  return invalidResponse();
}

const API_ERROR_CODES = new Set<ZkbytesErrorCode>([
  "OBJECT_NOT_FOUND",
  "OBJECT_UNAVAILABLE",
  "INVALID_REQUEST",
  "INVALID_ITEM_SIGNATURE",
  "RETENTION_NOT_ALLOWED",
  "INVALID_MANAGER_PROOF",
  "OBJECT_CONFLICT",
  "PAYLOAD_TOO_LARGE",
  "RATE_LIMITED",
  "SERVICE_UNAVAILABLE",
]);

function requireOrigin(value: string, name: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new ZkbytesError("INVALID_ARGUMENT", `${name} must be an HTTPS origin.`, { cause: error });
  }
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash ||
      url.username || url.password || value.endsWith("/")) {
    throw new ZkbytesError("INVALID_ARGUMENT", `${name} must be an HTTPS origin without a path.`);
  }
  return url.origin;
}

function invalidResponse(): never {
  throw new ZkbytesError("INVALID_RESPONSE", "The service returned an invalid response.");
}
