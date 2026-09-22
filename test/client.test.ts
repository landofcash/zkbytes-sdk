import { beforeAll, describe, expect, it, vi } from "vitest";

import {
  ZkbytesApiError,
  ZkbytesClient,
  decodeBase64,
  prepareItem,
  verifyEd25519,
  type PreparedItem,
} from "../src/index.js";

const seed = "aaisem2ekvthpcezvk54zxpo74";
const apiOrigin = "https://api.zkbytes.test";
const downloadOrigin = "https://files.zkbytes.test";
let prepared: PreparedItem;

beforeAll(async () => {
  prepared = await prepareItem({
    plaintext: "client flow",
    expiresAt: "2030-01-01T00:00:00Z",
    seed,
    signer: {
      address: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
      async signMessage() {
        return decodeBase64(
          "4D2KMp9y3XolhxKKFigvuOqlQDFrHSeYFFrL3YdoLORspXrcIgdyS72aEn8UaersRfyc0FlBQxkB28n63sdR1hw=",
        );
      },
    },
  });
});

describe("zkbytes HTTP client", () => {
  it("preserves the global receiver for default browser fetch during recovery", async () => {
    const browserFetch = vi.fn(function (this: unknown) {
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      return Promise.resolve(jsonResponse({ seed, state: "pending" }, 202));
    });
    vi.stubGlobal("fetch", browserFetch);
    try {
      const client = new ZkbytesClient({ apiOrigin, downloadOrigin });
      await expect(client.recoverUpload(seed, prepared.item.creator)).resolves.toEqual({
        outcome: "pending",
        status: { seed, state: "pending" },
      });
      expect(browserFetch).toHaveBeenCalledExactlyOnceWith(
        `${apiOrigin}/v1/objects/${seed}/status`, { method: "GET" },
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("supports a custom fetch when global fetch is unavailable", async () => {
    vi.stubGlobal("fetch", undefined);
    try {
      const fetchMock = vi.fn(async () => jsonResponse({ seed, state: "pending" }, 202));
      await expect(createClient(fetchMock).getStatus(seed)).resolves.toEqual({ seed, state: "pending" });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(() => new ZkbytesClient({ apiOrigin, downloadOrigin })).toThrow(
        "A Fetch API implementation is required.",
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("uploads once and validates every completed-response binding", async () => {
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      const requestBody = String(init?.body);
      expect(JSON.parse(requestBody)).toEqual(prepared.item);
      expect(requestBody).not.toContain("client flow");
      expect(requestBody).not.toContain(
        "4D2KMp9y3XolhxKKFigvuOqlQDFrHSeYFFrL3YdoLORspXrcIgdyS72aEn8UaersRfyc0FlBQxkB28n63sdR1hw=",
      );
      expect(requestBody).not.toContain(Buffer.from(prepared.keys.signingPrivateKey).toString("base64"));
      expect(requestBody).not.toContain(Buffer.from(prepared.keys.encryptionPrivateKey).toString("base64"));
      return jsonResponse({
        version: 1,
        seed,
        downloadUrl: `${downloadOrigin}/${seed}`,
        itemSignature: prepared.item.itemSignature,
        createdAt: "2026-09-21T12:37:03.075Z",
        expiresAt: prepared.item.expiresAt,
      }, 201);
    });
    const client = createClient(fetchMock);

    await expect(client.upload(prepared.item)).resolves.toMatchObject({ seed });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("recovers active uploads from status followed by a direct verified download", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/status")) {
        return jsonResponse({
          seed,
          state: "active",
          createdAt: "2026-09-21T12:37:03.075Z",
          expiresAt: prepared.item.expiresAt,
        });
      }
      return jsonResponse(prepared.item);
    });
    const client = createClient(fetchMock);

    await expect(client.recoverUpload(seed, prepared.item.creator)).resolves.toMatchObject({
      outcome: "active",
      item: { seed },
    });
    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      `${apiOrigin}/v1/objects/${seed}/status`,
      `${downloadOrigin}/${seed}`,
    ]);
  });

  it("treats only authoritative OBJECT_NOT_FOUND as permission to prepare anew", async () => {
    const client = createClient(vi.fn(async () => jsonResponse({
      error: { code: "OBJECT_NOT_FOUND", message: "No item is reserved at this seed." },
    }, 404)));

    await expect(client.recoverUpload(seed, prepared.item.creator)).resolves.toEqual({
      outcome: "not-found",
    });
  });

  it.each(["2026-02-30T12:00:00.075Z", "2026-09-21T12:37:03+00:00", "invalid"])(
    "rejects invalid server timestamps: %s", async (createdAt) => {
      const client = createClient(vi.fn(async () => jsonResponse({
        seed, state: "active", createdAt, expiresAt: prepared.item.expiresAt,
      })));
      await expect(client.getStatus(seed)).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    },
  );

  it("validates and signs the exact deletion challenge before execution", async () => {
    const issuedAt = new Date(Date.now() - 1_000).toISOString();
    const expiresAt = new Date(Date.now() + 300_000).toISOString();
    const challengeId = "f164d41e-bae0-4188-97ad-29b7b9778bfe";
    const message = [
      "zkbytes management v1",
      `Audience: ${apiOrigin}`,
      `Seed: ${seed}`,
      "Manager index: 0",
      "Action: delete",
      `Challenge: ${challengeId}`,
      `Issued: ${issuedAt}`,
      `Expires: ${expiresAt}`,
    ].join("\n");
    let calls = 0;
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      calls++;
      if (calls === 1) {
        expect(JSON.parse(String(init?.body))).toEqual({
          version: 1,
          managerIndex: 0,
          action: "delete",
          parameters: {},
        });
        return jsonResponse({
          version: 1,
          challengeId,
          seed,
          managerIndex: 0,
          action: "delete",
          parameters: {},
          signatureScheme: "zkbytes-ed25519-v1",
          messageEncoding: "utf-8",
          message,
          issuedAt,
          expiresAt,
        }, 201);
      }
      const action = JSON.parse(String(init?.body)) as { signature: string };
      expect(verifyEd25519(
        new TextEncoder().encode(message),
        prepared.keys.signingPublicKey,
        decodeBase64(action.signature),
      )).toBe(true);
      return jsonResponse({
        version: 1,
        seed,
        state: "deleted",
        deletedBy: { publicKey: prepared.item.creator.publicKey },
        deletedAt: new Date().toISOString(),
        physicalDeletion: "pending",
      }, 202);
    });
    const client = createClient(fetchMock);

    await expect(client.delete(seed, 0, prepared.keys.signingPrivateKey)).resolves.toMatchObject({
      state: "deleted",
      deletedBy: { publicKey: prepared.item.creator.publicKey },
    });
  });

  it("preserves safe API errors and retry timing", async () => {
    const client = createClient(vi.fn(async () => jsonResponse(
      { error: { code: "RATE_LIMITED", message: "Too many requests." } },
      429,
      { "Retry-After": "60" },
    )));

    await expect(client.getStatus(seed)).rejects.toMatchObject<ZkbytesApiError>({
      code: "RATE_LIMITED",
      status: 429,
      retryAfterSeconds: 60,
    });
  });
});

function createClient(fetchMock: ReturnType<typeof vi.fn>): ZkbytesClient {
  return new ZkbytesClient({
    apiOrigin,
    downloadOrigin,
    fetch: fetchMock as typeof fetch,
  });
}

function jsonResponse(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
