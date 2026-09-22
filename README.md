# zkbytes SDK

TypeScript SDK for preparing, encrypting, signing, uploading, downloading, verifying,
decrypting, recovering, and deleting zkbytes objects. It works in modern browsers and
Node.js 22 or later and does not send plaintext or derived private keys to the service.

> This package implements the fixed zkbytes v1 cryptographic profile. Treat it as
> pre-release software until an external security review has been completed.

## Install

```sh
pnpm add @zkbytes/sdk
```

The package is ESM-only. Browser environments must provide Web Crypto and `fetch`;
Node.js 22 provides both globally.

## Prepare and upload

```ts
import {
  ZkbytesClient,
  clearItemKeys,
  prepareItem,
  type MasterMessageSigner,
} from "@zkbytes/sdk";

const signer: MasterMessageSigner = {
  address: selectedAccountAddress,
  async signMessage(message) {
    return await applicationWalletIntegration.signEip191Message(message);
  },
};

const prepared = await prepareItem({
  plaintext: "private content",
  expiresAt: new Date("2030-01-01T00:00:00Z"),
  signer,
});

const client = new ZkbytesClient({
  apiOrigin: "https://api.example.com",
  downloadOrigin: "https://cdn.example.com",
});

try {
  const upload = await client.upload(prepared.item);
  const reference = client.createReference(prepared.item);
  // Persist `reference` and handle `upload.state === "pending"` when returned.
} finally {
  clearItemKeys(prepared.keys);
}
```

`prepareItem` requests one canonical EIP-191 signature for the generated seed through the
application-supplied `MasterMessageSigner`. The SDK deliberately does not integrate a
specific browser, hardware, embedded, or custodial wallet. Account selection, user prompts,
transport, and provider-specific message encoding belong to the integrating application.
The callback may return a canonical 65-byte signature as a `Uint8Array` or hexadecimal text.
By default the creator is also the sole manager and the uploader receives the first
wrapped content key. Pass `managers: []` to make an object intentionally undeletable,
or provide `recipientPublicKeys` to wrap the content key for additional X25519 recipients.

## Download and decrypt

Never trust the creator descriptor supplied by a downloaded object. Keep the
`expectedCreator` from the reference created at upload time or obtain it through an
authenticated channel.

```ts
import { decryptStorageItem } from "@zkbytes/sdk";

const item = await client.downloadAndVerify(reference.seed, reference.expectedCreator);
const result = await decryptStorageItem(
  item,
  reference.expectedCreator,
  recipientEncryptionPrivateKey,
);

console.log(result.plaintext);
```

Validation is performed before decryption: strict JSON parsing, fixed profile and
algorithm identifiers, canonical encodings, Ed25519 subgroup checks, and the item
signature are all checked.

## Recover an uncertain upload

If the upload response was lost, do not immediately prepare a new object. Query the
authoritative status using the original seed and expected creator:

```ts
const recovery = await client.recoverUpload(reference.seed, reference.expectedCreator);

switch (recovery.outcome) {
  case "active":
    // recovery.item has been downloaded and verified against expectedCreator.
    break;
  case "pending":
    // Poll again later. Do not submit a replacement yet.
    break;
  case "not-found":
    // Only OBJECT_NOT_FOUND permits preparing a new candidate.
    break;
  case "deleted":
  case "expired":
    break;
}
```

Network failures, unavailable objects, and malformed responses are surfaced as errors;
they are not treated as proof that the object is absent.

## Delete

Deletion requires the private Ed25519 key corresponding to the selected manager index.
The SDK validates the complete, short-lived service challenge before signing it.

```ts
await client.delete(reference.seed, 0, managerSigningPrivateKey);
```

An accepted deletion is logical immediately. Physical storage deletion can remain
pending and cached CDN content can remain visible for up to the configured 60-second TTL.

## Errors

SDK failures throw `ZkbytesError`. Valid service errors throw `ZkbytesApiError`, which
also provides the HTTP `status` and optional `retryAfterSeconds`.

```ts
import { ZkbytesApiError } from "@zkbytes/sdk";

try {
  await client.getStatus(seed);
} catch (error) {
  if (error instanceof ZkbytesApiError && error.code === "RATE_LIMITED") {
    console.log(error.retryAfterSeconds);
  }
}
```

## Development

### Compact encrypted seeds (0.1.4)

`sealSeed(seed, recipientPublicKeyBase64)` encrypts the raw 16-byte seed directly
using HPKE X25519/HKDF-SHA256/AES-256-GCM. It returns 65 bytes:
version `3` (1 byte), encapsulation (32 bytes), ciphertext and tag (32 bytes).
`openSealedSeed(envelope, recipientPrivateKey)` authenticates and returns the
canonical seed. Both functions are asynchronous. No network requests are made.

The domain is `zkbytes.hpke.sealed-seed.v3`; AAD is the version byte followed by
the 32-byte recipient public key. This is separate from item-key wrapping.
The recipient key need not be carried in a link: opening derives it from the
selected private key. Envelopes do not authenticate the sender or pin a creator.
Unpadded Base64URL encoding yields 87 characters; URL formatting belongs to the app.

### Commands

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm browser:serve
```

The test suite includes the public deterministic key-derivation fixture, strict parser
and signature checks, client recovery behavior, and bidirectional HPKE interoperability
against an independent implementation.

With `browser:serve` running, open `/test/browser/` to execute the browser Web Crypto
round trip. The harness uses the public deterministic wallet fixture and does not require
a live wallet. A real wallet/device acceptance pass is still required before release.
