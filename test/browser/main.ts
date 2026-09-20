import {
  clearItemKeys,
  createSeedSigningMessage,
  decryptStorageItem,
  prepareItem,
} from "../../src/index.ts";

const seed = "aaisem2ekvthpcezvk54zxpo74";
const address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
const signature =
  "0xe03d8a329f72dd7a2587128a16282fb8eaa540316b1d2798145acbdd87682ce46ca57adc2207724bbd9a127f1469eaec45fc9cd05941431901dbc9fadec751d61c";
const result = document.querySelector<HTMLParagraphElement>("#result");

if (!result) throw new Error("Browser-check result element is missing.");

try {
  const signer = {
    address,
    async signMessage(message: string) {
      if (message !== createSeedSigningMessage(seed)) throw new Error("Unexpected signing message.");
      return signature;
    },
  };
  const prepared = await prepareItem({
    plaintext: "browser round trip",
    expiresAt: "2030-01-01T00:00:00Z",
    signer,
    seed,
  });
  try {
    const decrypted = await decryptStorageItem(
      prepared.item,
      prepared.item.creator,
      prepared.keys.encryptionPrivateKey,
    );
    if (decrypted.plaintext !== "browser round trip") throw new Error("Plaintext mismatch.");
    result.dataset.status = "pass";
    result.textContent = "PASS: browser encryption, signing, verification, and decryption succeeded.";
  } finally {
    clearItemKeys(prepared.keys);
  }
} catch (error) {
  result.dataset.status = "fail";
  result.textContent = `FAIL: ${error instanceof Error ? error.message : String(error)}`;
  throw error;
}
