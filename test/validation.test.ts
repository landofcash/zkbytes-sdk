import { describe, expect, it } from "vitest";

import {
  decodeBase64,
  decodeSeed,
  parseStrictJson,
  validateEd25519PublicKey,
  validateX25519PublicKey,
} from "../src/index.js";

describe("strict validation", () => {
  it("rejects noncanonical seeds", () => {
    for (const value of [
      "AAISEM2EKVTHPCEZVK54ZXPO74",
      "aaisem2ekvthpcezvk54zxpo7z",
      "aaisem2ekvthpcezvk54zxpo74=",
      " aaisem2ekvthpcezvk54zxpo74",
    ]) expect(() => decodeSeed(value)).toThrow();
  });

  it("rejects noncanonical Base64 and malformed curve points", () => {
    expect(() => decodeBase64("AQ", 1)).toThrow();
    expect(() => validateX25519PublicKey(new Uint8Array(32).fill(0xff))).toThrow();
    expect(() => validateEd25519PublicKey(new Uint8Array(32))).toThrow();
  });

  it("rejects duplicate JSON properties and malformed Unicode", () => {
    expect(() => parseStrictJson('{"value":1,"value":2}')).toThrow(/Duplicate/);
    expect(() => parseStrictJson('{"value":"\\ud800"}')).toThrow(/Unicode/);
  });
});
