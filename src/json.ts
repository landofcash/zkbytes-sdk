import { ZkbytesError } from "./errors.js";

const decoder = new TextDecoder("utf-8", { fatal: true });

export function parseStrictJson(input: Uint8Array | string): unknown {
  let source: string;
  try {
    source = typeof input === "string" ? input : decoder.decode(input);
    new DuplicateKeyScanner(source).scan();
    const value: unknown = JSON.parse(source);
    assertValidUnicode(value);
    return value;
  } catch (error) {
    if (error instanceof ZkbytesError) throw error;
    throw new ZkbytesError("INVALID_RESPONSE", "The response is not valid JSON.", { cause: error });
  }
}

class DuplicateKeyScanner {
  private index = 0;
  public constructor(private readonly source: string) {}

  public scan(): void {
    this.skipWhitespace();
    this.value();
    this.skipWhitespace();
    if (this.index !== this.source.length) this.invalid();
  }

  private value(): void {
    const character = this.source[this.index];
    if (character === "{") return this.object();
    if (character === "[") return this.array();
    if (character === '"') return void this.string();
    if (character === "t") return this.literal("true");
    if (character === "f") return this.literal("false");
    if (character === "n") return this.literal("null");
    this.number();
  }

  private object(): void {
    this.index++;
    this.skipWhitespace();
    const keys = new Set<string>();
    if (this.consume("}")) return;
    for (;;) {
      if (this.source[this.index] !== '"') this.invalid();
      const start = this.index;
      this.string();
      const key = JSON.parse(this.source.slice(start, this.index)) as string;
      if (keys.has(key)) throw new ZkbytesError("INVALID_RESPONSE", "Duplicate JSON properties are not allowed.");
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.invalid();
      this.skipWhitespace();
      this.value();
      this.skipWhitespace();
      if (this.consume("}")) return;
      if (!this.consume(",")) this.invalid();
      this.skipWhitespace();
    }
  }

  private array(): void {
    this.index++;
    this.skipWhitespace();
    if (this.consume("]")) return;
    for (;;) {
      this.value();
      this.skipWhitespace();
      if (this.consume("]")) return;
      if (!this.consume(",")) this.invalid();
      this.skipWhitespace();
    }
  }

  private string(): void {
    this.index++;
    for (;;) {
      const character = this.source[this.index++];
      if (character === undefined || character.charCodeAt(0) < 0x20) this.invalid();
      if (character === '"') return;
      if (character !== "\\") continue;
      const escape = this.source[this.index++];
      if (escape === "u") {
        if (!/^[0-9a-f]{4}$/iu.test(this.source.slice(this.index, this.index + 4))) this.invalid();
        this.index += 4;
      } else if (!escape || !'"\\/bfnrt'.includes(escape)) {
        this.invalid();
      }
    }
  }

  private number(): void {
    const match = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/uy;
    match.lastIndex = this.index;
    const result = match.exec(this.source);
    if (!result) this.invalid();
    this.index = match.lastIndex;
  }

  private literal(value: string): void {
    if (this.source.slice(this.index, this.index + value.length) !== value) this.invalid();
    this.index += value.length;
  }

  private consume(value: string): boolean {
    if (this.source[this.index] !== value) return false;
    this.index++;
    return true;
  }

  private skipWhitespace(): void {
    while (/[\u0009\u000a\u000d\u0020]/u.test(this.source[this.index] ?? "")) this.index++;
  }

  private invalid(): never {
    throw new ZkbytesError("INVALID_RESPONSE", "The response is not valid JSON.");
  }
}

function assertValidUnicode(value: unknown): void {
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index++) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(++index);
        if (!(next >= 0xdc00 && next <= 0xdfff)) invalidUnicode();
      } else if (unit >= 0xdc00 && unit <= 0xdfff) invalidUnicode();
    }
  } else if (Array.isArray(value)) {
    value.forEach(assertValidUnicode);
  } else if (isRecord(value)) {
    Object.entries(value).forEach(([key, child]) => {
      assertValidUnicode(key);
      assertValidUnicode(child);
    });
  }
}

function invalidUnicode(): never {
  throw new ZkbytesError("INVALID_RESPONSE", "The response contains malformed Unicode.");
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}
