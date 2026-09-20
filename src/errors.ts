export type ZkbytesErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_ENCODING"
  | "INVALID_ITEM"
  | "INVALID_SIGNATURE"
  | "INVALID_MASTER_SIGNATURE"
  | "UNSUPPORTED_PROFILE"
  | "ENCRYPTION_FAILED"
  | "DECRYPTION_FAILED"
  | "NETWORK_ERROR"
  | "INVALID_RESPONSE"
  | "OBJECT_NOT_FOUND"
  | "OBJECT_UNAVAILABLE"
  | "INVALID_REQUEST"
  | "INVALID_ITEM_SIGNATURE"
  | "RETENTION_NOT_ALLOWED"
  | "INVALID_MANAGER_PROOF"
  | "OBJECT_CONFLICT"
  | "PAYLOAD_TOO_LARGE"
  | "RATE_LIMITED"
  | "SERVICE_UNAVAILABLE";

export class ZkbytesError extends Error {
  public constructor(
    public readonly code: ZkbytesErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ZkbytesError";
  }
}

export class ZkbytesApiError extends ZkbytesError {
  public constructor(
    code: ZkbytesErrorCode,
    message: string,
    public readonly status: number,
    public readonly retryAfterSeconds?: number,
  ) {
    super(code, message);
    this.name = "ZkbytesApiError";
  }
}

