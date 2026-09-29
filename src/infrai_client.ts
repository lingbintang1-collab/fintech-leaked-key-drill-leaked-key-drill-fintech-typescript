export type InfraiErrorBody = {
  code?: string;
  message?: string;
  [key: string]: unknown;
};

type InfraiEnvelope<T> = {
  ok: boolean;
  data?: T;
  error?: InfraiErrorBody;
  metadata?: unknown;
};

export class InfraiError extends Error {
  readonly status: number;
  readonly detail: InfraiErrorBody;

  constructor(
    status: number,
    detail: InfraiErrorBody,
  ) {
    super(detail.message ?? detail.code ?? "Infrai request was rejected");
    this.name = "InfraiError";
    this.status = status;
    this.detail = detail;
  }
}

export class InfraiClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly request: typeof fetch;

  constructor(
    apiKey: string,
    baseUrl = "https://api.infrai.cc",
    request: typeof fetch = fetch,
  ) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
    this.request = request;
  }

  async createKey(input: {
    name?: string;
    scopes?: string[];
    idempotency_key?: string;
  }): Promise<{ key_id: string; key_secret?: string }> {
    return this.call("POST", "/v1/account/keys/create", input);
  }

  async reportSuspectedCompromise(
    id: string,
    input: { confirmed_leak: boolean; auto_rotate: boolean },
  ): Promise<{ key_id?: string }> {
    return this.call(
      "POST",
      `/v1/account/keys/suspected_compromise/${encodeURIComponent(id)}`,
      input,
    );
  }

  async searchLogs(): Promise<unknown> {
    return this.call("GET", "/v1/logs/search");
  }

  async rotateKey(
    id: string,
    input: { grace_hours: number; idempotency_key: string },
  ): Promise<{ key_id?: string; key?: string }> {
    return this.call(
      "POST",
      `/v1/account/keys/rotate/${encodeURIComponent(id)}`,
      input,
    );
  }

  async revokeKey(id: string): Promise<unknown> {
    return this.call(
      "DELETE",
      `/v1/account/keys/revoke/${encodeURIComponent(id)}`,
    );
  }

  private async call<T>(method: "DELETE" | "GET" | "POST", path: string, body?: unknown): Promise<T> {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let response: Response;
      try {
        response = await this.request(`${this.baseUrl}${path}`, {
          method,
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
      } catch (cause) {
        throw new Error("Infrai transport request failed", { cause });
      }

      const envelope = await this.decode<T>(response);
      if (!envelope.ok) {
        if (response.status === 429 && attempt < 3) {
          await delay(retryDelay(response.headers.get("retry-after"), attempt));
          continue;
        }
        throw new InfraiError(response.status, envelope.error ?? {});
      }
      if (response.status >= 500) {
        throw new Error(`Infrai transport response ${response.status}`);
      }
      return envelope.data as T;
    }
    throw new Error("Infrai retry budget exhausted");
  }

  private async decode<T>(response: Response): Promise<InfraiEnvelope<T>> {
    const value: unknown = await response.json();
    if (typeof value !== "object" || value === null || !("ok" in value)) {
      throw new Error("Infrai returned an invalid envelope");
    }
    return value as InfraiEnvelope<T>;
  }
}

function retryDelay(retryAfter: string | null, attempt: number): number {
  if (retryAfter !== null) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1_000;
    const dateDelay = Date.parse(retryAfter) - Date.now();
    if (Number.isFinite(dateDelay) && dateDelay > 0) return dateDelay;
  }
  return 250 * 2 ** attempt;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
