export type FieldErrors = Record<string, string>;

/** A stable code for why a field is invalid, with the values its text needs. */
export interface FieldIssue {
  code: string;
  params?: Record<string, string>;
}

export type FieldCodes = Record<string, FieldIssue>;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** The server's English message per field. */
  readonly fields: FieldErrors;
  /** The code of every field message that has one. */
  readonly fieldCodes: FieldCodes;
  readonly retryAfterSeconds: number | undefined;

  constructor(init: {
    status: number;
    code: string;
    message: string;
    fields?: FieldErrors;
    fieldCodes?: FieldCodes;
    retryAfterSeconds?: number;
  }) {
    super(init.message);
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.fields = init.fields ?? {};
    this.fieldCodes = init.fieldCodes ?? {};
    this.retryAfterSeconds = init.retryAfterSeconds;
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export const CSRF_HEADER = 'X-TunnelDeck-Request';

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

interface RequestOptions {
  method?: Method;
  body?: unknown;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const response = await send(path, method, options.body);
  if (!response.ok) {
    throw await toApiError(response);
  }
  return (await readJson(response)) as T;
}

async function send(path: string, method: Method, body: unknown): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method !== 'GET') {
    headers[CSRF_HEADER] = '1';
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  try {
    return await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (cause) {
    throw new ApiError({
      status: 0,
      code: 'network',
      message: cause instanceof Error ? cause.message : 'network error',
    });
  }
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  return text === '' ? undefined : JSON.parse(text);
}

/** RFC 9457 problem details; `code`, `fields` and `fieldCodes` are TunnelDeck extension members. */
interface ProblemDetails {
  title?: string;
  detail?: string;
  code?: string;
  fields?: FieldErrors;
  fieldCodes?: FieldCodes;
}

const PROBLEM_CONTENT_TYPE = 'application/problem+json';

function optionalString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

function toFieldErrors(value: unknown): FieldErrors | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const entries = Object.entries(value).filter(
    (entry): entry is [string, string] => typeof entry[1] === 'string',
  );
  return Object.fromEntries(entries);
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    typeof value === 'object' &&
    value !== null &&
    Object.values(value).every((entry) => typeof entry === 'string')
  );
}

function toFieldIssue(value: unknown): FieldIssue | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const { code, params } = value as Record<string, unknown>;
  if (typeof code !== 'string') {
    return undefined;
  }
  return isStringRecord(params) ? { code, params } : { code };
}

function toFieldCodes(value: unknown): FieldCodes | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const entries = Object.entries(value).flatMap(([field, raw]) => {
    const issue = toFieldIssue(raw);
    return issue ? [[field, issue] as const] : [];
  });
  return Object.fromEntries(entries);
}

async function readProblem(response: Response): Promise<ProblemDetails | undefined> {
  const contentType = response.headers.get('Content-Type') ?? '';
  if (!contentType.includes(PROBLEM_CONTENT_TYPE)) {
    return undefined;
  }
  let payload: unknown;
  try {
    payload = await readJson(response);
  } catch {
    return undefined;
  }
  if (typeof payload !== 'object' || payload === null) {
    return undefined;
  }
  const record = payload as Record<string, unknown>;
  return {
    title: optionalString(record, 'title'),
    detail: optionalString(record, 'detail'),
    code: optionalString(record, 'code'),
    fields: toFieldErrors(record.fields),
    fieldCodes: toFieldCodes(record.fieldCodes),
  };
}

async function toApiError(response: Response): Promise<ApiError> {
  const problem = await readProblem(response);
  return new ApiError({
    status: response.status,
    code: problem?.code ?? `http_${response.status}`,
    message:
      problem?.detail ?? problem?.title ?? (response.statusText || `HTTP ${response.status}`),
    fields: problem?.fields,
    fieldCodes: problem?.fieldCodes,
    retryAfterSeconds: parseRetryAfter(response.headers.get('Retry-After')),
  });
}

function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) {
    return undefined;
  }
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? Math.ceil(seconds) : undefined;
}
