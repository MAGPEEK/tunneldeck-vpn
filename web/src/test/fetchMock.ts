import { vi } from 'vitest';

export interface MockResponse {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

export type MockReply = MockResponse | 'network-error';

/** Routes are keyed "METHOD /path". An array is answered in order; its last entry repeats. */
export type MockRoutes = Record<string, MockReply | MockReply[]>;

export function jsonResponse({ status = 200, body, headers = {} }: MockResponse): Response {
  const text = body === undefined ? null : JSON.stringify(body);
  return new Response(text, {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

/** An RFC 9457 problem-details error reply. */
export function problem(
  status: number,
  code: string,
  detail: string,
  options: { fields?: Record<string, string>; headers?: Record<string, string> } = {},
): MockResponse {
  return {
    status,
    body: { type: 'about:blank', title: 'Error', status, detail, code, fields: options.fields },
    headers: { 'Content-Type': 'application/problem+json', ...options.headers },
  };
}

export function mockFetch(routes: MockRoutes) {
  const calls = new Map<string, number>();
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${String(input)}`;
    const route = routes[key];
    if (route === undefined) {
      throw new Error(`unexpected request: ${key}`);
    }
    const replies = Array.isArray(route) ? route : [route];
    const count = calls.get(key) ?? 0;
    calls.set(key, count + 1);
    const reply = replies[Math.min(count, replies.length - 1)];
    if (reply === undefined || reply === 'network-error') {
      throw new TypeError('Failed to fetch');
    }
    return jsonResponse(reply);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
