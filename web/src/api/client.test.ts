import { describe, expect, it } from 'vitest';
import { mockFetch, problem } from '../test/fetchMock';
import { ApiError, CSRF_HEADER, request } from './client';

function sentHeaders(fetchMock: ReturnType<typeof mockFetch>): Record<string, string> {
  const init = fetchMock.mock.calls[0]?.[1];
  return (init?.headers ?? {}) as Record<string, string>;
}

describe('request', () => {
  it('omits the CSRF header on GET and sends same-origin credentials', async () => {
    const fetchMock = mockFetch({ 'GET /api/system': { body: { version: '1.0.0' } } });

    await expect(request('/api/system')).resolves.toEqual({ version: '1.0.0' });

    expect(sentHeaders(fetchMock)[CSRF_HEADER]).toBeUndefined();
    expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe('same-origin');
  });

  it.each(['POST', 'PUT', 'DELETE'] as const)('adds the CSRF header on %s', async (method) => {
    const fetchMock = mockFetch({ [`${method} /api/thing`]: { status: 204 } });

    await expect(request('/api/thing', { method })).resolves.toBeUndefined();

    expect(sentHeaders(fetchMock)[CSRF_HEADER]).toBe('1');
  });

  it('sends the body as JSON', async () => {
    const fetchMock = mockFetch({ 'POST /api/login': { status: 204 } });

    await request('/api/login', { method: 'POST', body: { username: 'admin' } });

    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.body).toBe('{"username":"admin"}');
    expect(sentHeaders(fetchMock)['Content-Type']).toBe('application/json');
  });

  it('maps problem details to an ApiError', async () => {
    mockFetch({
      'POST /api/setup': problem(400, 'validation_failed', 'invalid input', {
        fields: { username: 'too short' },
      }),
    });

    const error = await request('/api/setup', { method: 'POST' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 400,
      code: 'validation_failed',
      message: 'invalid input',
      fields: { username: 'too short' },
    });
  });

  it('uses the problem title when detail is missing', async () => {
    mockFetch({
      'GET /api/system': {
        status: 503,
        body: { type: 'about:blank', title: 'Service unavailable', status: 503, code: 'busy' },
        headers: { 'Content-Type': 'application/problem+json' },
      },
    });

    const error = await request('/api/system').catch((e: unknown) => e);

    expect(error).toMatchObject({ status: 503, code: 'busy', message: 'Service unavailable' });
  });

  it('reads Retry-After into the error', async () => {
    mockFetch({
      'POST /api/login': problem(429, 'rate_limited', 'slow down', {
        headers: { 'Retry-After': '30' },
      }),
    });

    const error = await request('/api/login', { method: 'POST' }).catch((e: unknown) => e);

    expect(error).toMatchObject({ status: 429, code: 'rate_limited', retryAfterSeconds: 30 });
  });

  it('falls back to http_<status> for non-problem error bodies', async () => {
    mockFetch({ 'GET /api/system': { status: 502, body: { error: 'bad gateway' } } });

    const error = await request('/api/system').catch((e: unknown) => e);

    expect(error).toMatchObject({ status: 502, code: 'http_502', fields: {} });
  });

  it('maps network failures to code network', async () => {
    mockFetch({ 'GET /api/session': 'network-error' });

    const error = await request('/api/session').catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 0, code: 'network' });
  });
});
