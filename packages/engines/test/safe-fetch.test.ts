import { describe, expect, it, vi } from 'vitest';
import { inspectUrl, isBlockedAddress, safeFetch } from '../src/net/safeFetch.js';

/**
 * The guard exists because two checks fetch URLs chosen by whoever controls a
 * stranger's DNS. Every case below is something one of those records could
 * legitimately contain, so each one is a request the Worker would otherwise
 * have made from our egress.
 */

const ok = (body: string, headers: Record<string, string> = {}) =>
  new Response(body, { status: 200, headers: { 'content-type': 'text/plain', ...headers } });

/** A fetch that records every URL it is asked for. */
function spy(responses: Response[] | ((url: string) => Response)) {
  const seen: string[] = [];
  let at = 0;
  const impl = vi.fn(async (url: string, _init?: RequestInit) => {
    seen.push(url);
    if (typeof responses === 'function') return responses(url);
    return responses[at++] ?? ok('');
  });
  return { impl, seen };
}

const base = { maxBytes: 1024, timeoutMs: 500 };

describe('inspectUrl', () => {
  it('allows an ordinary https URL', () => {
    const result = inspectUrl('https://static.example.com/bimi/logo.svg');
    expect(result.ok).toBe(true);
  });

  it.each([
    ['http://example.com/logo.svg', 'plain http'],
    ['ftp://example.com/logo.svg', 'ftp'],
    ['file:///etc/passwd', 'a local file'],
    ['data:image/svg+xml,<svg/>', 'a data URL'],
  ])('refuses %s (%s)', (url) => {
    const result = inspectUrl(url);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('NOT_HTTPS');
  });

  it('refuses credentials in the URL', () => {
    const result = inspectUrl('https://user:pass@example.com/logo.svg');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('NOT_HTTPS');
  });

  it('refuses a port that is not 443', () => {
    const result = inspectUrl('https://example.com:8080/logo.svg');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('NOT_HTTPS');
  });

  it.each([
    'https://127.0.0.1/x',
    'https://10.0.0.5/x',
    'https://172.16.4.1/x',
    'https://192.168.1.1/x',
    'https://169.254.169.254/latest/meta-data/',
    'https://[::1]/x',
    'https://[fc00::1]/x',
    'https://[fe80::1]/x',
    'https://localhost/x',
    'https://db.internal/x',
    'https://printer.local/x',
  ])('refuses %s', (url) => {
    const result = inspectUrl(url);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('BLOCKED_ADDRESS');
  });

  it('refuses the cloud metadata address however it is spelled', () => {
    // `new URL` normalises the decimal form, which is the usual way past a
    // string comparison against "169.254.169.254".
    expect(inspectUrl('https://2852039166/latest/meta-data/').ok).toBe(false);
    expect(inspectUrl('https://0x7f000001/x').ok).toBe(false);
  });
});

describe('isBlockedAddress', () => {
  it('blocks private space and allows public', () => {
    expect(isBlockedAddress('127.0.0.1')).toBe(true);
    expect(isBlockedAddress('169.254.169.254')).toBe(true);
    expect(isBlockedAddress('::1')).toBe(true);
    expect(isBlockedAddress('93.184.216.34')).toBe(false);
    expect(isBlockedAddress('2606:2800:220:1:248:1893:25c8:1946')).toBe(false);
  });
});

describe('safeFetch', () => {
  it('fetches a public https URL and never sets redirect follow', async () => {
    const { impl, seen } = spy([ok('hello')]);
    const result = await safeFetch('https://example.com/a.txt', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(true);
    expect(seen).toEqual(['https://example.com/a.txt']);
    expect(impl.mock.calls[0]?.[1]?.redirect).toBe('manual');
  });

  it('makes no request at all when the URL is refused', async () => {
    const { impl, seen } = spy([ok('hello')]);
    const result = await safeFetch('https://169.254.169.254/latest/', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(false);
    // The point of the guard: refused before anything leaves.
    expect(seen).toEqual([]);
  });

  it('refuses a host that resolves into private space', async () => {
    const { impl, seen } = spy([ok('hello')]);
    const result = await safeFetch('https://rebind.example.com/logo.svg', {
      ...base,
      fetchImpl: impl,
      resolveHost: async () => ['10.1.2.3'],
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('BLOCKED_ADDRESS');
    expect(seen).toEqual([]);
  });

  it('allows a host that resolves publicly', async () => {
    const { impl } = spy([ok('hello')]);
    const result = await safeFetch('https://example.com/logo.svg', {
      ...base,
      fetchImpl: impl,
      resolveHost: async () => ['93.184.216.34'],
    });
    expect(result.ok).toBe(true);
  });

  it('does not fail closed when the resolver itself errors', async () => {
    // A resolver failure is not evidence of anything, and `fetch` will fail on
    // its own if the name is genuinely dead.
    const { impl } = spy([ok('hello')]);
    const result = await safeFetch('https://example.com/logo.svg', {
      ...base,
      fetchImpl: impl,
      resolveHost: async () => {
        throw new Error('DoH down');
      },
    });
    expect(result.ok).toBe(true);
  });

  it('treats a redirect as the answer when none are allowed', async () => {
    const { impl } = spy([new Response(null, { status: 301, headers: { location: 'https://elsewhere.example/x' } })]);
    const result = await safeFetch('https://example.com/a.txt', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('REDIRECT');
  });

  it('re-checks every redirect hop and refuses one into private space', async () => {
    const { impl, seen } = spy([
      new Response(null, { status: 302, headers: { location: 'https://169.254.169.254/latest/' } }),
      ok('secrets'),
    ]);
    const result = await safeFetch('https://example.com/a.txt', {
      ...base,
      fetchImpl: impl,
      maxRedirects: 3,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('BLOCKED_ADDRESS');
    // The first hop happened, the second never did.
    expect(seen).toEqual(['https://example.com/a.txt']);
  });

  it('refuses a redirect that downgrades to http', async () => {
    const { impl } = spy([
      new Response(null, { status: 302, headers: { location: 'http://example.com/a.txt' } }),
    ]);
    const result = await safeFetch('https://example.com/a.txt', {
      ...base,
      fetchImpl: impl,
      maxRedirects: 2,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('NOT_HTTPS');
  });

  it('follows a relative redirect against the hop it came from', async () => {
    const { impl, seen } = spy([
      new Response(null, { status: 302, headers: { location: '/moved/logo.svg' } }),
      ok('<svg/>'),
    ]);
    const result = await safeFetch('https://example.com/a/logo.svg', {
      ...base,
      fetchImpl: impl,
      maxRedirects: 2,
    });

    expect(result.ok).toBe(true);
    expect(seen).toEqual(['https://example.com/a/logo.svg', 'https://example.com/moved/logo.svg']);
  });

  it('stops after the hop budget', async () => {
    const { impl } = spy((url) =>
      new Response(null, { status: 302, headers: { location: `${url}x` } }),
    );
    const result = await safeFetch('https://example.com/a', {
      ...base,
      fetchImpl: impl,
      maxRedirects: 2,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('REDIRECT');
  });

  it('refuses a body larger than the ceiling, by content-length', async () => {
    const { impl } = spy([ok('x', { 'content-length': '99999' })]);
    const result = await safeFetch('https://example.com/a', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('TOO_LARGE');
  });

  it('refuses a body larger than the ceiling when the header lied', async () => {
    const { impl } = spy([ok('y'.repeat(5_000), { 'content-length': '1' })]);
    const result = await safeFetch('https://example.com/a', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('TOO_LARGE');
  });

  it('reports a non-200 as a status rather than a body', async () => {
    const { impl } = spy([new Response('nope', { status: 404 })]);
    const result = await safeFetch('https://example.com/a', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('STATUS');
  });

  it('reports a thrown fetch as unreachable rather than crashing', async () => {
    const impl = vi.fn(async () => {
      throw new Error('certificate invalid');
    });
    const result = await safeFetch('https://example.com/a', { ...base, fetchImpl: impl });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.refusal).toBe('UNREACHABLE');
  });

  it('passes an abort signal so a slow host cannot hold a subrequest open', async () => {
    const { impl } = spy([ok('hello')]);
    await safeFetch('https://example.com/a', { ...base, fetchImpl: impl });
    expect(impl.mock.calls[0]?.[1]?.signal).toBeDefined();
  });
});
