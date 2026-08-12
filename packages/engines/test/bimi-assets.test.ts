import { describe, expect, it } from 'vitest';
import { fetchCertificate, fetchLogo } from '../src/index.js';

/**
 * BIMI is judged on what the URLs serve, not on what the record claims. These
 * are the failures that make a record look perfect and show no logo.
 */

const serve = (body: string, init: { status?: number; type?: string; length?: number } = {}) =>
  async () =>
    new Response(body, {
      status: init.status ?? 200,
      headers: {
        'content-type': init.type ?? 'image/svg+xml',
        ...(init.length === undefined ? {} : { 'content-length': String(init.length) }),
      },
    });

const VALID_SVG = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 512 512"><title>Acme</title><rect width="512" height="512" fill="#000"/></svg>`;

describe('fetchLogo', () => {
  it('accepts a correct indicator', async () => {
    const report = await fetchLogo('https://example.com/logo.svg', serve(VALID_SVG));
    expect(report).toMatchObject({ ok: true, tinyPs: true, hasTitle: true, square: true });
    expect(report.forbidden).toEqual([]);
  });

  it('refuses a URL that is not https', async () => {
    const report = await fetchLogo('http://example.com/logo.svg', serve(VALID_SVG));
    expect(report).toMatchObject({ ok: false, failure: 'NOT_HTTPS' });
  });

  it('reports a logo that does not load', async () => {
    const report = await fetchLogo('https://example.com/logo.svg', serve('nope', { status: 404 }));
    expect(report).toMatchObject({ ok: false, failure: 'STATUS', detail: 'HTTP 404' });
  });

  it('catches the wrong SVG profile', async () => {
    const plain = VALID_SVG.replace(' baseProfile="tiny-ps"', '');
    const report = await fetchLogo('https://example.com/logo.svg', serve(plain));
    expect(report.tinyPs).toBe(false);
  });

  it('catches a missing title and a rectangular canvas', async () => {
    const bad = `<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 512 256"></svg>`;
    const report = await fetchLogo('https://example.com/logo.svg', serve(bad));
    expect(report).toMatchObject({ hasTitle: false, square: false, viewBox: '0 0 512 256' });
  });

  it('catches constructs the profile forbids', async () => {
    const hostile = VALID_SVG.replace('<title>', '<script>alert(1)</script><title>');
    const report = await fetchLogo('https://example.com/logo.svg', serve(hostile));
    expect(report.forbidden).toContain('script');
  });

  it('refuses a file larger than the cap without reading it', async () => {
    const report = await fetchLogo(
      'https://example.com/logo.svg',
      serve(VALID_SVG, { length: 5_000_000 }),
    );
    expect(report).toMatchObject({ ok: false, failure: 'TOO_LARGE' });
  });

  it('refuses a response that is not an SVG', async () => {
    const report = await fetchLogo(
      'https://example.com/logo.svg',
      serve('<html></html>', { type: 'text/html' }),
    );
    expect(report).toMatchObject({ ok: false, failure: 'CONTENT_TYPE' });
  });
});

describe('fetchCertificate', () => {
  it('reports a response with no certificate in it', async () => {
    const report = await fetchCertificate(
      'https://example.com/vmc.pem',
      serve('not a certificate', { type: 'text/plain' }),
    );
    expect(report).toMatchObject({ ok: false, failure: 'CONTENT_TYPE' });
  });

  it('reports one that does not load', async () => {
    const report = await fetchCertificate(
      'https://example.com/vmc.pem',
      serve('', { status: 500 }),
    );
    expect(report).toMatchObject({ ok: false, failure: 'STATUS' });
  });

  it('counts the certificates in a chain', async () => {
    const block = '-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----';
    const report = await fetchCertificate(
      'https://example.com/vmc.pem',
      serve(`${block}\n${block}`, { type: 'application/pem-certificate-chain' }),
    );
    expect(report.ok).toBe(true);
    expect(report.certificates).toBe(2);
  });
});
