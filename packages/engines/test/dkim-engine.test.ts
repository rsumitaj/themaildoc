import { describe, expect, it } from 'vitest';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockZone } from '@maildoc/resolver/testing';
import { analyzeDkim, COMMON_SELECTORS, inspectKey, rsaModulusBits, decodeBase64 } from '../src/index.js';

/**
 * Real public keys, generated for these tests. Key size is the finding that
 * matters, so the fixtures are genuine DER rather than plausible-looking
 * base64 — a parser that only works on invented data proves nothing.
 */
const RSA_1024 =
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDnrW6P5x3RoBIi+9HgSmzQEYghcv0B2g1qX2Cie+DVe/RjCs5BxVqcc8v5SR9cTcH1Ap0lPeAe53ok8oHmYQXNPnMUSugKWSzdsa/Bfqh/H1TCaG3sl/4qbP6wlD0wHHxYy9C2BZuOP7HM00J0YDW+HtgnQ8SdvSBMShPQipTxwIDAQAB';

const RSA_2048 =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr85WflNZtr86vJVhlKv0bBT4SS9k77i/mL5GoBIj1xVMjIThDtmwvzqryoz2+GXKkXmbedSxnKQQjIXhFTJA9cCiJbRevsgrwnyb9iAycHuwlC6lveVHfcQiO7ODUOnZKod6uYwIgzMF8ifVCNZ0FzcMSR3vQ4D2rtAhtYeb2dVa1HpWm/zECXWWuQ89wVWQFtcLxYX6+JA4ZD7afc99362neYCa1hc96dKkd+T3YA5wPLaRCLo8C8ow5ifUIBw9Q4p/WW2sdOw6Yer3yfQvFylbh4cwJYlJspJ6nNbIe1kioNs7RYXaH66DtyOgWuHXCSv1AdrCXwdYb63pT3S1GQIDAQAB';

async function run(zone: MockZone, options: Parameters<typeof analyzeDkim>[2] = {}) {
  const mock = createMockDoh(zone);
  const resolver = new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 20, budget: 40 });
  const analysis = await analyzeDkim('example.com', resolver, options);
  return { analysis, codes: analysis.conditions.map((c) => c.code), mock };
}

const at = (selector: string, record: string): MockZone => ({
  [`${selector}._domainkey.example.com`]: { TXT: [record] },
});

describe('DKIM key inspection', () => {
  it('reads the modulus length out of a real 1024-bit key', () => {
    const bytes = decodeBase64(RSA_1024);
    expect(bytes).not.toBeNull();
    expect(rsaModulusBits(bytes as Uint8Array)).toBe(1024);
  });

  it('reads the modulus length out of a real 2048-bit key', () => {
    const bytes = decodeBase64(RSA_2048);
    expect(rsaModulusBits(bytes as Uint8Array)).toBe(2048);
  });

  it('measures an Ed25519 key by its raw byte length', () => {
    const key = inspectKey('MeibXMi1eOFA8lHEj4DWaxfmjPltWPQy8tWso3jgUBY=', 'ed25519');
    expect(key).toEqual({ algorithm: 'ed25519', bits: 256, valid: true });
  });

  it('rejects an Ed25519 key of the wrong length', () => {
    const key = inspectKey('11qYAYKxCrfVS/7TyWQHOg==', 'ed25519');
    expect(key?.valid).toBe(false);
  });

  it('returns null for key material that is not base64', () => {
    expect(inspectKey('not a key!!', 'rsa')).toBeNull();
  });

  it('tolerates the whitespace DNS panels insert', () => {
    const wrapped = RSA_2048.replace(/(.{40})/g, '$1 ');
    expect(inspectKey(wrapped, 'rsa')?.bits).toBe(2048);
  });
});

describe('DKIM — discovery', () => {
  it('finds a key at a common selector', async () => {
    const { analysis, codes } = await run(at('google', `v=DKIM1; k=rsa; p=${RSA_2048}`));

    expect(analysis.found).toBe(true);
    expect(analysis.keys[0]?.selector).toBe('google');
    expect(analysis.keys[0]?.key?.bits).toBe(2048);
    expect(codes).toEqual([]);
  });

  it('says it probed and found nothing, rather than claiming DKIM is missing', async () => {
    const { analysis, codes } = await run({ 'example.com': { A: ['203.0.113.1'] } });

    expect(codes).toEqual(['DKIM_SELECTOR_NOT_FOUND']);
    expect(analysis.conditions[0]?.severity).toBe('INFO');
    // The wording must not accuse the domain of having no DKIM — we guessed.
    expect(analysis.conditions[0]?.why).toContain('selector only you know');
    expect(analysis.conditions[0]?.fix).toContain('DKIM-Signature header');
    expect(analysis.probed.length).toBeGreaterThan(5);
  });

  it('treats a selector the patient supplied as authoritative', async () => {
    const { codes } = await run({ 'example.com': { A: ['203.0.113.1'] } }, {
      explicitSelector: 'mysel',
    });
    expect(codes).toEqual(['DKIM_RECORD_MISSING']);
  });

  it('stops probing once the budget is nearly gone', async () => {
    const mock = createMockDoh({});
    const resolver = new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 20, budget: 4 });
    const analysis = await analyzeDkim('example.com', resolver);
    expect(analysis.probed.length).toBeLessThanOrEqual(4);
  });
});

describe('DKIM — key strength', () => {
  it('reports a key below the accepted minimum as critical', async () => {
    // A 512-bit modulus: verifiers MUST NOT accept it (RFC 8301 §3.2).
    const { analysis, codes } = await run(
      at('s1', 'v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKhzJm4TSMktCwwUBCGoFB6WNVI+bERfieU/17jvFW4EzfN+F1cI5gCHMTDzl/wifj65OnAFQwUVfpJkd3ahH2ECAwEAAQ=='),
    );
    expect(codes).toContain('DKIM_KEY_TOO_WEAK');
    expect(analysis.conditions[0]?.severity).toBe('CRITICAL');
  });

  it('reports 1024 bits as workable but dated', async () => {
    const { analysis, codes } = await run(at('s1', `v=DKIM1; k=rsa; p=${RSA_1024}`));
    expect(codes).toEqual(['DKIM_KEY_WEAK_1024']);
    expect(analysis.conditions[0]?.severity).toBe('MEDIUM');
  });

  it('says nothing about a 2048-bit key', async () => {
    const { codes } = await run(at('s1', `v=DKIM1; p=${RSA_2048}`));
    expect(codes).toEqual([]);
  });

  it('reports an empty p= as a revocation', async () => {
    const { analysis, codes } = await run(at('google', 'v=DKIM1; k=rsa; p='));
    expect(codes).toContain('DKIM_KEY_REVOKED');
    expect(analysis.keys[0]?.revoked).toBe(true);
  });

  it('reports a record with no key at all as broken', async () => {
    const { codes } = await run(at('google', 'v=DKIM1; k=rsa'));
    expect(codes).toContain('DKIM_RECORD_BROKEN');
  });

  it('flags an unknown algorithm', async () => {
    const { codes } = await run(at('google', `v=DKIM1; k=magic; p=${RSA_2048}`));
    expect(codes).toContain('DKIM_ALGO_UNKNOWN');
  });
});

describe('DKIM — record flags', () => {
  it('flags testing mode', async () => {
    const { codes } = await run(at('google', `v=DKIM1; k=rsa; t=y; p=${RSA_2048}`));
    expect(codes).toContain('DKIM_TESTING_MODE');
  });

  it('flags a key restricted away from SHA-256', async () => {
    const { codes } = await run(at('google', `v=DKIM1; k=rsa; h=sha1; p=${RSA_2048}`));
    expect(codes).toContain('DKIM_ALGO_SHA1');
  });

  it('accepts an explicit sha256 restriction', async () => {
    const { codes } = await run(at('google', `v=DKIM1; k=rsa; h=sha256; p=${RSA_2048}`));
    expect(codes).toEqual([]);
  });

  it('flags a key restricted to non-email services', async () => {
    const { codes } = await run(at('google', `v=DKIM1; k=rsa; s=web; p=${RSA_2048}`));
    expect(codes).toContain('DKIM_SERVICE_RESTRICTED');
  });

  it('accepts s=* and s=email', async () => {
    const { codes } = await run(at('google', `v=DKIM1; k=rsa; s=*; p=${RSA_2048}`));
    expect(codes).toEqual([]);
  });

  it('flags multiple records at one selector', async () => {
    const { codes } = await run({
      'google._domainkey.example.com': {
        TXT: [`v=DKIM1; k=rsa; p=${RSA_2048}`, `v=DKIM1; k=rsa; p=${RSA_1024}`],
      },
    });
    expect(codes).toContain('DKIM_MULTIPLE_RECORDS');
  });

  it('does not split the base64 key on its padding', async () => {
    // `p=` values end in '=' — a naive tag parser truncates the key here.
    const { analysis } = await run(at('google', `v=DKIM1; k=rsa; p=${RSA_2048}`));
    expect(analysis.keys[0]?.tags['p']).toBe(RSA_2048);
  });
});

describe('wildcard selectors', () => {
  /** A zone where every name under _domainkey answers the same record. */
  const wildcardZone = (record: string): MockZone => {
    const zone: MockZone = {};
    for (const selector of [...COMMON_SELECTORS, 'md-wildcard-probe']) {
      zone[`${selector}._domainkey.example.com`] = { TXT: [record] };
    }
    return zone;
  };

  it('reports one condition, not one per selector', async () => {
    const { analysis, codes } = await run(wildcardZone('v=DKIM1; p='));

    expect(codes).toContain('DKIM_WILDCARD_REVOKED');
    expect(codes).not.toContain('DKIM_KEY_REVOKED');
    expect(codes.filter((code) => code === 'DKIM_WILDCARD_REVOKED')).toHaveLength(1);
    expect(analysis.keys).toHaveLength(1);
    expect(analysis.keys[0]?.selector).toBe('*');
  });

  it('does not move the score thirteen times over', async () => {
    const { analysis } = await run(wildcardZone('v=DKIM1; p='));
    // INFO, so 2 points, rather than a CRITICAL charged once per selector.
    expect(analysis.conditions.every((condition) => condition.severity === 'INFO')).toBe(true);
  });

  it('is loud when the wildcard publishes a usable key', async () => {
    const { codes } = await run(wildcardZone(`v=DKIM1; k=rsa; p=${RSA_2048}`));

    expect(codes).toContain('DKIM_WILDCARD_KEY');
    expect(codes).not.toContain('DKIM_WILDCARD_REVOKED');
  });

  it('does not call a genuinely repeated key a wildcard', async () => {
    // Three selectors share a key, but the invented probe finds nothing.
    const record = `v=DKIM1; k=rsa; p=${RSA_2048}`;
    const zone: MockZone = {
      'google._domainkey.example.com': { TXT: [record] },
      'selector1._domainkey.example.com': { TXT: [record] },
      'k1._domainkey.example.com': { TXT: [record] },
    };

    const { codes, analysis } = await run(zone);
    expect(codes).not.toContain('DKIM_WILDCARD_REVOKED');
    expect(codes).not.toContain('DKIM_WILDCARD_KEY');
    expect(analysis.keys).toHaveLength(3);
  });

  it('leaves an explicitly asked-for selector alone', async () => {
    const { codes } = await run(wildcardZone('v=DKIM1; p='), { explicitSelector: 'google' });
    // The patient asked about one selector, so answer about that selector.
    expect(codes).toContain('DKIM_KEY_REVOKED');
    expect(codes).not.toContain('DKIM_WILDCARD_REVOKED');
  });
});
