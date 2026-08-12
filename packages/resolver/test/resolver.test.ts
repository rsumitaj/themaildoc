import { describe, expect, it } from 'vitest';
import { DohResolver } from '../src/index.js';
import { createMockDoh, type MockZone } from '../src/testing/index.js';

const zone: MockZone = {
  'example.com': {
    TXT: ['v=spf1 include:_spf.example.com -all'],
    MX: ['10 mail.example.com.'],
    A: ['203.0.113.10'],
  },
  '_spf.example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] },
  'nomail.example.com': { A: ['203.0.113.11'] },
};

const resolverWith = (mock: ReturnType<typeof createMockDoh>, options = {}) =>
  new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 20, ...options });

describe('DohResolver — answers', () => {
  it('parses a TXT answer', async () => {
    const mock = createMockDoh(zone);
    const result = await resolverWith(mock).query('example.com', 'TXT');

    expect(result.status).toBe('NOERROR');
    expect(result.txt.map((t) => t.value)).toEqual(['v=spf1 include:_spf.example.com -all']);
    expect(result.isVoid).toBe(false);
    expect(result.providers).toEqual(['google']);
  });

  it('concatenates multi-string TXT records', async () => {
    const mock = createMockDoh(
      { 'long.example.com': { TXT: [['v=spf1 ip4:203.0.113.0/24 ', 'ip4:198.51.100.0/24 -all']] } },
      { txtRendering: 'quoted' },
    );
    const result = await resolverWith(mock).query('long.example.com', 'TXT');
    expect(result.txt[0]?.value).toBe('v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/24 -all');
    expect(result.txt[0]?.strings).toHaveLength(2);
    expect(result.txt[0]?.segmented).toBe(true);
  });

  it('knows when a provider has hidden the character-strings', async () => {
    // Google's DoH returns TXT rdata already concatenated and unquoted, so the
    // wire chunking is simply not knowable from its answer.
    const mock = createMockDoh(
      { 'long.example.com': { TXT: [['v=spf1 ip4:203.0.113.0/24 ', '-all']] } },
      { txtRendering: 'concatenated' },
    );
    const result = await resolverWith(mock).query('long.example.com', 'TXT');
    expect(result.txt[0]?.value).toBe('v=spf1 ip4:203.0.113.0/24 -all');
    expect(result.txt[0]?.segmented).toBe(false);
  });

  it('takes segmentation from the resolver that preserves it when both agree', async () => {
    const mock = createMockDoh({
      'long.example.com': { TXT: [['v=spf1 ip4:203.0.113.0/24 ', '-all']] },
    });
    const result = await resolverWith(mock).query('long.example.com', 'TXT', { verify: true });

    expect(result.agreement).toBe('AGREED');
    expect(result.txt[0]?.segmented).toBe(true);
    expect(result.txt[0]?.strings).toHaveLength(2);
  });

  it('separates answers of the queried type from the rest of the chain', async () => {
    const mock = createMockDoh(zone);
    const result = await resolverWith(mock).query('example.com', 'MX');
    expect(result.records.map((r) => r.data)).toEqual(['10 mail.example.com.']);
  });

  it('normalizes the queried name (case and trailing dot)', async () => {
    const mock = createMockDoh(zone);
    const result = await resolverWith(mock).query('EXAMPLE.com.', 'TXT');
    expect(result.name).toBe('example.com');
    expect(result.txt).toHaveLength(1);
  });
});

describe('DohResolver — void lookups (RFC 7208 §4.6.4)', () => {
  it('treats NXDOMAIN as void', async () => {
    const mock = createMockDoh(zone);
    const result = await resolverWith(mock).query('missing.example.com', 'TXT');
    expect(result.status).toBe('NXDOMAIN');
    expect(result.isVoid).toBe(true);
  });

  it('treats an empty answer for an existing name as void', async () => {
    const mock = createMockDoh(zone);
    const result = await resolverWith(mock).query('nomail.example.com', 'TXT');
    expect(result.status).toBe('NOERROR');
    expect(result.records).toHaveLength(0);
    expect(result.isVoid).toBe(true);
  });

  it('does NOT treat our own resolver failure as a void lookup', async () => {
    const mock = createMockDoh(zone, { fail: () => 'NETWORK' });
    const result = await resolverWith(mock).query('example.com', 'TXT');
    expect(result.status).toBe('ERROR');
    expect(result.isVoid).toBe(false);
    expect(result.notes).toContain('RESOLVER_ERROR');
  });
});

describe('DohResolver — resilience', () => {
  it('falls back to Cloudflare when Google fails', async () => {
    const mock = createMockDoh(zone, {
      fail: (call) => (call.provider === 'google' ? 'NETWORK' : undefined),
    });
    const result = await resolverWith(mock).query('example.com', 'TXT');

    expect(result.providers).toEqual(['cloudflare']);
    expect(result.txt).toHaveLength(1);
  });

  it('retries a failed query exactly once per provider', async () => {
    const mock = createMockDoh(zone, { fail: () => 'NETWORK' });
    const result = await resolverWith(mock).query('example.com', 'TXT');

    // 2 providers × (1 attempt + 1 retry)
    expect(mock.calls).toHaveLength(4);
    expect(result.status).toBe('ERROR');
  });

  it('does not retry a 4xx — the query itself is the problem', async () => {
    const mock = createMockDoh(zone, { fail: () => 400 });
    await resolverWith(mock).query('example.com', 'TXT');
    expect(mock.calls).toHaveLength(2);
  });

  it('times out and reports RESOLVER_TIMEOUT', async () => {
    const mock = createMockDoh(zone, { fail: () => 'TIMEOUT' });
    const result = await resolverWith(mock, { timeoutMs: 10, retries: 0 }).query(
      'example.com',
      'TXT',
    );

    expect(result.status).toBe('TIMEOUT');
    expect(result.notes).toContain('RESOLVER_TIMEOUT');
    expect(result.error).toBeTruthy();
  });

  it('never throws — a total outage returns a typed empty result', async () => {
    const mock = createMockDoh(zone, { fail: () => 'NETWORK' });
    const result = await resolverWith(mock).query('example.com', 'MX');
    expect(result.records).toEqual([]);
    expect(result.error).toBe('The DNS lookup failed.');
  });
});

describe('DohResolver — agreement', () => {
  it('flags PROPAGATION_IN_PROGRESS when resolvers disagree', async () => {
    const mock = createMockDoh(zone, {
      overrides: { cloudflare: { 'example.com': { TXT: ['v=spf1 include:_spf.example.com ~all'] } } },
    });
    const result = await resolverWith(mock).query('example.com', 'TXT', { verify: true });

    expect(result.agreement).toBe('DISAGREED');
    expect(result.notes).toContain('PROPAGATION_IN_PROGRESS');
    // The primary resolver's answer is what we report — never a merge.
    expect(result.txt[0]?.value).toBe('v=spf1 include:_spf.example.com -all');
  });

  it('agrees when both resolvers return the same record set', async () => {
    const mock = createMockDoh(zone);
    const result = await resolverWith(mock).query('example.com', 'TXT', { verify: true });

    expect(result.agreement).toBe('AGREED');
    expect(result.notes).toEqual([]);
    expect(result.providers).toEqual(['google', 'cloudflare']);
  });

  it('ignores record order and TXT chunking differences between resolvers', async () => {
    const mock = createMockDoh(
      { 'multi.example.com': { TXT: ['v=spf1 -all', 'other=1'] } },
      {
        overrides: {
          cloudflare: { 'multi.example.com': { TXT: ['other=1', ['v=spf1 ', '-all']] } },
        },
      },
    );
    const result = await resolverWith(mock).query('multi.example.com', 'TXT', { verify: true });
    expect(result.agreement).toBe('AGREED');
  });

  it('reports SINGLE when only one resolver answers', async () => {
    const mock = createMockDoh(zone, {
      fail: (call) => (call.provider === 'cloudflare' ? 'NETWORK' : undefined),
    });
    const result = await resolverWith(mock).query('example.com', 'TXT', { verify: true });

    expect(result.agreement).toBe('SINGLE');
    expect(result.notes).not.toContain('PROPAGATION_IN_PROGRESS');
  });

  it('does not verify by default — one subrequest per query', async () => {
    const mock = createMockDoh(zone);
    await resolverWith(mock).query('example.com', 'TXT');
    expect(mock.calls).toHaveLength(1);
  });
});

describe('DohResolver — budget and reuse', () => {
  it('memoizes identical queries within a checkup', async () => {
    const mock = createMockDoh(zone);
    const resolver = resolverWith(mock);

    await Promise.all([
      resolver.query('example.com', 'TXT'),
      resolver.query('example.com', 'TXT'),
      resolver.query('EXAMPLE.COM', 'TXT'),
    ]);

    expect(mock.calls).toHaveLength(1);
    expect(resolver.queriesIssued).toBe(1);
  });

  it('treats a different type as a different query', async () => {
    const mock = createMockDoh(zone);
    const resolver = resolverWith(mock);
    await resolver.query('example.com', 'TXT');
    await resolver.query('example.com', 'MX');
    expect(mock.calls).toHaveLength(2);
  });

  it('stops at the budget and says so instead of guessing', async () => {
    const mock = createMockDoh(zone);
    const resolver = resolverWith(mock, { budget: 1 });

    await resolver.query('example.com', 'TXT');
    const second = await resolver.query('_spf.example.com', 'TXT');

    expect(second.notes).toContain('BUDGET_EXCEEDED');
    expect(second.isVoid).toBe(false);
    expect(resolver.budgetExhausted).toBe(true);
    expect(mock.calls).toHaveLength(1);
  });

  it('serves from an injected cache without touching the network', async () => {
    const store = new Map<string, import('../src/types.js').DnsQueryResult>();
    const cache = {
      get: (key: string) => store.get(key),
      set: (key: string, value: import('../src/types.js').DnsQueryResult) => {
        store.set(key, value);
      },
    };

    const first = createMockDoh(zone);
    await resolverWith(first, { cache, memoize: false }).query('example.com', 'TXT');
    expect(first.calls).toHaveLength(1);

    const second = createMockDoh(zone);
    const cached = await resolverWith(second, { cache, memoize: false }).query('example.com', 'TXT');
    expect(second.calls).toHaveLength(0);
    expect(cached.txt[0]?.value).toBe('v=spf1 include:_spf.example.com -all');
  });
});

describe('DohResolver — DNSSEC signalling', () => {
  it('surfaces the authenticated-data flag', async () => {
    const mock = createMockDoh({
      'signed.example.com': { A: { data: ['203.0.113.5'], ad: true } },
      'plain.example.com': { A: { data: ['203.0.113.6'] } },
    });
    const resolver = resolverWith(mock);

    expect((await resolver.query('signed.example.com', 'A')).authenticated).toBe(true);
    expect((await resolver.query('plain.example.com', 'A')).authenticated).toBe(false);
  });
});
