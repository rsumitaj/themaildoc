import { describe, expect, it } from 'vitest';
import { vitals } from '@maildoc/catalog';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockDohOptions, type MockZone } from '@maildoc/resolver/testing';
import { analyzeSpf, type SpfEngineOptions } from '../src/index.js';

/**
 * Golden tests for the SPF engine. Every case is a zone a real domain could
 * have; the assertions are the exact catalog codes a receiver's behaviour
 * justifies. If this file is honest, the product is accurate.
 */

interface RunOptions extends SpfEngineOptions {
  domain?: string;
  mock?: MockDohOptions;
  budget?: number;
}

async function run(zone: MockZone, options: RunOptions = {}) {
  const { domain = 'example.com', mock: mockOptions, budget, ...engineOptions } = options;
  const mock = createMockDoh(zone, mockOptions);
  const resolver = new DohResolver({
    fetchImpl: mock.fetch,
    timeoutMs: 20,
    ...(budget === undefined ? {} : { budget }),
  });
  const analysis = await analyzeSpf(domain, resolver, { verifyApex: false, ...engineOptions });
  return { analysis, codes: analysis.conditions.map((c) => c.code), mock, resolver };
}

/** A healthy two-hop setup: apex includes one vendor, both end in -all. */
const healthyZone: MockZone = {
  'example.com': {
    TXT: ['v=spf1 include:_spf.example.com ip4:203.0.113.0/24 -all'],
    A: ['203.0.113.10'],
  },
  '_spf.example.com': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
};

describe('SPF — a healthy record', () => {
  it('finds no conditions and a clean bill of health', async () => {
    const { analysis, codes } = await run(healthyZone);

    expect(analysis.found).toBe(true);
    expect(analysis.record).toBe('v=spf1 include:_spf.example.com ip4:203.0.113.0/24 -all');
    expect(codes).toEqual([]);
    expect(analysis.status).toBe('HEALTHY');
    expect(vitals(analysis.conditions).score).toBe(100);
  });

  it('counts exactly one DNS lookup for one include', async () => {
    const { analysis } = await run(healthyZone);
    expect(analysis.lookupCount).toBe(1);
    expect(analysis.lookupCountExact).toBe(true);
    expect(analysis.voidLookupCount).toBe(0);
  });

  it('records the chain it walked', async () => {
    const { analysis } = await run(healthyZone);
    expect(analysis.chain?.domain).toBe('example.com');
    expect(analysis.chain?.children).toHaveLength(1);
    expect(analysis.chain?.children[0]?.domain).toBe('_spf.example.com');
    expect(analysis.chain?.children[0]?.via).toBe('include');
    expect(analysis.chain?.children[0]?.record).toBe('v=spf1 ip4:198.51.100.0/24 -all');
  });

  it('reads a multi-string record the way a receiver does', async () => {
    const { analysis, codes } = await run({
      'example.com': {
        TXT: [['v=spf1 ip4:203.0.113.0/24 ', 'ip4:198.51.100.0/24 -all']],
      },
    });
    expect(analysis.record).toBe('v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/24 -all');
    expect(codes).toEqual([]);
  });
});

describe('SPF — missing record', () => {
  it('reports SPF_RECORD_MISSING when the domain has no SPF', async () => {
    const { analysis, codes } = await run({ 'example.com': { A: ['203.0.113.10'] } });

    expect(analysis.found).toBe(false);
    expect(codes).toEqual(['SPF_RECORD_MISSING']);
    expect(analysis.status).toBe('CRITICAL');
    expect(vitals(analysis.conditions).score).toBe(60);
    expect(analysis.conditions[0]?.why).toContain('example.com');
  });

  it('reports SPF_RECORD_MISSING when other TXT records exist', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=DMARC1x', 'MS=ms12345678', 'google-site-verification=abc'] },
    });
    expect(codes).toEqual(['SPF_RECORD_MISSING']);
  });

  it('reports the domain, not SPF, when nothing resolves at all', async () => {
    const { codes } = await run({});
    expect(codes).toEqual(['DOMAIN_NXDOMAIN']);
  });

  it('spots a record with the wrong version prefix', async () => {
    const { codes, analysis } = await run({
      'example.com': { TXT: ['v=spf2 include:_spf.example.com -all'] },
    });
    expect(codes).toEqual(['SPF_INVALID_VERSION']);
    expect(analysis.conditions[0]?.evidence).toBe('v=spf2 include:_spf.example.com -all');
  });
});

describe('SPF — multiple records', () => {
  it('reports a PermError and refuses to pick one', async () => {
    const { analysis, codes } = await run({
      'example.com': {
        TXT: ['v=spf1 include:_spf.example.com -all', 'v=spf1 ip4:203.0.113.1 ~all'],
      },
      '_spf.example.com': { TXT: ['v=spf1 -all'] },
    });

    expect(codes).toEqual(['SPF_MULTIPLE_RECORDS']);
    expect(analysis.records).toHaveLength(2);
    expect(analysis.record).toBeNull();
    // A receiver stops at the PermError, so no include is ever evaluated.
    expect(analysis.lookupCount).toBe(0);
    expect(analysis.conditions[0]?.why).toContain('2 SPF records');
  });
});

describe('SPF — the "all" policy', () => {
  it('flags +all as authorising the entire internet', async () => {
    const { codes, analysis } = await run({ 'example.com': { TXT: ['v=spf1 +all'] } });
    expect(codes).toEqual(['SPF_ALL_TOO_PERMISSIVE']);
    expect(analysis.allQualifier).toBe('+');
    expect(analysis.conditions[0]?.severity).toBe('CRITICAL');
    expect(analysis.conditions[0]?.why).toContain('+all');
  });

  it('flags ?all the same way — neutral protects nobody', async () => {
    const { codes } = await run({ 'example.com': { TXT: ['v=spf1 ip4:203.0.113.1 ?all'] } });
    expect(codes).toEqual(['SPF_ALL_TOO_PERMISSIVE']);
  });

  it('treats ~all as an advisory, not a fault', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 ~all'] },
    });

    expect(codes).toEqual(['SPF_SOFTFAIL_ADVISORY']);
    expect(analysis.allQualifier).toBe('~');
    expect(analysis.status).toBe('HEALTHY');
    expect(analysis.conditions[0]?.severity).toBe('INFO');
    expect(analysis.conditions[0]?.dismissible).toBe(true);
    expect(vitals(analysis.conditions).score).toBe(98);
  });

  it('says nothing about -all', async () => {
    const { codes } = await run({ 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] } });
    expect(codes).toEqual([]);
  });

  it('flags a record that never says no', async () => {
    const { codes } = await run({ 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24'] } });
    expect(codes).toEqual(['SPF_ALL_MISSING']);
  });

  it('flags mechanisms stranded after all', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 -all include:_spf.example.com'] },
      '_spf.example.com': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    });
    expect(codes).toContain('SPF_ALL_NOT_LAST');
  });

  it('flags +all inside an included record — the same free pass', async () => {
    const { codes, analysis } = await run({
      'example.com': { TXT: ['v=spf1 include:vendor.example.net -all'] },
      'vendor.example.net': { TXT: ['v=spf1 +all'] },
    });
    expect(codes).toContain('SPF_ALL_TOO_PERMISSIVE');
    expect(analysis.conditions.find((c) => c.code === 'SPF_ALL_TOO_PERMISSIVE')?.why).toContain(
      'vendor.example.net',
    );
  });
});

describe('SPF — the 10-lookup limit (RFC 7208 §4.6.4)', () => {
  const chainZone = (count: number): MockZone => {
    const includes = Array.from({ length: count }, (_, i) => `include:v${i}.example.net`);
    const zone: MockZone = {
      'example.com': { TXT: [`v=spf1 ${includes.join(' ')} -all`] },
    };
    for (let i = 0; i < count; i += 1) {
      zone[`v${i}.example.net`] = { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] };
    }
    return zone;
  };

  it('counts each include exactly once', async () => {
    const { analysis } = await run(chainZone(4));
    expect(analysis.lookupCount).toBe(4);
    expect(analysis.lookupCountExact).toBe(true);
  });

  it('counts lookups nested inside includes', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 include:a.example.net -all'] },
      'a.example.net': { TXT: ['v=spf1 include:b.example.net mx a -all'] },
      'b.example.net': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    });
    // include(a) + include(b) + mx + a = 4
    expect(analysis.lookupCount).toBe(4);
    expect(codes).not.toContain('SPF_LOOKUP_LIMIT_EXCEEDED');
  });

  it('does not count ip4, ip6 or all', async () => {
    const { analysis } = await run({
      'example.com': {
        TXT: ['v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/24 ip6:2001:db8::/32 -all'],
      },
    });
    expect(analysis.lookupCount).toBe(0);
  });

  it('reports SPF_LOOKUP_LIMIT_EXCEEDED past 10 with the exact count', async () => {
    const { analysis, codes } = await run(chainZone(11));

    expect(analysis.lookupCount).toBe(11);
    expect(codes).toContain('SPF_LOOKUP_LIMIT_EXCEEDED');
    expect(codes).not.toContain('SPF_LOOKUP_APPROACHING_LIMIT');
    const condition = analysis.conditions.find((c) => c.code === 'SPF_LOOKUP_LIMIT_EXCEEDED');
    expect(condition?.severity).toBe('CRITICAL');
    expect(condition?.why).toContain('11 DNS lookups');
  });

  it('is not fooled at exactly 10 — that is still valid', async () => {
    const { analysis, codes } = await run(chainZone(10), { budget: 40 });
    expect(analysis.lookupCount).toBe(10);
    expect(codes).toContain('SPF_LOOKUP_APPROACHING_LIMIT');
    expect(codes).not.toContain('SPF_LOOKUP_LIMIT_EXCEEDED');
  });

  it('warns at 9 lookups, before the record breaks', async () => {
    const { codes } = await run(chainZone(9));
    expect(codes).toEqual(['SPF_LOOKUP_APPROACHING_LIMIT']);
  });

  it('says nothing at 8', async () => {
    const { codes } = await run(chainZone(8));
    expect(codes).toEqual([]);
  });

  it('counts a duplicate include twice — it costs two lookups', async () => {
    const { analysis, codes } = await run({
      'example.com': {
        TXT: ['v=spf1 include:v.example.net include:v.example.net -all'],
      },
      'v.example.net': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    });

    expect(analysis.lookupCount).toBe(2);
    expect(codes).toContain('SPF_DUPLICATE_INCLUDE');
    expect(
      analysis.conditions.find((c) => c.code === 'SPF_DUPLICATE_INCLUDE')?.why,
    ).toContain('2 times');
  });
});

describe('SPF — void lookups', () => {
  it('reports more than two lookups that resolve to nothing', async () => {
    const { analysis, codes } = await run({
      'example.com': {
        TXT: [
          'v=spf1 include:gone1.example.net include:gone2.example.net include:gone3.example.net -all',
        ],
      },
    });

    expect(analysis.voidLookupCount).toBe(3);
    expect(analysis.voidDomains).toEqual([
      'gone1.example.net',
      'gone2.example.net',
      'gone3.example.net',
    ]);
    expect(codes).toContain('SPF_VOID_LOOKUP_EXCEEDED');
    expect(
      analysis.conditions.find((c) => c.code === 'SPF_VOID_LOOKUP_EXCEEDED')?.why,
    ).toContain('gone1.example.net');
  });

  it('tolerates two void lookups — the RFC allows them', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 include:gone1.example.net include:gone2.example.net -all'] },
    });
    expect(analysis.voidLookupCount).toBe(2);
    expect(codes).not.toContain('SPF_VOID_LOOKUP_EXCEEDED');
  });

  it('counts an a: mechanism pointing at a name with no address', async () => {
    const { analysis } = await run({
      'example.com': { TXT: ['v=spf1 a:ghost.example.net -all'] },
      'ghost.example.net': { TXT: ['unrelated'] },
    });
    expect(analysis.voidLookupCount).toBe(1);
    expect(analysis.voidDomains).toEqual(['ghost.example.net']);
  });

  it('reports an include target that exists but publishes no SPF', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 include:vendor.example.net -all'] },
      'vendor.example.net': { TXT: ['google-site-verification=abc'] },
    });

    expect(codes).toEqual(['SPF_INCLUDE_NXDOMAIN']);
    expect(analysis.conditions[0]?.why).toContain('vendor.example.net');
    // The name answered, so this is a PermError but not a void lookup.
    expect(analysis.voidLookupCount).toBe(0);
  });
});

describe('SPF — circular includes', () => {
  it('detects a loop and stops walking it', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 include:a.example.net -all'] },
      'a.example.net': { TXT: ['v=spf1 include:b.example.net -all'] },
      'b.example.net': { TXT: ['v=spf1 include:example.com -all'] },
    });

    expect(codes).toContain('SPF_CIRCULAR_INCLUDE');
    const condition = analysis.conditions.find((c) => c.code === 'SPF_CIRCULAR_INCLUDE');
    expect(condition?.severity).toBe('CRITICAL');
    expect(condition?.why).toContain('example.com → a.example.net → b.example.net → example.com');
    expect(analysis.lookupCount).toBe(3);
  });

  it('detects a record that includes itself', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 include:example.com -all'] },
    });
    expect(codes).toContain('SPF_CIRCULAR_INCLUDE');
  });

  it('terminates instead of hanging', async () => {
    const { resolver } = await run({
      'example.com': { TXT: ['v=spf1 include:loop.example.net -all'] },
      'loop.example.net': { TXT: ['v=spf1 include:loop.example.net -all'] },
    });
    expect(resolver.queriesIssued).toBeLessThan(10);
  });
});

describe('SPF — syntax and mechanism problems', () => {
  it('flags the deprecated ptr mechanism and counts its lookup', async () => {
    const { analysis, codes } = await run({ 'example.com': { TXT: ['v=spf1 ptr -all'] } });
    expect(codes).toEqual(['SPF_PTR_MECHANISM']);
    expect(analysis.lookupCount).toBe(1);
  });

  it('flags invalid IPv4 and IPv6 literals', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 ip4:999.1.1.1 ip6:zzzz::1 -all'] },
    });
    expect(codes).toContain('SPF_INVALID_IPV4');
    expect(codes).toContain('SPF_INVALID_IPV6');
  });

  it('flags an impossible prefix length', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/33 ip6:2001:db8::/129 -all'] },
    });
    expect(codes).toContain('SPF_INVALID_IPV4_CIDR');
    expect(codes).toContain('SPF_INVALID_IPV6_CIDR');
  });

  it('flags private addresses as an advisory', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 ip4:203.0.113.1 ip4:10.0.0.1 -all'] },
    });
    expect(codes).toEqual(['SPF_PRIVATE_IP_IN_SPF']);
    expect(analysis.conditions[0]?.severity).toBe('INFO');
  });

  it('flags a term no receiver can parse', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 include:_spf.example.com example.net -all'] },
      '_spf.example.com': { TXT: ['v=spf1 -all'] },
    });
    expect(codes).toContain('SPF_UNKNOWN_TERM');
  });

  it('notes an unknown modifier without treating it as a fault', async () => {
    // §6 requires receivers to ignore it, so this must never be an error —
    // but it is usually a misspelled redirect= that someone thinks is live.
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 moo=cow -all'] },
    });
    expect(codes).toEqual(['SPF_UNKNOWN_MODIFIER']);
    expect(analysis.conditions[0]?.severity).toBe('INFO');
    expect(analysis.status).toBe('HEALTHY');
  });

  it('catches a mechanism written with = instead of :', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 include=_spf.example.com -all'] },
    });
    expect(codes).toContain('SPF_INVALID_TERM_SEPARATOR');
    expect(codes).not.toContain('SPF_UNKNOWN_MODIFIER');
  });

  it('catches a duplicated redirect modifier', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 redirect=a.example.net redirect=b.example.net'] },
      'a.example.net': { TXT: ['v=spf1 -all'] },
      'b.example.net': { TXT: ['v=spf1 -all'] },
    });
    expect(codes).toContain('SPF_DUPLICATE_MODIFIER');
  });

  it('separates a redirect loop from an include loop', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 redirect=r.example.net'] },
      'r.example.net': { TXT: ['v=spf1 redirect=example.com'] },
    });
    expect(codes).toContain('SPF_REDIRECT_LOOP');
    expect(codes).not.toContain('SPF_CIRCULAR_INCLUDE');
  });

  it('reports a redirect to a domain with no SPF as its own condition', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 redirect=gone.example.net'] },
    });
    expect(codes).toContain('SPF_REDIRECT_NXDOMAIN');
    expect(codes).not.toContain('SPF_INCLUDE_NXDOMAIN');
  });

  it('enforces the separate 10-name cap on a single mx mechanism', async () => {
    const mx = Array.from({ length: 11 }, (_, i) => `${i * 10} mail${i}.example.com.`);
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 mx -all'], MX: mx },
    });
    expect(codes).toContain('SPF_MX_LIMIT_EXCEEDED');
  });

  it('names which mechanism resolved to nothing', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 a:ghost.example.net mx:nomx.example.net -all'] },
      'ghost.example.net': { TXT: ['x'] },
      'nomx.example.net': { A: ['203.0.113.9'] },
    });
    expect(codes).toContain('SPF_A_TARGET_VOID');
    expect(codes).toContain('SPF_MX_TARGET_VOID');
  });

  it('flags mixed-case mechanisms and stray whitespace as tidy-ups only', async () => {
    const { analysis } = await run({
      'example.com': { TXT: ['v=spf1  IP4:203.0.113.0/24   -all'] },
    });
    const codes = analysis.conditions.map((c) => c.code);
    expect(codes).toContain('SPF_MECHANISM_CASE');
    expect(codes).toContain('SPF_EXTRA_WHITESPACE');
    expect(analysis.status).toBe('HEALTHY');
  });

  it('notes an exp= published by an included record', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 include:vendor.example.net -all'] },
      'vendor.example.net': { TXT: ['v=spf1 ip4:198.51.100.0/24 exp=why.vendor.example.net -all'] },
    });
    expect(codes).toContain('SPF_EXP_IN_INCLUDE');
  });

  it('flags a malformed macro', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 exists:%{z}.example.net -all'] },
    });
    expect(codes).toContain('SPF_INVALID_MACRO');
  });

  it('accepts a valid macro without resolving it', async () => {
    const { codes, analysis } = await run({
      'example.com': { TXT: ['v=spf1 exists:%{ir}.spam.example.net -all'] },
    });
    expect(codes).toEqual([]);
    expect(analysis.lookupCount).toBe(1);
  });
});

describe('SPF — redirect', () => {
  it('follows redirect= and counts its lookup', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 redirect=_spf.example.com'] },
      '_spf.example.com': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    });

    expect(codes).toEqual([]);
    expect(analysis.lookupCount).toBe(1);
    expect(analysis.redirect).toBe('_spf.example.com');
    expect(analysis.chain?.children[0]?.via).toBe('redirect');
  });

  it('flags redirect= alongside all — the redirect is dead weight', async () => {
    const { analysis, codes } = await run({
      'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all redirect=_spf.example.com'] },
      '_spf.example.com': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    });

    expect(codes).toEqual(['SPF_REDIRECT_ALL_CONFLICT']);
    // The ignored redirect costs no lookup, because receivers never follow it.
    expect(analysis.lookupCount).toBe(0);
  });

  it('does not demand an all mechanism when redirect= supplies the policy', async () => {
    const { codes } = await run({
      'example.com': { TXT: ['v=spf1 redirect=_spf.example.com'] },
      '_spf.example.com': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    });
    expect(codes).not.toContain('SPF_ALL_MISSING');
  });
});

describe('SPF — record size', () => {
  const padded = (bytes: number) => {
    const ips: string[] = [];
    let record = 'v=spf1';
    while (record.length < bytes) {
      const ip = `ip4:198.51.${Math.floor(ips.length / 250)}.${ips.length % 250}`;
      ips.push(ip);
      record = `v=spf1 ${ips.join(' ')} -all`;
    }
    return record;
  };

  it('flags a record published as one over-long string', async () => {
    const record = padded(300);
    const { codes } = await run(
      { 'example.com': { TXT: [record] } },
      { mock: { txtRendering: 'quoted' } },
    );
    expect(codes).toContain('SPF_RECORD_STRING_TOO_LONG');
  });

  it('does not flag the same record when it is split correctly', async () => {
    const record = padded(300);
    const half = Math.floor(record.length / 2);
    const { codes } = await run(
      { 'example.com': { TXT: [[record.slice(0, half), record.slice(half)]] } },
      { mock: { txtRendering: 'quoted' } },
    );
    expect(codes).not.toContain('SPF_RECORD_STRING_TOO_LONG');
  });

  it('stays silent when the resolver concatenated the strings away', async () => {
    // Regression: github.com's record is correctly split, but Google's DoH
    // hands it back as one long string. Accusing it of being malformed would
    // be a false positive on every large, healthy record.
    const record = padded(300);
    const half = Math.floor(record.length / 2);
    const { codes } = await run(
      { 'example.com': { TXT: [[record.slice(0, half), record.slice(half)]] } },
      { mock: { txtRendering: 'concatenated' } },
    );
    expect(codes).not.toContain('SPF_RECORD_STRING_TOO_LONG');
  });

  it('recovers segmentation from the second resolver when verifying the apex', async () => {
    const record = padded(300);
    const { codes } = await run({ 'example.com': { TXT: [record] } }, { verifyApex: true });
    expect(codes).toContain('SPF_RECORD_STRING_TOO_LONG');
  });

  it('warns about truncation risk on a large record', async () => {
    const record = padded(500);
    const half = Math.floor(record.length / 2);
    const { codes } = await run({
      'example.com': { TXT: [[record.slice(0, half), record.slice(half)]] },
    });
    expect(codes).toContain('SPF_UDP_TRUNCATION_RISK');
  });
});

describe('SPF — never a wrong answer', () => {
  it('reports a resolver timeout instead of inventing a missing record', async () => {
    const { analysis, codes } = await run(healthyZone, {
      mock: { fail: () => 'TIMEOUT' },
    });

    expect(codes).toEqual(['RESOLVER_TIMEOUT']);
    expect(codes).not.toContain('SPF_RECORD_MISSING');
    expect(analysis.found).toBe(false);
    expect(analysis.lookupCountExact).toBe(false);
    expect(analysis.notes).toContain('RESOLVER_TIMEOUT');
  });

  it('flags propagation when the two resolvers disagree', async () => {
    const { analysis, codes } = await run(healthyZone, {
      verifyApex: true,
      mock: {
        overrides: {
          cloudflare: { 'example.com': { TXT: ['v=spf1 include:_spf.example.com ~all'] } },
        },
      },
    });

    expect(codes).toContain('PROPAGATION_IN_PROGRESS');
    expect(analysis.notes).toContain('PROPAGATION_IN_PROGRESS');
    // Google is primary, so the diagnosis is of its answer — not a merge.
    expect(analysis.record).toContain('-all');
  });

  it('stops at the query budget and marks the count as a floor', async () => {
    const zone: MockZone = { 'example.com': { TXT: ['v=spf1'] } };
    let record = 'v=spf1';
    for (let i = 0; i < 12; i += 1) {
      record += ` include:v${i}.example.net`;
      zone[`v${i}.example.net`] = { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] };
    }
    zone['example.com'] = { TXT: [`${record} -all`] };

    const { analysis } = await run(zone, { budget: 5 });

    expect(analysis.lookupCountExact).toBe(false);
    expect(analysis.notes).toContain('BUDGET_EXCEEDED');
    expect(analysis.conditions.every((c) => c.code !== 'SPF_INCLUDE_NXDOMAIN')).toBe(true);
  });

  it('produces conditions that are fully interpolated', async () => {
    const { analysis } = await run({
      'example.com': { TXT: ['v=spf1 include:gone.example.net ptr ip4:bad -all'] },
    });

    expect(analysis.conditions.length).toBeGreaterThan(0);
    for (const condition of analysis.conditions) {
      expect(`${condition.title} ${condition.why} ${condition.fix}`).not.toMatch(/\{[a-z_]+\}/);
    }
  });

  it('triages the chart most severe first', async () => {
    const { analysis } = await run({
      'example.com': { TXT: ['v=spf1 ptr ip4:10.0.0.1 +all'] },
    });
    const severities = analysis.conditions.map((c) => c.severity);
    expect(severities[0]).toBe('CRITICAL');
    expect(severities[severities.length - 1]).toBe('INFO');
  });
});
