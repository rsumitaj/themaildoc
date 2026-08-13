import { describe, expect, it } from 'vitest';
import { vitals } from '@maildoc/catalog';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockDohOptions, type MockZone } from '@maildoc/resolver/testing';
import { analyzeSpf, SPF_DEEP_WALK_BUDGET, type SpfEngineOptions } from '../src/index.js';
import type { SpfChainNode } from '../src/spf/types.js';

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
    // No SPF record is not a fault in a record, it is the absence of one, so
    // the two pillars that depend on having one are held down rather than
    // merely charged: impersonation to 20, delivery to 40. This used to score
    // 82, which said a domain nothing vouches for was in decent shape.
    expect(vitals(analysis.conditions).score).toBe(49);
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
    expect(vitals(analysis.conditions).score).toBe(99);
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

/**
 * The shape that broke in production: four includes at the apex, one of them a
 * five-deep linear chain of per-customer names published by an SPF flattening
 * vendor. Twelve lookups, well over the limit, and every hop of the deep branch
 * only discoverable by resolving the one above it.
 */
const deepChainZone: MockZone = {
  'example.com': {
    TXT: [
      'v=spf1 include:mail.vendor-a.example include:_spf.vendor-b.example ' +
        'include:example.com.k1.spf.vendor-c.example include:vendor-d.example ~all',
    ],
  },
  'mail.vendor-a.example': { TXT: ['v=spf1 ip4:192.0.2.0/24 ~all'] },
  '_spf.vendor-b.example': { TXT: ['v=spf1 ip4:198.51.100.0/24 ~all'] },
  'example.com.k1.spf.vendor-c.example': {
    TXT: ['v=spf1 ip4:203.0.113.0/24 include:p1.example.com.k1.spf.vendor-c.example ~all'],
  },
  'p1.example.com.k1.spf.vendor-c.example': {
    TXT: ['v=spf1 ip4:203.0.113.1/32 include:p2.example.com.k1.spf.vendor-c.example ~all'],
  },
  'p2.example.com.k1.spf.vendor-c.example': {
    TXT: ['v=spf1 ip4:203.0.113.2/32 include:p3.example.com.k1.spf.vendor-c.example ~all'],
  },
  'p3.example.com.k1.spf.vendor-c.example': {
    TXT: ['v=spf1 ip4:203.0.113.3/32 ~all'],
  },
  'vendor-d.example': { TXT: ['v=spf1 include:_spf.vendor-d.example ~all'] },
  '_spf.vendor-d.example': {
    TXT: ['v=spf1 include:_spf1.vendor-d.example include:_spf2.vendor-d.example ~all'],
  },
  '_spf1.vendor-d.example': { TXT: ['v=spf1 ip4:209.0.113.0/24 ~all'] },
  '_spf2.vendor-d.example': { TXT: ['v=spf1 ip4:210.0.113.0/24 ~all'] },
};

/** Every node in the chain, depth first, as [status, domain]. */
function chainStatuses(node: SpfChainNode, out: Array<[string, string]> = []) {
  out.push([node.status, node.domain]);
  for (const child of node.children) chainStatuses(child, out);
  return out;
}

describe('SPF — walking a wide, deep chain', () => {
  it('counts every lookup in it', async () => {
    const { analysis, codes } = await run(deepChainZone);

    expect(analysis.lookupCount).toBe(10);
    expect(analysis.lookupCountExact).toBe(true);
    expect(chainStatuses(analysis.chain!).every(([status]) => status === 'OK')).toBe(true);
    expect(codes).toContain('SPF_LOOKUP_APPROACHING_LIMIT');
  });

  it('keeps the children in the order the record lists them', async () => {
    // The tree on screen has to read in record order, not in the order the
    // network happened to answer. Walking siblings concurrently makes that a
    // property worth asserting rather than one that falls out of the loop.
    const { analysis } = await run(deepChainZone);

    expect(analysis.chain?.children.map((child) => child.domain)).toEqual([
      'mail.vendor-a.example',
      '_spf.vendor-b.example',
      'example.com.k1.spf.vendor-c.example',
      'vendor-d.example',
    ]);
  });

  it('walks independent branches at the same time', async () => {
    // Serial evaluation made this chain thirteen round trips in series, which
    // on the real domain measured over three seconds and left the engine still
    // running long after the other nine had finished. Nothing in one include
    // can change another's result, so nothing required them to be serial.
    let inFlight = 0;
    let peak = 0;
    const mock = createMockDoh(deepChainZone);
    const resolver = new DohResolver({
      fetchImpl: async (url, init) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        try {
          await Promise.resolve();
          return await mock.fetch(url, init);
        } finally {
          inFlight -= 1;
        }
      },
      timeoutMs: 50,
    });

    await analyzeSpf('example.com', resolver, { verifyApex: false });
    expect(peak).toBeGreaterThan(1);
  });
});

describe('SPF — when a lookup fails on our side', () => {
  /** What a Worker does past its subrequest ceiling: fetch throws outright. */
  const failAfter = (n: number): MockDohOptions => {
    let seen = 0;
    return { fail: () => (++seen > n ? 'NETWORK' : undefined) };
  };

  it('reports the incomplete chain once, not once per name', async () => {
    const { analysis, codes } = await run(deepChainZone, { mock: failAfter(3) });

    // Several names went unanswered.
    const unresolved = chainStatuses(analysis.chain!).filter(([s]) => s === 'UNRESOLVED');
    expect(unresolved.length).toBeGreaterThan(1);

    // One card about it. This used to be one per name, so a bad minute on our
    // side put four or five alarming findings on somebody's chart, each naming
    // a hostname belonging to their vendor.
    expect(codes.filter((code) => code === 'RESOLVER_TIMEOUT')).toHaveLength(1);
  });

  it('names the domain being examined, never the vendor host that failed', async () => {
    const { analysis } = await run(deepChainZone, { mock: failAfter(3) });
    const note = analysis.conditions.find((c) => c.code === 'RESOLVER_TIMEOUT');

    expect(note?.vars).toMatchObject({ domain: 'example.com', record: 'SPF' });
  });

  it('says the count is a floor rather than a total', async () => {
    const { analysis } = await run(deepChainZone, { mock: failAfter(3) });
    expect(analysis.lookupCountExact).toBe(false);
    expect(analysis.notes).toContain('RESOLVER_ERROR');
  });

  it('does not call a partial count close to the limit', async () => {
    // A floor of nine could be nine or could be twenty. Telling somebody they
    // are approaching a limit they may already be past is worse than silence,
    // and the summary renders the count as `9+` either way.
    const { analysis, codes } = await run(deepChainZone, { mock: failAfter(3) });

    expect(analysis.lookupCountExact).toBe(false);
    expect(codes).not.toContain('SPF_LOOKUP_APPROACHING_LIMIT');
  });

  it('still reports a limit already exceeded, because that stays true', async () => {
    // Over ten is over ten however much of the rest of the chain went unread.
    const overZone: MockZone = {
      'example.com': {
        TXT: [
          'v=spf1 a mx include:a.example include:b.example include:c.example ' +
            'include:d.example include:e.example include:f.example include:g.example ' +
            'include:h.example include:i.example ~all',
        ],
      },
      'a.example': { TXT: ['v=spf1 ip4:192.0.2.1/32 ~all'] },
    };
    const { analysis, codes } = await run(overZone, { mock: failAfter(2) });

    expect(analysis.lookupCount).toBeGreaterThan(10);
    expect(analysis.lookupCountExact).toBe(false);
    expect(codes).toContain('SPF_LOOKUP_LIMIT_EXCEEDED');
  });
});

describe('SPF — what the analysis reports about its own cost', () => {
  it('counts its own queries, not everything the shared resolver did', async () => {
    // One resolver serves ten engines at once, so a delta on its counter
    // measured whatever the other nine did while this one was walking. A
    // fourteen-lookup domain reported twenty-nine.
    const mock = createMockDoh(deepChainZone);
    const resolver = new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 50 });

    // Something else on the same resolver, before and during.
    await resolver.query('unrelated.example', 'A');
    const analysis = await analyzeSpf('example.com', resolver, { verifyApex: false });
    await resolver.query('another.example', 'A');

    expect(analysis.queriesUsed).toBe(11);
    expect(resolver.queriesIssued).toBeGreaterThan(analysis.queriesUsed);
  });
});

describe('SPF — the chain gets the budget it needs', () => {
  /**
   * The failure this reserve exists for.
   *
   * Ten engines share one resolver and the budget used to be
   * first-come-first-served, which quietly meant last-served-loses. Nine of
   * them are shallow and spend their queries at once; the SPF walk discovers
   * its names one hop at a time and is still asking long after the others have
   * finished. So the deepest chains — the ones most likely to be broken, since
   * depth is what breaks them — were the ones that could not be read, and the
   * customer got a tree ending in "we stopped walking here" three names in.
   *
   * `spend` here is those other nine: it takes the budget down to almost
   * nothing before the walk gets going.
   */
  async function walkUnderPressure(reserve: number, spend: number) {
    const mock = createMockDoh(deepChainZone);
    const resolver = new DohResolver({
      fetchImpl: mock.fetch,
      timeoutMs: 50,
      budget: 30,
      ...(reserve ? { reserve } : {}),
    });

    for (let i = 0; i < spend; i += 1) {
      await resolver.query(`filler-${i}.example`, 'A');
    }

    const analysis = await analyzeSpf('example.com', resolver, { verifyApex: false });
    return {
      analysis,
      truncated: chainStatuses(analysis.chain!).filter(([status]) => status === 'TRUNCATED'),
    };
  }

  it('walks to the last include even when everything else got there first', async () => {
    const { analysis, truncated } = await walkUnderPressure(22, 22);

    expect(truncated).toEqual([]);
    expect(analysis.lookupCountExact).toBe(true);
    expect(analysis.lookupCount).toBe(10);

    // The deepest name in the vendor's chain, four hops down, actually read.
    const deepest = chainStatuses(analysis.chain!).map(([, domain]) => domain);
    expect(deepest).toContain('p3.example.com.k1.spf.vendor-c.example');
  });

  it('is the reserve doing it, not luck', async () => {
    // Same pressure, same budget, no reserve: this is what shipped, and it is
    // exactly the report — the walk stops part way down and the count is a
    // floor rather than a total.
    const { analysis, truncated } = await walkUnderPressure(0, 22);

    expect(truncated.length).toBeGreaterThan(0);
    expect(analysis.lookupCountExact).toBe(false);
  });

  it('says so on the chart when it does have to stop', async () => {
    // "We stopped walking here" appeared in the tree with no card next to it
    // explaining why, so the one thing the reader could see was the one thing
    // nothing accounted for.
    const { analysis } = await walkUnderPressure(0, 22);
    const codes = analysis.conditions.map((c) => c.code);

    expect(codes.filter((code) => code === 'RESOLVER_TIMEOUT')).toHaveLength(1);
  });

  it('does not let an ordinary caller poison a name the walk still needs', async () => {
    // One shallow engine asking for a name a moment too late used to memoise
    // the refusal, and the chain walk — entitled to the reserve — was handed
    // that refusal instead of a lookup.
    const mock = createMockDoh(deepChainZone);
    const resolver = new DohResolver({
      fetchImpl: mock.fetch,
      timeoutMs: 50,
      budget: 30,
      reserve: 22,
    });

    for (let i = 0; i < 22; i += 1) await resolver.query(`filler-${i}.example`, 'A');

    // Ordinary work is out of budget and gets turned away.
    const refused = await resolver.query('vendor-d.example', 'TXT');
    expect(refused.notes).toContain('BUDGET_EXCEEDED');

    // The walk asks for the same name and gets a real answer.
    const answered = await resolver.query('vendor-d.example', 'TXT', { essential: true });
    expect(answered.notes).not.toContain('BUDGET_EXCEEDED');
    expect(answered.txt[0]?.value).toContain('v=spf1');
  });
});

describe('SPF — the walk goes to the end of the chain', () => {
  /** A linear chain `n` hops deep, each hop only findable from the one above. */
  function linearChain(depth: number): MockZone {
    const zone: MockZone = {
      'example.com': { TXT: ['v=spf1 include:hop1.vendor.example ~all'] },
    };
    for (let i = 1; i <= depth; i += 1) {
      zone[`hop${i}.vendor.example`] = {
        TXT: [
          i === depth
            ? `v=spf1 ip4:203.0.113.${i}/32 ~all`
            : `v=spf1 ip4:203.0.113.${i}/32 include:hop${i + 1}.vendor.example ~all`,
        ],
      };
    }
    return zone;
  }

  /** Every domain in the tree, in the order the tree lists them. */
  function chainDomains(node: SpfChainNode, out: string[] = []) {
    out.push(node.domain);
    for (const child of node.children) chainDomains(child, out);
    return out;
  }

  it('reads every hop of a chain forty-five deep', async () => {
    // The standalone chain endpoint spends SPF_DEEP_WALK_BUDGET on nothing but
    // this, so the walk has to be able to use all of it. Forty-five hops is
    // nine times the deepest chain a real SPF vendor publishes and one short of
    // the budget, which is where the honest limit is.
    const deep = await run(linearChain(45), { budget: SPF_DEEP_WALK_BUDGET });
    const names = chainDomains(deep.analysis.chain!);

    expect(names).toHaveLength(46);
    expect(names.at(-1)).toBe('hop45.vendor.example');
    expect(deep.analysis.lookupCountExact).toBe(true);
    expect(deep.analysis.chain!.children[0]).toBeDefined();
  });

  it('reads all twenty-five hops of a chain twenty-five deep', async () => {
    // Twice the depth the old guard allowed, and five times the deepest chain
    // a real SPF vendor publishes. Nothing in the walk stops before the record
    // does.
    const { analysis, codes } = await run(linearChain(25), { budget: 60 });

    const domains = chainDomains(analysis.chain!);
    expect(domains).toHaveLength(26);
    expect(domains.at(-1)).toBe('hop25.vendor.example');
    expect(analysis.lookupCountExact).toBe(true);
    expect(analysis.lookupCount).toBe(25);
    expect(codes).toContain('SPF_LOOKUP_LIMIT_EXCEEDED');
  });

  it('keeps the record at every hop, so the tree can show it', async () => {
    const { analysis } = await run(linearChain(25), { budget: 60 });

    let node = analysis.chain!;
    for (let i = 1; i <= 25; i += 1) {
      node = node.children[0]!;
      expect(node.domain).toBe(`hop${i}.vendor.example`);
      expect(node.record).toContain(`ip4:203.0.113.${i}/32`);
    }
    expect(node.children).toEqual([]);
  });

  it('still refuses to loop', async () => {
    // Depth is not what catches a loop, the ancestor path is, and raising the
    // depth guard must not have quietly made a circular record walk forever.
    const looping: MockZone = {
      'example.com': { TXT: ['v=spf1 include:a.example ~all'] },
      'a.example': { TXT: ['v=spf1 include:b.example ~all'] },
      'b.example': { TXT: ['v=spf1 include:a.example ~all'] },
    };
    const { analysis, codes } = await run(looping);

    expect(codes).toContain('SPF_CIRCULAR_INCLUDE');
    expect(chainDomains(analysis.chain!).length).toBeLessThan(10);
  });

  it('is the query budget that bounds a walk now, and it says so', async () => {
    // The honest limit. A chain deeper than the budget can reach is reported
    // as incomplete with a floor for a count, never as a finished tree.
    const { analysis, codes } = await run(linearChain(25), { budget: 12 });

    expect(analysis.lookupCountExact).toBe(false);
    expect(codes.filter((code) => code === 'RESOLVER_TIMEOUT')).toHaveLength(1);
  });
});
