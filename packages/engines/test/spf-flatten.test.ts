import { describe, expect, it } from 'vitest';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockZone } from '@maildoc/resolver/testing';
import { byteLength, flattenSpf, splitForTxt, TXT_STRING_MAX } from '../src/index.js';

async function flatten(zone: MockZone, domain = 'example.com', budget = 60) {
  const mock = createMockDoh(zone);
  const resolver = new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 20, budget });
  const result = await flattenSpf(domain, resolver);
  return { result, mock };
}

/** A record over the limit: five includes, each with its own senders. */
const OVER_LIMIT: MockZone = {
  'example.com': { TXT: ['v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com a mx ~all'] },
  '_spf.google.com': {
    TXT: ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all'],
  },
  '_netblocks.google.com': { TXT: ['v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all'] },
  '_netblocks2.google.com': { TXT: ['v=spf1 ip6:2001:4860:4000::/36 ~all'] },
  'sendgrid.net': { TXT: ['v=spf1 ip4:167.89.0.0/17 ip4:168.245.0.0/17 ~all'] },
  'mail.zendesk.com': { TXT: ['v=spf1 ip4:192.161.144.0/20 ~all'] },
  // `a` and `mx` on the apex.
  'mail.example.com': { A: ['203.0.113.10'], AAAA: ['2001:db8::10'] },
};

const WITH_MX: MockZone = {
  ...OVER_LIMIT,
  'example.com': {
    ...OVER_LIMIT['example.com'],
    A: ['198.51.100.5'],
    MX: ['10 mail.example.com.'],
  },
};

describe('flattenSpf', () => {
  it('folds every include into addresses and drops the lookups', async () => {
    const { result } = await flatten(WITH_MX);

    expect(result.complete).toBe(true);
    expect(result.lookupsBefore).toBeGreaterThan(5);
    expect(result.lookupsAfter).toBe(0);
    expect(result.flattened).toContain('v=spf1');
    expect(result.flattened).not.toContain('include:');
    expect(result.flattened).toContain('~all');
  });

  it('carries every source address through', async () => {
    const { result } = await flatten(WITH_MX);

    // Google, SendGrid, Zendesk, the apex A and the MX host.
    expect(result.ipv4).toContain('35.190.247.0/24');
    expect(result.ipv4).toContain('167.89.0.0/17');
    expect(result.ipv4).toContain('192.161.144.0/20');
    expect(result.ipv4).toContain('198.51.100.5');
    expect(result.ipv4).toContain('203.0.113.10');
    expect(result.ipv6).toContain('2001:4860:4000::/36');
    expect(result.ipv6).toContain('2001:db8::10');
  });

  it('reports which source each address came from', async () => {
    const { result } = await flatten(WITH_MX);
    const terms = result.expanded.map((entry) => entry.term);

    expect(terms).toContain('include:_spf.google.com');
    expect(terms).toContain('include:sendgrid.net');
    expect(terms).toContain('mx');
    expect(result.expanded.find((e) => e.term === 'include:sendgrid.net')?.ipv4).toBe(2);
  });

  it('keeps the all qualifier exactly as published', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 include:one.example -all'] },
      'one.example': { TXT: ['v=spf1 ip4:192.0.2.1 -all'] },
    });

    expect(result.allTerm).toBe('-all');
    expect(result.flattened?.endsWith('-all')).toBe(true);
  });

  it('preserves exists and ptr rather than pretending to flatten them', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 ip4:192.0.2.1 exists:%{i}.spf.example.com ptr ~all'] },
    });

    const reasons = Object.fromEntries(result.preserved.map((p) => [p.term, p.reason]));
    expect(reasons['exists:%{i}.spf.example.com']).toBe('MACRO');
    expect(reasons['ptr']).toBe('PER_MESSAGE');
    // They still cost a lookup each, and the count says so.
    expect(result.lookupsAfter).toBe(2);
    expect(result.flattened).toContain('ptr');
  });

  it('preserves an include containing a macro', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 include:%{d}.spf.example.com ~all'] },
    });

    expect(result.preserved[0]).toEqual({
      term: 'include:%{d}.spf.example.com',
      reason: 'MACRO',
    });
  });

  it('follows redirect and takes its terms as its own', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 redirect=_spf.example.net'] },
      '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] },
    });

    expect(result.ipv4).toEqual(['192.0.2.0/24']);
    expect(result.flattened).not.toContain('redirect=');
  });

  it('refuses to publish when an include did not resolve', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 include:gone.example include:one.example ~all'] },
      'one.example': { TXT: ['v=spf1 ip4:192.0.2.1 ~all'] },
      // gone.example is absent: NXDOMAIN.
    });

    expect(result.complete).toBe(false);
    expect(result.flattened).toBeNull();
    expect(result.notes).toContain('PARTIAL');
    expect(result.preserved).toContainEqual({ term: 'include:gone.example', reason: 'UNRESOLVED' });
  });

  it('carries a mechanism CIDR onto every address it resolved', async () => {
    // a:mail.example.com/24 authorises the /24 around the address, not the
    // address alone. Dropping the prefix would narrow the record.
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 a:mail.example.com/24 -all'] },
      'mail.example.com': { A: ['203.0.113.10'] },
    });

    expect(result.ipv4).toEqual(['203.0.113.0/24']);
  });

  it('merges overlapping ranges from different providers', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 include:one.example include:two.example -all'] },
      'one.example': { TXT: ['v=spf1 ip4:192.0.2.0/25 -all'] },
      'two.example': { TXT: ['v=spf1 ip4:192.0.2.128/25 -all'] },
    });

    expect(result.ipv4).toEqual(['192.0.2.0/24']);
  });

  it('says so when the domain publishes no SPF at all', async () => {
    const { result } = await flatten({ 'example.com': { A: ['192.0.2.1'] } });

    expect(result.notes).toContain('NO_RECORD');
    expect(result.flattened).toBeNull();
  });

  it('does not claim to have shrunk a record that needs no flattening', async () => {
    const { result } = await flatten({
      'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] },
    });

    expect(result.lookupsBefore).toBe(0);
    expect(result.notes).toContain('ALREADY_SMALL');
  });

  it('reports the size of what it produced', async () => {
    const { result } = await flatten(WITH_MX);
    expect(result.bytesBefore).toBe(byteLength(result.original as string));
    expect(result.bytesAfter).toBe(byteLength(result.flattened as string));
  });

  it('stops rather than half-flattening when the budget runs out', async () => {
    const { result } = await flatten(WITH_MX, 'example.com', 4);

    expect(result.complete).toBe(false);
    expect(result.flattened).toBeNull();
    expect(result.preserved.some((p) => p.reason === 'BUDGET')).toBe(true);
  });
});

describe('splitForTxt', () => {
  it('leaves a short record as one string', () => {
    expect(splitForTxt('v=spf1 ip4:192.0.2.1 -all')).toEqual(['v=spf1 ip4:192.0.2.1 -all']);
  });

  it('splits a long record without breaking a term', () => {
    const record = `v=spf1 ${Array.from({ length: 40 }, (_, i) => `ip4:192.0.${i}.0/24`).join(' ')} -all`;
    const strings = splitForTxt(record);

    expect(strings.length).toBeGreaterThan(1);
    for (const string of strings) expect(byteLength(string)).toBeLessThanOrEqual(TXT_STRING_MAX);
    // A receiver concatenates with nothing between, so this must rebuild exactly.
    expect(strings.join('')).toBe(record);
    for (const string of strings) expect(string).not.toMatch(/ip4:\d+\.\d+\.\d+$/);
  });
});
