import { describe, expect, it } from 'vitest';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockZone } from '@maildoc/resolver/testing';
import { analyzeAddresses, analyzeDnssec, analyzeMx } from '../src/index.js';

const resolverFor = (zone: MockZone, options: Parameters<typeof createMockDoh>[1] = {}) => {
  const mock = createMockDoh(zone, options);
  return {
    mock,
    resolver: new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 20, budget: 40 }),
  };
};

describe('MX', () => {
  it('reads mail exchangers with their priorities', async () => {
    const { resolver } = resolverFor({
      'example.com': { MX: ['10 mail1.example.com.', '20 mail2.example.com.'] },
      'mail1.example.com': { A: ['203.0.113.1'] },
      'mail2.example.com': { A: ['203.0.113.2'] },
    });
    const analysis = await analyzeMx('example.com', resolver);

    expect(analysis.found).toBe(true);
    expect(analysis.hosts.map((h) => h.host)).toEqual(['mail1.example.com', 'mail2.example.com']);
    expect(analysis.hosts[0]?.priority).toBe(10);
    expect(analysis.hosts[0]?.addresses).toEqual(['203.0.113.1']);
    expect(analysis.conditions.map((c) => c.code)).toEqual([]);
  });

  it('reports a domain with no mail exchangers', async () => {
    const { resolver } = resolverFor({ 'example.com': { A: ['203.0.113.1'] } });
    const analysis = await analyzeMx('example.com', resolver);
    expect(analysis.conditions.map((c) => c.code)).toEqual(['MX_MISSING']);
  });

  it('treats a null MX as a deliberate statement, not a fault', async () => {
    const { resolver } = resolverFor({ 'example.com': { MX: ['0 .'] } });
    const analysis = await analyzeMx('example.com', resolver);

    expect(analysis.acceptsNoMail).toBe(true);
    expect(analysis.conditions.map((c) => c.code)).toEqual(['MX_NULL']);
    expect(analysis.status).toBe('HEALTHY');
  });

  it('flags an MX that points at an IP address', async () => {
    const { resolver } = resolverFor({ 'example.com': { MX: ['10 203.0.113.1'] } });
    const analysis = await analyzeMx('example.com', resolver);
    expect(analysis.conditions.map((c) => c.code)).toContain('MX_POINTS_TO_IP');
  });

  it('flags a mail exchanger with no address', async () => {
    const { resolver } = resolverFor({
      'example.com': { MX: ['10 ghost.example.com.', '20 mail.example.com.'] },
      'ghost.example.com': { TXT: ['x'] },
      'mail.example.com': { A: ['203.0.113.2'] },
    });
    const analysis = await analyzeMx('example.com', resolver);
    expect(analysis.conditions.map((c) => c.code)).toContain('MX_TARGET_NO_ADDRESS');
  });

  it('leaves equal priorities alone and flags a lone exchanger', async () => {
    // Two hosts at the same priority is load balancing, which is how nearly
    // every mail provider publishes. It is not a fault and must not score.
    const { resolver } = resolverFor({
      'example.com': { MX: ['10 a.example.com.', '10 b.example.com.'] },
      'a.example.com': { A: ['203.0.113.1'] },
      'b.example.com': { A: ['203.0.113.2'] },
    });
    const analysis = await analyzeMx('example.com', resolver);
    expect(analysis.conditions.map((c) => c.code)).toEqual([]);

    const { resolver: single } = resolverFor({
      'example.com': { MX: ['10 a.example.com.'] },
      'a.example.com': { A: ['203.0.113.1'] },
    });
    const one = await analyzeMx('example.com', single);
    expect(one.conditions.map((c) => c.code)).toContain('MX_SINGLE_POINT_OF_FAILURE');
  });

  it('does not call one MX name backed by several addresses a weak point', async () => {
    // How Google and GitHub publish: one hostname, many machines behind it.
    const { resolver } = resolverFor({
      'example.com': { MX: ['10 smtp.example.com.'] },
      'smtp.example.com': { A: ['203.0.113.1', '203.0.113.2', '203.0.113.3'] },
    });
    const analysis = await analyzeMx('example.com', resolver);
    expect(analysis.conditions.map((c) => c.code)).not.toContain('MX_SINGLE_POINT_OF_FAILURE');
  });

  it('reports a timeout rather than claiming there is no mail server', async () => {
    const { resolver } = resolverFor({ 'example.com': { MX: ['10 a.example.com.'] } }, {
      fail: () => 'TIMEOUT',
    });
    const analysis = await analyzeMx('example.com', resolver);
    const codes = analysis.conditions.map((c) => c.code);
    expect(codes).toEqual(['RESOLVER_TIMEOUT']);
    expect(codes).not.toContain('MX_MISSING');
  });
});

describe('A / AAAA', () => {
  it('reports both families when present', async () => {
    const { resolver } = resolverFor({
      'example.com': { A: ['203.0.113.1'], AAAA: ['2001:db8::1'] },
    });
    const analysis = await analyzeAddresses('example.com', resolver);

    expect(analysis.ipv4).toEqual(['203.0.113.1']);
    expect(analysis.ipv6).toEqual(['2001:db8::1']);
    expect(analysis.conditions.map((c) => c.code)).toEqual([]);
  });

  it('says nothing about a missing AAAA, which does not affect mail', async () => {
    const { resolver } = resolverFor({ 'example.com': { A: ['203.0.113.1'] } });
    const analysis = await analyzeAddresses('example.com', resolver);

    expect(analysis.conditions.map((c) => c.code)).toEqual([]);
    expect(analysis.status).toBe('HEALTHY');
    expect(analysis.ipv4).toEqual(['203.0.113.1']);
  });

  it('says nothing about a domain with no address record at all', async () => {
    // A mail-only domain is a normal thing to own.
    const { resolver } = resolverFor({ 'example.com': { MX: ['10 a.example.com.'] } });
    const analysis = await analyzeAddresses('example.com', resolver);

    expect(analysis.conditions.map((c) => c.code)).toEqual([]);
    expect(analysis.status).toBe('HEALTHY');
  });

  it('flags a private address in public DNS', async () => {
    const { resolver } = resolverFor({
      'example.com': { A: ['192.168.1.10'], AAAA: ['2001:db8::1'] },
    });
    const analysis = await analyzeAddresses('example.com', resolver);
    expect(analysis.conditions.map((c) => c.code)).toContain('A_PRIVATE_IP');
  });

});

describe('DNSSEC', () => {
  it('is healthy when the zone is signed and the resolver validated it', async () => {
    const { resolver } = resolverFor({
      'example.com': { DNSKEY: { data: ['257 3 13 abc'], ad: true } },
    });
    const analysis = await analyzeDnssec('example.com', resolver);

    expect(analysis.authenticated).toBe(true);
    expect(analysis.signed).toBe(true);
    expect(analysis.conditions).toEqual([]);
  });

  it('reports an unsigned zone as a minor condition', async () => {
    const { resolver } = resolverFor({ 'example.com': { A: ['203.0.113.1'] } });
    const analysis = await analyzeDnssec('example.com', resolver);

    expect(analysis.signed).toBe(false);
    expect(analysis.conditions.map((c) => c.code)).toEqual(['DNSSEC_UNSIGNED']);
    expect(analysis.conditions[0]?.severity).toBe('LOW');
  });

  it('catches keys published with no DS at the parent', async () => {
    const { resolver } = resolverFor({
      'example.com': { DNSKEY: { data: ['257 3 13 abc'], ad: false } },
    });
    const analysis = await analyzeDnssec('example.com', resolver);

    expect(analysis.conditions.map((c) => c.code)).toEqual(['DNSSEC_DS_MISSING']);
    expect(analysis.hasDelegationSigner).toBe(false);
  });

  it('calls a signed zone with a DS that does not validate bogus', async () => {
    const { resolver } = resolverFor({
      'example.com': {
        DNSKEY: { data: ['257 3 13 abc'], ad: false },
        DS: { data: ['12345 13 2 abcdef'] },
      },
    });
    const analysis = await analyzeDnssec('example.com', resolver);

    expect(analysis.conditions.map((c) => c.code)).toEqual(['DNSSEC_BOGUS']);
    expect(analysis.conditions[0]?.severity).toBe('CRITICAL');
  });
});
