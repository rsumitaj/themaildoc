import { describe, expect, it } from 'vitest';
import {
  isSpfRecord,
  isValidIpv4,
  isValidIpv6,
  isValidMacroString,
  isValidPrefix,
  isPrivateIpv4,
  isPrivateIpv6,
  looksLikeBrokenSpf,
  parseSpf,
  type SpfMechanism,
  type SpfModifier,
} from '../src/index.js';

const mechanisms = (record: string) =>
  parseSpf(record).terms.filter((t): t is SpfMechanism => t.kind === 'mechanism');

describe('isSpfRecord', () => {
  it.each([
    ['v=spf1 -all', true],
    ['V=SPF1 -all', true],
    ['v=spf1', true],
    ['v=spf10 -all', false],
    ['v=DMARC1; p=none', false],
    ['google-site-verification=abc', false],
  ])('%j → %s', (value, expected) => {
    expect(isSpfRecord(value)).toBe(expected);
  });
});

describe('looksLikeBrokenSpf', () => {
  it('spots a record that means to be SPF but has the wrong version', () => {
    expect(looksLikeBrokenSpf('v=spf2 include:_spf.example.com -all')).toBe(true);
    expect(looksLikeBrokenSpf('spf1 include:_spf.example.com ~all')).toBe(true);
  });

  it('does not claim unrelated TXT records', () => {
    expect(looksLikeBrokenSpf('v=spf1 -all')).toBe(false);
    expect(looksLikeBrokenSpf('v=DMARC1; p=reject')).toBe(false);
    expect(looksLikeBrokenSpf('MS=ms12345678')).toBe(false);
    expect(looksLikeBrokenSpf('spf2.0/pra include:example.com')).toBe(false);
  });
});

describe('parseSpf', () => {
  it('parses qualifiers, defaulting to pass', () => {
    const [include, all] = mechanisms('v=spf1 include:_spf.example.com -all');
    expect(include?.name).toBe('include');
    expect(include?.qualifier).toBe('+');
    expect(include?.value).toBe('_spf.example.com');
    expect(all?.name).toBe('all');
    expect(all?.qualifier).toBe('-');
  });

  it.each(['+all', '-all', '~all', '?all'])('reads the %s qualifier', (term) => {
    expect(mechanisms(`v=spf1 ${term}`)[0]?.qualifier).toBe(term[0]);
  });

  it('splits ip4 addresses from their prefix', () => {
    const [ip] = mechanisms('v=spf1 ip4:203.0.113.0/24 -all');
    expect(ip?.value).toBe('203.0.113.0');
    expect(ip?.cidr4).toBe('24');
  });

  it('keeps IPv6 addresses with their colons intact', () => {
    const [ip] = mechanisms('v=spf1 ip6:2001:db8::/32 -all');
    expect(ip?.name).toBe('ip6');
    expect(ip?.value).toBe('2001:db8::');
    expect(ip?.cidr4).toBe('32');
  });

  it('parses dual-CIDR a and mx mechanisms', () => {
    const [bare, withDomain] = mechanisms('v=spf1 a/24//64 mx:mail.example.com/28 -all');
    expect(bare?.name).toBe('a');
    expect(bare?.value).toBeNull();
    expect(bare?.cidr4).toBe('24');
    expect(bare?.cidr6).toBe('64');
    expect(withDomain?.value).toBe('mail.example.com');
    expect(withDomain?.cidr4).toBe('28');
  });

  it('treats name=value as a modifier, not a mechanism', () => {
    const terms = parseSpf('v=spf1 redirect=_spf.example.com').terms;
    const modifier = terms[0] as SpfModifier;
    expect(modifier.kind).toBe('modifier');
    expect(modifier.name).toBe('redirect');
    expect(modifier.value).toBe('_spf.example.com');
  });

  it('keeps macro mechanisms whole', () => {
    const [exists] = mechanisms('v=spf1 exists:%{ir}.spam.example.com -all');
    expect(exists?.name).toBe('exists');
    expect(exists?.value).toBe('%{ir}.spam.example.com');
  });

  it('flags terms that are neither mechanism nor modifier', () => {
    const terms = parseSpf('v=spf1 example.com -all').terms;
    expect(terms[0]?.kind).toBe('unknown');
  });

  it('rejects a qualifier on a modifier', () => {
    expect(parseSpf('v=spf1 -redirect=example.com').terms[0]?.kind).toBe('unknown');
  });

  it('is case-insensitive about mechanism names', () => {
    expect(mechanisms('v=spf1 INCLUDE:example.com -ALL')[0]?.name).toBe('include');
  });
});

describe('IP validation', () => {
  it.each([
    ['203.0.113.1', true],
    ['0.0.0.0', true],
    ['255.255.255.255', true],
    ['256.0.0.1', false],
    ['192.168.01.1', false],
    ['203.0.113', false],
    ['203.0.113.1.5', false],
    ['not-an-ip', false],
  ])('ipv4 %j → %s', (value, expected) => {
    expect(isValidIpv4(value)).toBe(expected);
  });

  it.each([
    ['2001:db8::1', true],
    ['2001:0db8:0000:0000:0000:0000:0000:0001', true],
    ['::', true],
    ['::1', true],
    ['::ffff:203.0.113.1', true],
    ['2001:db8', false],
    ['2001:db8:::1', false],
    ['gggg::1', false],
    ['2001:db8::1::2', false],
  ])('ipv6 %j → %s', (value, expected) => {
    expect(isValidIpv6(value)).toBe(expected);
  });

  it.each([
    ['24', 32, true],
    ['32', 32, true],
    ['33', 32, false],
    ['128', 128, true],
    ['129', 128, false],
    ['08', 32, false],
  ])('prefix %j/%i → %s', (value, max, expected) => {
    expect(isValidPrefix(value, max)).toBe(expected);
  });

  it('recognises addresses that can never send public mail', () => {
    expect(isPrivateIpv4('10.0.0.1')).toBe(true);
    expect(isPrivateIpv4('192.168.1.1')).toBe(true);
    expect(isPrivateIpv4('172.16.0.1')).toBe(true);
    expect(isPrivateIpv4('172.32.0.1')).toBe(false);
    expect(isPrivateIpv4('127.0.0.1')).toBe(true);
    expect(isPrivateIpv4('169.254.1.1')).toBe(true);
    expect(isPrivateIpv4('100.64.0.1')).toBe(true);
    expect(isPrivateIpv6('fd00::1')).toBe(true);
    expect(isPrivateIpv6('fe80::1')).toBe(true);
    expect(isPrivateIpv6('2001:db8::1')).toBe(false);
  });

  it('leaves documentation ranges alone (they are used in every example)', () => {
    expect(isPrivateIpv4('203.0.113.1')).toBe(false);
    expect(isPrivateIpv4('198.51.100.1')).toBe(false);
  });
});

describe('macro validation', () => {
  it.each([
    ['%{i}.example.com', true],
    ['%{ir}.spam.example.com', true],
    ['%{d4}.example.com', true],
    ['%{s}%{d}', true],
    ['100%%.example.com', true],
    ['a%_b%-c', true],
    ['no-macros-here', true],
    ['%{}.example.com', false],
    ['%{z}.example.com', false],
    ['%{i.example.com', false],
    ['50%.example.com', false],
  ])('%j → %s', (value, expected) => {
    expect(isValidMacroString(value)).toBe(expected);
  });
});
