import { describe, expect, it } from 'vitest';
import { classifyIp, expandIpv6, reverseName } from '../src/ip.js';

describe('classifyIp', () => {
  it.each([
    ['209.85.220.41', 'public'],
    ['10.0.0.1', 'private'],
    ['172.16.4.4', 'private'],
    ['172.32.4.4', 'public'],
    ['192.168.1.1', 'private'],
    ['100.64.0.1', 'private'],
    ['127.0.0.1', 'loopback'],
    ['169.254.1.1', 'linklocal'],
    ['192.0.2.50', 'documentation'],
    ['198.51.100.42', 'documentation'],
    ['203.0.113.99', 'documentation'],
    ['2a01:111:f400:7e1a::711', 'public'],
    ['fd00::1', 'private'],
    ['fe80::1', 'linklocal'],
    ['::1', 'loopback'],
    ['2001:db8::1', 'documentation'],
    ['999.1.1.1', 'invalid'],
    ['', 'invalid'],
  ])('reads %s as %s', (ip, kind) => {
    expect(classifyIp(ip)).toBe(kind);
  });
});

describe('expandIpv6', () => {
  it('fills in the elided groups', () => {
    expect(expandIpv6('2001:db8::1')).toEqual([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
    expect(expandIpv6('::')).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('reads the IPv4-mapped form', () => {
    expect(expandIpv6('::ffff:192.0.2.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201]);
  });

  it('rejects nonsense', () => {
    expect(expandIpv6('1::2::3')).toBeNull();
    expect(expandIpv6('gggg::1')).toBeNull();
    expect(expandIpv6('1:2:3')).toBeNull();
  });
});

describe('reverseName', () => {
  it('builds the in-addr.arpa name', () => {
    expect(reverseName('209.85.220.41')).toBe('41.220.85.209.in-addr.arpa');
  });

  it('builds the ip6.arpa name, one nibble at a time', () => {
    expect(reverseName('2001:db8::1')).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
    );
  });

  it('returns null rather than a bad query', () => {
    expect(reverseName('not-an-ip')).toBeNull();
    expect(reverseName('')).toBeNull();
  });
});
