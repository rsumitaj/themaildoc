import { describe, expect, it } from 'vitest';
import { bigIntToIpv6, intToIpv4, ipv4ToInt, ipv6ToBigInt, mergeIpv4, mergeIpv6 } from '../src/index.js';

describe('ipv4 conversion', () => {
  it('round-trips', () => {
    expect(ipv4ToInt('192.0.2.1')).toBe(3221225985);
    expect(intToIpv4(3221225985)).toBe('192.0.2.1');
    expect(ipv4ToInt('255.255.255.255')).toBe(4294967295);
  });

  it('rejects what is not an address', () => {
    expect(ipv4ToInt('192.0.2')).toBeNull();
    expect(ipv4ToInt('192.0.2.256')).toBeNull();
    expect(ipv4ToInt('192.0.02.1')).toBeNull(); // leading zero
    expect(ipv4ToInt('')).toBeNull();
  });
});

describe('mergeIpv4', () => {
  it('leaves a single address alone', () => {
    expect(mergeIpv4(['192.0.2.1'])).toEqual(['192.0.2.1']);
  });

  it('collapses a full sibling pair into one block', () => {
    expect(mergeIpv4(['192.0.2.0', '192.0.2.1'])).toEqual(['192.0.2.0/31']);
  });

  it('collapses 256 addresses into a /24', () => {
    const all = Array.from({ length: 256 }, (_, index) => `192.0.2.${index}`);
    expect(mergeIpv4(all)).toEqual(['192.0.2.0/24']);
  });

  it('never widens a range to make it tidier', () => {
    // .1 and .2 are adjacent but not siblings: a /31 at .1 does not exist and
    // a /30 would also authorise .0 and .3. They stay two separate entries.
    expect(mergeIpv4(['192.0.2.1', '192.0.2.2'])).toEqual(['192.0.2.1', '192.0.2.2']);
  });

  it('absorbs an address already inside a block', () => {
    expect(mergeIpv4(['10.0.0.0/8', '10.1.2.3'])).toEqual(['10.0.0.0/8']);
  });

  it('joins two adjacent blocks', () => {
    expect(mergeIpv4(['192.0.2.0/25', '192.0.2.128/25'])).toEqual(['192.0.2.0/24']);
  });

  it('keeps blocks that merely touch nothing', () => {
    expect(mergeIpv4(['192.0.2.0/24', '198.51.100.0/24'])).toEqual([
      '192.0.2.0/24',
      '198.51.100.0/24',
    ]);
  });

  it('deduplicates', () => {
    expect(mergeIpv4(['1.2.3.4', '1.2.3.4', '1.2.3.4'])).toEqual(['1.2.3.4']);
  });

  it('normalises a host address written with a prefix', () => {
    expect(mergeIpv4(['192.0.2.130/24'])).toEqual(['192.0.2.0/24']);
  });

  it('drops what it cannot parse rather than guessing', () => {
    expect(mergeIpv4(['not-an-ip', '192.0.2.1', '1.2.3.4/33'])).toEqual(['192.0.2.1']);
  });
});

describe('ipv6 conversion', () => {
  it('round-trips and compresses per RFC 5952', () => {
    expect(bigIntToIpv6(ipv6ToBigInt('2001:db8::1') as bigint)).toBe('2001:db8::1');
    expect(bigIntToIpv6(ipv6ToBigInt('::') as bigint)).toBe('::');
    expect(bigIntToIpv6(ipv6ToBigInt('2001:4860:4000:0:0:0:0:0') as bigint)).toBe('2001:4860:4000::');
  });

  it('reads the IPv4-mapped form', () => {
    expect(ipv6ToBigInt('::ffff:192.0.2.1')).toBe(ipv6ToBigInt('::ffff:c000:201'));
  });

  it('rejects nonsense', () => {
    expect(ipv6ToBigInt('1::2::3')).toBeNull();
    expect(ipv6ToBigInt('gggg::')).toBeNull();
    expect(ipv6ToBigInt('1:2:3')).toBeNull();
  });
});

describe('mergeIpv6', () => {
  it('collapses siblings', () => {
    expect(mergeIpv6(['2001:db8::', '2001:db8::1'])).toEqual(['2001:db8::/127']);
  });

  it('absorbs an address inside a published block', () => {
    expect(mergeIpv6(['2001:4860:4000::/36', '2001:4860:4000::1'])).toEqual([
      '2001:4860:4000::/36',
    ]);
  });

  it('keeps distinct provider ranges apart', () => {
    expect(mergeIpv6(['2001:4860:4000::/36', '2404:6800:4000::/36'])).toEqual([
      '2001:4860:4000::/36',
      '2404:6800:4000::/36',
    ]);
  });
});
