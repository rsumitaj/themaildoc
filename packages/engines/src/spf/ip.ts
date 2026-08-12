/**
 * IP validation for SPF mechanisms (RFC 7208 §5.6).
 * Deliberately strict: a receiver that can't parse `ip4:` treats the whole
 * record as a permanent error, so "close enough" is a wrong answer.
 */

const IPV4_OCTET = /^(0|[1-9]\d{0,2})$/;

export function isValidIpv4(value: string): boolean {
  const octets = value.split('.');
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    if (!IPV4_OCTET.test(octet)) return false; // rejects leading zeros
    const number = Number(octet);
    return number >= 0 && number <= 255;
  });
}

export function isValidIpv6(value: string): boolean {
  if (value.length === 0 || value.includes(':::')) return false;

  const doubleColons = value.split('::').length - 1;
  if (doubleColons > 1) return false;

  let head = value;
  let tail = '';
  if (doubleColons === 1) {
    const [before = '', after = ''] = value.split('::');
    head = before;
    tail = after;
  }

  const headGroups = head === '' ? [] : head.split(':');
  const tailGroups = tail === '' ? [] : tail.split(':');
  const groups = [...headGroups, ...tailGroups];
  if (groups.some((group) => group === '')) return false;

  // A trailing IPv4 literal (e.g. ::ffff:203.0.113.1) occupies two groups.
  let groupCount = groups.length;
  const last = groups[groups.length - 1];
  if (last !== undefined && last.includes('.')) {
    if (!isValidIpv4(last)) return false;
    groupCount += 1;
  }

  const hextets = last !== undefined && last.includes('.') ? groups.slice(0, -1) : groups;
  if (!hextets.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return false;

  return doubleColons === 1 ? groupCount <= 7 : groupCount === 8;
}

export function isValidPrefix(value: string, max: number): boolean {
  if (!/^\d{1,3}$/.test(value)) return false;
  if (value.length > 1 && value.startsWith('0')) return false;
  const prefix = Number(value);
  return prefix >= 0 && prefix <= max;
}

/**
 * Addresses that can never appear as a public mail source: RFC 1918 private
 * space, loopback, link-local, CGNAT, unspecified and reserved/multicast.
 *
 * Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
 * deliberately NOT flagged here — they are routable address space and would
 * otherwise fire on every example record.
 */
export function isPrivateIpv4(value: string): boolean {
  if (!isValidIpv4(value)) return false;
  const [a = 0, b = 0] = value.split('.').map(Number) as [number, number, number, number];

  if (a === 0) return true; // "this network"
  if (a === 10) return true;
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast + reserved
  return false;
}

export function isPrivateIpv6(value: string): boolean {
  if (!isValidIpv6(value)) return false;
  const address = value.toLowerCase();
  if (address === '::' || address === '::1') return true;
  if (/^f[cd][0-9a-f]{0,2}:/.test(address)) return true; // unique local fc00::/7
  if (/^fe[89ab][0-9a-f]?:/.test(address)) return true; // link-local fe80::/10
  return false;
}
