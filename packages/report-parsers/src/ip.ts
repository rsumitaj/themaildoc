/**
 * Just enough IP handling to say something true about a report's source
 * addresses. Aggregate reports carry a mix of IPv4 and IPv6, and a surprising
 * number of addresses that cannot possibly have sent internet mail.
 */

export type IpKind =
  | 'public'
  | 'private'
  | 'loopback'
  | 'linklocal'
  | 'documentation'
  | 'reserved'
  | 'invalid';

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpv6(ip: string): boolean {
  return ip.includes(':');
}

export function classifyIp(raw: string): IpKind {
  const ip = raw.trim().toLowerCase();
  if (!ip) return 'invalid';
  return isIpv6(ip) ? classifyIpv6(ip) : classifyIpv4(ip);
}

function classifyIpv4(ip: string): IpKind {
  const match = IPV4.exec(ip);
  if (!match) return 'invalid';

  const octets = match.slice(1, 5).map((part) => Number.parseInt(part, 10));
  if (octets.some((value) => !Number.isFinite(value) || value < 0 || value > 255)) return 'invalid';

  const [a = 0, b = 0, c = 0] = octets;

  if (a === 127) return 'loopback';
  if (a === 10) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'private'; // CGNAT, RFC 6598
  if (a === 169 && b === 254) return 'linklocal';

  // RFC 5737 documentation ranges — real reports never contain these.
  if (a === 192 && b === 0 && c === 2) return 'documentation';
  if (a === 198 && b === 51 && c === 100) return 'documentation';
  if (a === 203 && b === 0 && c === 113) return 'documentation';

  if (a === 0 || a >= 224) return 'reserved';
  return 'public';
}

function classifyIpv6(ip: string): IpKind {
  const groups = expandIpv6(ip);
  if (!groups) return 'invalid';

  const first = groups[0] ?? 0;
  if (groups.every((group, index) => (index === 7 ? group === 1 : group === 0))) return 'loopback';
  if (groups.every((group) => group === 0)) return 'reserved';
  if ((first & 0xfe00) === 0xfc00) return 'private'; // fc00::/7 unique-local
  if ((first & 0xffc0) === 0xfe80) return 'linklocal';
  if (first === 0x2001 && (groups[1] ?? 0) === 0x0db8) return 'documentation'; // RFC 3849
  if ((first & 0xff00) === 0xff00) return 'reserved'; // multicast
  return 'public';
}

/** Sixteen-bit groups, or `null` when the address does not parse. */
export function expandIpv6(raw: string): number[] | null {
  const ip = raw.trim().toLowerCase().replace(/%.*$/, '');
  if (!ip || ip.split('::').length > 2) return null;

  // A trailing IPv4 form (::ffff:1.2.3.4) becomes two groups.
  const v4 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(ip);
  let head = ip;
  const tail: number[] = [];
  if (v4 && v4[1]) {
    const octets = v4[1].split('.').map((part) => Number.parseInt(part, 10));
    if (octets.some((value) => !Number.isFinite(value) || value < 0 || value > 255)) return null;
    tail.push(((octets[0] ?? 0) << 8) | (octets[1] ?? 0), ((octets[2] ?? 0) << 8) | (octets[3] ?? 0));
    head = ip.slice(0, v4.index).replace(/:$/, ':');
  }

  const [left, right] = head.split('::');
  const parse = (part: string): number[] | null => {
    if (!part) return [];
    const groups: number[] = [];
    for (const piece of part.split(':')) {
      if (!piece) continue;
      if (!/^[0-9a-f]{1,4}$/.test(piece)) return null;
      groups.push(Number.parseInt(piece, 16));
    }
    return groups;
  };

  const front = parse(left ?? '');
  const back = parse(right ?? '');
  if (!front || !back) return null;

  const known = front.length + back.length + tail.length;
  if (head.includes('::')) {
    if (known > 8) return null;
    return [...front, ...new Array<number>(8 - known).fill(0), ...back, ...tail];
  }

  const all = [...front, ...back, ...tail];
  return all.length === 8 ? all : null;
}

/**
 * The name a PTR lookup asks for. Kept here rather than imported from the
 * engines because Bloodwork runs in the browser and must not pull a
 * server-side package in behind it — and unlike the engines' version, this one
 * has to handle IPv6, which is most of what modern reports contain.
 */
export function reverseName(raw: string): string | null {
  const ip = raw.trim().toLowerCase();
  if (!ip) return null;

  if (!isIpv6(ip)) {
    const match = IPV4.exec(ip);
    if (!match) return null;
    const octets = match.slice(1, 5);
    if (octets.some((part) => Number.parseInt(part, 10) > 255)) return null;
    return `${octets.reverse().join('.')}.in-addr.arpa`;
  }

  const groups = expandIpv6(ip);
  if (!groups) return null;

  const nibbles = groups
    .map((group) => group.toString(16).padStart(4, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.');

  return `${nibbles}.ip6.arpa`;
}
