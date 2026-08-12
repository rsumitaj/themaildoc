/**
 * Turning a pile of addresses into the shortest correct set of CIDR blocks.
 *
 * A flattened SPF record is only useful if it is small, and it is only safe if
 * it authorises exactly what it authorised before. So this merges adjacent and
 * contained ranges and never widens one: two /32s that are not siblings stay
 * two /32s rather than becoming a /31 that also covers somebody else.
 */

export interface CidrBlock {
  /** Network address, normalised. */
  address: string;
  prefix: number;
}

/* IPv4 --------------------------------------------------------------------- */

export function ipv4ToInt(address: string): number | null {
  const octets = address.split('.');
  if (octets.length !== 4) return null;

  let value = 0;
  for (const octet of octets) {
    if (!/^(0|[1-9]\d{0,2})$/.test(octet)) return null;
    const part = Number(octet);
    if (part > 255) return null;
    value = value * 256 + part;
  }
  return value;
}

export function intToIpv4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

interface Range {
  start: bigint;
  end: bigint;
}

function toRange(value: bigint, prefix: number, bits: number): Range {
  const size = 1n << BigInt(bits - prefix);
  const start = (value / size) * size;
  return { start, end: start + size - 1n };
}

/**
 * Merge overlapping and adjacent ranges, then express the result as the
 * fewest CIDR blocks that cover exactly that set and nothing more.
 */
function mergeRanges(ranges: Range[]): Range[] {
  const sorted = [...ranges].sort((a, b) => (a.start === b.start ? 0 : a.start < b.start ? -1 : 1));
  const merged: Range[] = [];

  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end + 1n) {
      if (range.end > last.end) last.end = range.end;
    } else {
      merged.push({ ...range });
    }
  }
  return merged;
}

/** The exact CIDR cover of one contiguous range. Never widens it. */
function rangeToCidrs(range: Range, bits: number): { value: bigint; prefix: number }[] {
  const blocks: { value: bigint; prefix: number }[] = [];
  let start = range.start;
  const end = range.end;

  while (start <= end) {
    // The largest block that starts here and does not overshoot the end.
    let prefix = bits;
    while (prefix > 0) {
      const size = 1n << BigInt(bits - (prefix - 1));
      if (start % size !== 0n || start + size - 1n > end) break;
      prefix -= 1;
    }
    blocks.push({ value: start, prefix });
    start += 1n << BigInt(bits - prefix);
  }

  return blocks;
}

/**
 * Collapse IPv4 addresses and CIDRs into the smallest equivalent set.
 * Input entries may be `1.2.3.4` or `1.2.3.0/24`. Unparseable input is dropped
 * by the caller, never guessed at.
 */
export function mergeIpv4(entries: readonly string[]): string[] {
  const ranges: Range[] = [];

  for (const entry of entries) {
    const [address = '', prefixText] = entry.split('/');
    const value = ipv4ToInt(address);
    if (value === null) continue;

    const prefix = prefixText === undefined ? 32 : Number(prefixText);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) continue;

    ranges.push(toRange(BigInt(value), prefix, 32));
  }

  return mergeRanges(ranges)
    .flatMap((range) => rangeToCidrs(range, 32))
    .map(({ value, prefix }) =>
      prefix === 32 ? intToIpv4(Number(value)) : `${intToIpv4(Number(value))}/${prefix}`,
    );
}

/* IPv6 --------------------------------------------------------------------- */

export function ipv6ToBigInt(address: string): bigint | null {
  const clean = address.trim().toLowerCase().replace(/%.*$/, '');
  if (!clean || clean.split('::').length > 2) return null;

  const groups: number[] = [];
  const [left = '', right = ''] = clean.includes('::') ? clean.split('::') : [clean, ''];

  const parse = (part: string): number[] | null => {
    if (!part) return [];
    const out: number[] = [];
    for (const piece of part.split(':')) {
      if (!piece) return null;
      // A trailing IPv4 literal occupies two groups.
      if (piece.includes('.')) {
        const value = ipv4ToInt(piece);
        if (value === null) return null;
        out.push(value >>> 16, value & 0xffff);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(piece)) return null;
      out.push(Number.parseInt(piece, 16));
    }
    return out;
  };

  const head = parse(left);
  const tail = clean.includes('::') ? parse(right) : [];
  if (!head || !tail) return null;

  if (clean.includes('::')) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups.push(...head, ...new Array<number>(missing).fill(0), ...tail);
  } else {
    groups.push(...head);
  }

  if (groups.length !== 8) return null;
  return groups.reduce((total, group) => (total << 16n) | BigInt(group), 0n);
}

export function bigIntToIpv6(value: bigint): string {
  const groups: string[] = [];
  for (let index = 7; index >= 0; index -= 1) {
    groups.push(((value >> BigInt(index * 16)) & 0xffffn).toString(16));
  }

  // Compress the longest run of zero groups, as RFC 5952 requires.
  let bestStart = -1;
  let bestLength = 0;
  let start = -1;
  let length = 0;

  groups.forEach((group, index) => {
    if (group === '0') {
      if (start === -1) start = index;
      length += 1;
      if (length > bestLength) {
        bestLength = length;
        bestStart = start;
      }
    } else {
      start = -1;
      length = 0;
    }
  });

  if (bestLength < 2) return groups.join(':');

  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

export function mergeIpv6(entries: readonly string[]): string[] {
  const ranges: Range[] = [];

  for (const entry of entries) {
    const [address = '', prefixText] = entry.split('/');
    const value = ipv6ToBigInt(address);
    if (value === null) continue;

    const prefix = prefixText === undefined ? 128 : Number(prefixText);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) continue;

    ranges.push(toRange(value, prefix, 128));
  }

  return mergeRanges(ranges)
    .flatMap((range) => rangeToCidrs(range, 128))
    .map(({ value, prefix }) =>
      prefix === 128 ? bigIntToIpv6(value) : `${bigIntToIpv6(value)}/${prefix}`,
    );
}
