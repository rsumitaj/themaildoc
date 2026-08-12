/**
 * DMARC record parser — RFC 9989 §4.8.
 *
 * Two rules from the ABNF drive everything here, and both are routinely got
 * wrong elsewhere:
 *
 *   - `v=DMARC1` must be present, first, and exactly that. Otherwise the whole
 *     record MUST be ignored.
 *   - Unknown tags MUST be ignored — they are not errors, and flagging them
 *     would be a false positive on every forward-compatible record.
 */

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export const POLICY_VALUES: readonly string[] = ['none', 'quarantine', 'reject'];

/** Rank for comparing strictness — a lower rank is weaker protection. */
export const POLICY_RANK: Record<DmarcPolicy, number> = {
  none: 0,
  quarantine: 1,
  reject: 2,
};

/** Tags removed from DMARC by RFC 9989 (see Appendix A.6). */
export const OBSOLETE_TAGS: readonly string[] = ['pct', 'rf', 'ri'];

export interface DmarcTag {
  name: string;
  /** Name exactly as written, to report a casing problem faithfully. */
  rawName: string;
  value: string;
}

export interface ParsedDmarc {
  raw: string;
  tags: Record<string, string>;
  order: string[];
  entries: DmarcTag[];
  /** Tag names that appeared more than once. */
  duplicates: string[];
  /** Tag names written with uppercase letters. */
  uppercase: string[];
  /** Segments that are not `tag=value` at all. */
  malformed: string[];
}

/**
 * A record receivers will actually accept. The ABNF spells the version out in
 * literal uppercase characters, so `v=dmarc1` is not a DMARC record — it is a
 * broken one, which is a different and much more useful thing to be told.
 */
export function isDmarcRecord(value: string): boolean {
  return /^\s*v\s*=\s*DMARC1\s*(;|$)/.test(value);
}

/**
 * A record that is clearly *trying* to be DMARC. Receivers discard these, but
 * reporting "no DMARC record" to someone who published one and got the version
 * wrong helps nobody.
 */
export function looksLikeDmarc(value: string): boolean {
  if (isDmarcRecord(value)) return false;
  return /^\s*v\s*=\s*dmarc/i.test(value) || /(^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(;|$)/i.test(value);
}

export function parseDmarc(record: string): ParsedDmarc {
  const raw = record.trim();
  const parsed: ParsedDmarc = {
    raw,
    tags: {},
    order: [],
    entries: [],
    duplicates: [],
    uppercase: [],
    malformed: [],
  };

  for (const segment of raw.split(';')) {
    if (segment.trim() === '') continue; // a trailing semicolon is legal

    const equals = segment.indexOf('=');
    if (equals === -1) {
      parsed.malformed.push(segment.trim());
      continue;
    }

    const rawName = segment.slice(0, equals).trim();
    const value = segment.slice(equals + 1).trim();
    if (!/^[a-z][a-z0-9_]*$/i.test(rawName)) {
      parsed.malformed.push(segment.trim());
      continue;
    }

    const name = rawName.toLowerCase();
    if (rawName !== name) parsed.uppercase.push(rawName);
    if (Object.prototype.hasOwnProperty.call(parsed.tags, name)) {
      parsed.duplicates.push(name);
    }

    parsed.tags[name] = value;
    parsed.order.push(name);
    parsed.entries.push({ name, rawName, value });
  }

  return parsed;
}

export interface ReportUri {
  raw: string;
  /** Address without the scheme, e.g. `dmarc@example.com`. */
  address: string;
  /** The `!10m` style size limit, as written. */
  size: string | null;
  hasMailto: boolean;
  wellFormed: boolean;
}

const EMAIL = /^[^\s@,!]+@[^\s@,!]+\.[a-z0-9-]+$/i;
const SIZE = /^![0-9]+[kmgt]?$/i;

/**
 * Split a rua/ruf value into destinations. They are comma-separated
 * (RFC 9989 §4.6); a space-separated list is a common and silent mistake.
 */
export function parseReportUris(value: string): {
  uris: ReportUri[];
  spaceDelimited: boolean;
} {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  let spaceDelimited = false;
  const uris = parts.map((part) => {
    const hasMailto = /^mailto:/i.test(part);
    const body = part.replace(/^mailto:/i, '');
    const bang = body.indexOf('!');
    const address = bang === -1 ? body : body.slice(0, bang);
    const size = bang === -1 ? null : body.slice(bang);

    if (/\s/.test(address)) spaceDelimited = true;

    return {
      raw: part,
      address,
      size,
      hasMailto,
      wellFormed: hasMailto && EMAIL.test(address) && (size === null || SIZE.test(size)),
    };
  });

  return { uris, spaceDelimited };
}

export function isValidSize(size: string): boolean {
  return SIZE.test(size);
}

export function isValidAddress(address: string): boolean {
  return EMAIL.test(address);
}

/** `fo` is a colon-separated list drawn from 0, 1, d and s (§4.7.3). */
export function isValidFo(value: string): boolean {
  const parts = value.split(':').map((part) => part.trim());
  if (parts.length === 0 || parts.some((part) => part === '')) return false;
  return parts.every((part) => ['0', '1', 'd', 's'].includes(part));
}
