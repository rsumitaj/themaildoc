/**
 * SPF record parser — RFC 7208 §12 (ABNF).
 *
 * Structure only: this turns a record into terms and reports what is
 * syntactically wrong. Whether those terms are a *good idea* is the analyzer's
 * job, and what to tell the patient is the catalog's.
 */

export type Qualifier = '+' | '-' | '~' | '?';

export const MECHANISM_NAMES = [
  'all',
  'include',
  'a',
  'mx',
  'ptr',
  'ip4',
  'ip6',
  'exists',
] as const;

export type MechanismName = (typeof MECHANISM_NAMES)[number];

/** Mechanisms that cost one of the ten DNS lookups (RFC 7208 §4.6.4). */
export const LOOKUP_MECHANISMS: ReadonlySet<string> = new Set([
  'include',
  'a',
  'mx',
  'ptr',
  'exists',
]);

export interface SpfMechanism {
  kind: 'mechanism';
  raw: string;
  qualifier: Qualifier;
  name: MechanismName;
  /** The part after `:` — a domain-spec, or an IP for ip4/ip6. */
  value: string | null;
  /** `/24` style prefix, as written. */
  cidr4: string | null;
  /** `//64` style prefix, as written. */
  cidr6: string | null;
  index: number;
}

export interface SpfModifier {
  kind: 'modifier';
  raw: string;
  name: string;
  value: string;
  index: number;
}

/** A term that is neither a known mechanism nor a well-formed modifier. */
export interface SpfUnknownTerm {
  kind: 'unknown';
  raw: string;
  index: number;
}

export type SpfTerm = SpfMechanism | SpfModifier | SpfUnknownTerm;

export interface ParsedSpf {
  /** The record as evaluated (character-strings already concatenated). */
  raw: string;
  terms: SpfTerm[];
}

const QUALIFIERS = new Set(['+', '-', '~', '?']);
const MODIFIER_NAME = /^[a-z][a-z0-9._-]*$/i;
const MECHANISM_SET: ReadonlySet<string> = new Set(MECHANISM_NAMES);

/** Does this TXT value claim to be SPF at all? */
export function isSpfRecord(value: string): boolean {
  return /^v=spf1(\s|$)/i.test(value.trim());
}

/**
 * A TXT record that is *trying* to be SPF but has the version wrong —
 * `v=spf2`, `spf1 …`, `V=SPF1.0`. Worth telling the patient about, because it
 * looks published but is invisible to every receiver.
 */
export function looksLikeBrokenSpf(value: string): boolean {
  const trimmed = value.trim();
  if (isSpfRecord(trimmed)) return false;
  // spf2.0/... is Sender ID, a different (dead) protocol — not a broken SPF.
  if (/^spf2\.0/i.test(trimmed)) return false;
  return /^v?=?\s*spf\s*1?/i.test(trimmed) && /(\s|^)(include:|ip4:|ip6:|[+~?-]?all)/i.test(trimmed);
}

export function parseSpf(record: string): ParsedSpf {
  const raw = record.trim();
  const parts = raw.split(/\s+/).filter(Boolean);
  // parts[0] is the version token; everything after it is a term.
  const terms = parts.slice(1).map((term, offset) => parseTerm(term, offset + 1));
  return { raw, terms };
}

function parseTerm(raw: string, index: number): SpfTerm {
  let qualifier: Qualifier = '+';
  let body = raw;

  const first = raw[0];
  if (first !== undefined && QUALIFIERS.has(first)) {
    qualifier = first as Qualifier;
    body = raw.slice(1);
  }

  const colon = body.indexOf(':');
  const equals = body.indexOf('=');

  // `name=value` with no earlier colon is a modifier (redirect=, exp=, or an
  // unknown modifier, which RFC 7208 §6 says receivers must ignore).
  if (equals > 0 && (colon === -1 || equals < colon)) {
    if (raw !== body) return { kind: 'unknown', raw, index }; // qualifiers are illegal on modifiers
    const name = body.slice(0, equals);
    if (!MODIFIER_NAME.test(name)) return { kind: 'unknown', raw, index };
    return { kind: 'modifier', raw, name: name.toLowerCase(), value: body.slice(equals + 1), index };
  }

  let name = body;
  let value: string | null = null;
  if (colon > 0) {
    name = body.slice(0, colon);
    value = body.slice(colon + 1);
  }

  let cidr4: string | null = null;
  let cidr6: string | null = null;

  // Dual-CIDR suffixes: `/24`, `//64`, `/24//64`. ip4/ip6 carry a single prefix
  // on the address itself, which we split out the same way.
  const target = value === null ? name : value;
  const slash = target.indexOf('/');
  if (slash !== -1) {
    const base = target.slice(0, slash);
    const suffix = target.slice(slash);
    const match = /^(?:\/(\d*))?(?:\/\/(\d*))?$/.exec(suffix);
    if (match) {
      cidr4 = match[1] ?? null;
      cidr6 = match[2] ?? null;
      if (cidr4 === '') cidr4 = null;
      if (cidr6 === '') cidr6 = null;
      if (value === null) name = base;
      else value = base;
    }
  }

  const lower = name.toLowerCase();
  if (!MECHANISM_SET.has(lower)) return { kind: 'unknown', raw, index };

  return {
    kind: 'mechanism',
    raw,
    qualifier,
    name: lower as MechanismName,
    value,
    cidr4,
    cidr6,
    index,
  };
}

export function isLookupMechanism(term: SpfTerm): boolean {
  return term.kind === 'mechanism' && LOOKUP_MECHANISMS.has(term.name);
}
