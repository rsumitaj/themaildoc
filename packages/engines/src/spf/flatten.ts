import type { DohResolver } from '@maildoc/resolver';
import { mergeIpv4, mergeIpv6 } from './cidr.js';
import { isSpfRecord, parseSpf, type SpfMechanism, type SpfTerm } from './parse.js';
import { isValidIpv4, isValidIpv6 } from './ip.js';

/**
 * SPF flattening: replace the lookups with the addresses they resolve to.
 *
 * This is a treatment with a side effect, and the side effect is the whole
 * reason most flatteners are dangerous. A flattened record authorises the IPs
 * your providers used at the moment it was generated. When Google or your ESP
 * changes an address, your record still says the old one, and mail starts
 * failing SPF with nothing in your DNS having changed. Everything here is
 * built to make that trade explicit rather than to hide it.
 *
 * What it will not do:
 *
 *   - widen a range. Two addresses that are not siblings stay two entries.
 *   - flatten `exists:`, `ptr` or a macro. Those are evaluated per message
 *     against the connecting IP, so there is no set of addresses to fold in.
 *     They are preserved verbatim and still cost their lookup.
 *   - silently drop anything it could not resolve. A partial answer is
 *     reported as partial, because publishing a record built from half your
 *     senders is worse than publishing nothing.
 */

/** Why a term survived flattening instead of becoming addresses. */
export type PreserveReason =
  /** Evaluated per message against the connecting IP (RFC 7208 §5.7). */
  | 'PER_MESSAGE'
  /** Contains a macro, so it expands differently for every message (§7). */
  | 'MACRO'
  /** DNS did not answer, so folding it in would silently drop senders. */
  | 'UNRESOLVED'
  /** We ran out of query budget before reaching it. */
  | 'BUDGET';

export interface PreservedTerm {
  term: string;
  reason: PreserveReason;
}

export interface ExpandedSource {
  /** The term as written, e.g. `include:_spf.google.com`. */
  term: string;
  ipv4: number;
  ipv6: number;
}

export interface FlattenResult {
  domain: string;
  /** The record as published today, concatenated. UNTRUSTED. */
  original: string | null;
  /** The flattened record, or null when we could not build a safe one. */
  flattened: string | null;
  /** The record split for publishing, when it exceeds 255 characters. */
  strings: string[];
  lookupsBefore: number;
  lookupsAfter: number;
  bytesBefore: number;
  bytesAfter: number;
  ipv4: string[];
  ipv6: string[];
  expanded: ExpandedSource[];
  preserved: PreservedTerm[];
  /** The qualifier on `all`, carried through unchanged. */
  allTerm: string | null;
  /** True when every lookup term was resolved. False means do not publish. */
  complete: boolean;
  queriesUsed: number;
  notes: FlattenNote[];
}

export type FlattenNote =
  | 'NO_RECORD'
  | 'ALREADY_SMALL'
  | 'BUDGET_EXHAUSTED'
  | 'RECORD_TOO_LONG'
  | 'NOTHING_TO_FLATTEN'
  | 'PARTIAL';

export interface FlattenOptions {
  /** Guard against a chain built to make us walk forever. */
  maxDepth?: number;
  maxNodes?: number;
}

/** A single TXT string may not exceed 255 characters (RFC 1035 §3.3.14). */
export const TXT_STRING_MAX = 255;
/** Beyond this a record risks truncation on resolvers without EDNS0. */
export const UDP_SAFE_BYTES = 450;
/** The hard ceiling for a single TXT record assembled from its strings. */
export const RECORD_MAX_BYTES = 4096;

const MACRO = /%\{/;

interface Context {
  resolver: DohResolver;
  ipv4: string[];
  ipv6: string[];
  expanded: ExpandedSource[];
  preserved: PreservedTerm[];
  seen: Set<string>;
  nodes: number;
  maxNodes: number;
  maxDepth: number;
  complete: boolean;
}

export async function flattenSpf(
  domain: string,
  resolver: DohResolver,
  options: FlattenOptions = {},
): Promise<FlattenResult> {
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const startQueries = resolver.queriesIssued;
  const notes: FlattenNote[] = [];

  const context: Context = {
    resolver,
    ipv4: [],
    ipv6: [],
    expanded: [],
    preserved: [],
    seen: new Set(),
    nodes: 0,
    maxNodes: options.maxNodes ?? 48,
    maxDepth: options.maxDepth ?? 10,
    complete: true,
  };

  const record = await readSpf(resolver, name);
  if (!record) {
    return empty(name, null, ['NO_RECORD'], resolver.queriesIssued - startQueries);
  }

  const parsed = parseSpf(record);
  const lookupsBefore = await countLookups(context, record, 0);

  // Reset the counters the dry run used; the real walk collects addresses.
  context.ipv4 = [];
  context.ipv6 = [];
  context.expanded = [];
  context.preserved = [];
  context.seen = new Set();
  context.nodes = 0;

  const allTerm = findAll(parsed.terms);
  await collect(context, name, record, 0, name);

  if (!context.complete) notes.push('PARTIAL');
  if (resolver.remainingBudget <= 0) notes.push('BUDGET_EXHAUSTED');

  const ipv4 = mergeIpv4(context.ipv4);
  const ipv6 = mergeIpv6(context.ipv6);

  const terms = [
    'v=spf1',
    ...ipv4.map((entry) => `ip4:${entry}`),
    ...ipv6.map((entry) => `ip6:${entry}`),
    ...context.preserved.map((entry) => entry.term),
    ...(allTerm ? [allTerm] : []),
  ];

  const flattened = terms.join(' ');
  const bytesAfter = byteLength(flattened);
  const bytesBefore = byteLength(record);

  if (ipv4.length === 0 && ipv6.length === 0) notes.push('NOTHING_TO_FLATTEN');
  if (bytesAfter > RECORD_MAX_BYTES) notes.push('RECORD_TOO_LONG');

  const lookupsAfter = countStaticLookups(context.preserved);
  if (lookupsBefore <= 10 && lookupsAfter === lookupsBefore) notes.push('ALREADY_SMALL');

  const publishable = context.complete && bytesAfter <= RECORD_MAX_BYTES;

  return {
    domain: name,
    original: record,
    flattened: publishable ? flattened : null,
    strings: publishable ? splitForTxt(flattened) : [],
    lookupsBefore,
    lookupsAfter,
    bytesBefore,
    bytesAfter,
    ipv4,
    ipv6,
    expanded: context.expanded,
    preserved: context.preserved,
    allTerm,
    complete: context.complete,
    queriesUsed: resolver.queriesIssued - startQueries,
    notes,
  };
}

/* Walking ------------------------------------------------------------------ */

async function collect(
  context: Context,
  domain: string,
  record: string,
  depth: number,
  origin: string,
): Promise<void> {
  if (depth > context.maxDepth || context.nodes >= context.maxNodes) {
    context.complete = false;
    return;
  }
  context.nodes += 1;

  const parsed = parseSpf(record);

  for (const term of parsed.terms) {
    if (term.kind === 'modifier' && term.name === 'redirect') {
      // redirect= replaces the record entirely, so its terms belong to us.
      await follow(context, term.value, `redirect=${term.value}`, depth, origin);
      continue;
    }
    if (term.kind !== 'mechanism') continue;

    switch (term.name) {
      // The parser strips the prefix off the address and keeps the digits in
      // `cidr4`, for ip6 as well as ip4, so both are rebuilt the same way.
      case 'ip4':
        if (term.value && isValidIpv4(term.value)) {
          context.ipv4.push(term.cidr4 ? `${term.value}/${term.cidr4}` : term.value);
        }
        break;

      case 'ip6':
        if (term.value && isValidIpv6(term.value)) {
          context.ipv6.push(term.cidr4 ? `${term.value}/${term.cidr4}` : term.value);
        }
        break;

      case 'include':
        await follow(context, term.value, `include:${term.value}`, depth, origin);
        break;

      case 'a':
        await expandAddress(context, term, domain, 'a');
        break;

      case 'mx':
        await expandMx(context, term, domain);
        break;

      case 'ptr':
      case 'exists':
        // Evaluated against the connecting IP for every message. There is no
        // fixed set of addresses these stand for.
        preserve(context, term.raw, MACRO.test(term.value ?? '') ? 'MACRO' : 'PER_MESSAGE');
        break;

      case 'all':
        break;
    }
  }
}

async function follow(
  context: Context,
  target: string | null,
  label: string,
  depth: number,
  origin: string,
): Promise<void> {
  if (!target) return;

  if (MACRO.test(target)) {
    preserve(context, label, 'MACRO');
    return;
  }

  const name = target.trim().replace(/\.$/, '').toLowerCase();
  if (context.seen.has(name)) return;
  context.seen.add(name);

  if (context.resolver.remainingBudget <= 1) {
    preserve(context, label, 'BUDGET');
    context.complete = false;
    return;
  }

  const before = { v4: context.ipv4.length, v6: context.ipv6.length };
  const record = await readSpf(context.resolver, name);

  if (!record) {
    // An include that publishes nothing is a permanent error for a receiver.
    // Preserving it keeps the record honest rather than quietly dropping a
    // sender the owner believes is authorised.
    preserve(context, label, 'UNRESOLVED');
    context.complete = false;
    return;
  }

  await collect(context, name, record, depth + 1, origin);

  context.expanded.push({
    term: label,
    ipv4: context.ipv4.length - before.v4,
    ipv6: context.ipv6.length - before.v6,
  });
}

async function expandAddress(
  context: Context,
  term: SpfMechanism,
  current: string,
  kind: 'a' | 'mx',
): Promise<void> {
  const target = term.value ?? current;

  if (MACRO.test(target)) {
    preserve(context, term.raw, 'MACRO');
    return;
  }
  if (context.resolver.remainingBudget <= 1) {
    preserve(context, term.raw, 'BUDGET');
    context.complete = false;
    return;
  }

  const before = { v4: context.ipv4.length, v6: context.ipv6.length };
  const found = await addressesOf(context, target, term);

  if (!found) {
    preserve(context, term.raw, 'UNRESOLVED');
    context.complete = false;
    return;
  }

  context.expanded.push({
    term: `${kind}${term.value ? `:${term.value}` : ''}`,
    ipv4: context.ipv4.length - before.v4,
    ipv6: context.ipv6.length - before.v6,
  });
}

async function expandMx(context: Context, term: SpfMechanism, current: string): Promise<void> {
  const target = (term.value ?? current).trim().replace(/\.$/, '').toLowerCase();

  if (MACRO.test(target)) {
    preserve(context, term.raw, 'MACRO');
    return;
  }
  if (context.resolver.remainingBudget <= 2) {
    preserve(context, term.raw, 'BUDGET');
    context.complete = false;
    return;
  }

  const mx = await context.resolver.query(target, 'MX');
  if (mx.status !== 'NOERROR' || mx.records.length === 0) {
    preserve(context, term.raw, 'UNRESOLVED');
    context.complete = false;
    return;
  }

  const before = { v4: context.ipv4.length, v6: context.ipv6.length };
  // RFC 7208 §5.4 caps this at 10 MX names, and so do we.
  const hosts = mx.records
    .slice(0, 10)
    .map((record) => hostFromMx(record.data))
    .filter((host): host is string => host !== null);

  let resolvedAny = false;
  for (const host of hosts) {
    if (context.resolver.remainingBudget <= 1) {
      context.complete = false;
      break;
    }
    if (await addressesOf(context, host, term)) resolvedAny = true;
  }

  if (!resolvedAny) {
    preserve(context, term.raw, 'UNRESOLVED');
    context.complete = false;
    return;
  }

  context.expanded.push({
    term: `mx${term.value ? `:${term.value}` : ''}`,
    ipv4: context.ipv4.length - before.v4,
    ipv6: context.ipv6.length - before.v6,
  });
}

/**
 * A and AAAA for one name, carrying the mechanism's CIDR through.
 *
 * `a:example.com/24` authorises the /24 around each address, not the address
 * alone (RFC 7208 §5.3), so dropping the prefix here would narrow the record
 * and start rejecting mail that used to pass.
 */
async function addressesOf(
  context: Context,
  host: string,
  term: SpfMechanism,
): Promise<boolean> {
  let found = false;

  const v4 = await context.resolver.query(host, 'A');
  for (const record of v4.records) {
    if (!isValidIpv4(record.data)) continue;
    context.ipv4.push(term.cidr4 ? `${record.data}/${term.cidr4}` : record.data);
    found = true;
  }

  if (context.resolver.remainingBudget > 1) {
    const v6 = await context.resolver.query(host, 'AAAA');
    for (const record of v6.records) {
      if (!isValidIpv6(record.data)) continue;
      context.ipv6.push(term.cidr6 ? `${record.data}/${term.cidr6}` : record.data);
      found = true;
    }
  }

  return found;
}

function preserve(context: Context, term: string, reason: PreserveReason): void {
  if (context.preserved.some((entry) => entry.term === term)) return;
  context.preserved.push({ term, reason });
}

/* Counting ----------------------------------------------------------------- */

/**
 * The lookups the record costs today. Walks the chain without collecting
 * addresses, so the "before" number is the same one the checker reports.
 */
async function countLookups(context: Context, record: string, depth: number): Promise<number> {
  if (depth > context.maxDepth || context.nodes >= context.maxNodes) return 0;
  context.nodes += 1;

  const parsed = parseSpf(record);
  let total = 0;

  for (const term of parsed.terms) {
    if (term.kind === 'modifier' && term.name === 'redirect') {
      total += 1;
      const target = term.value.trim().replace(/\.$/, '').toLowerCase();
      if (context.seen.has(target) || context.resolver.remainingBudget <= 2) continue;
      context.seen.add(target);
      const nested = await readSpf(context.resolver, target);
      if (nested) total += await countLookups(context, nested, depth + 1);
      continue;
    }
    if (term.kind !== 'mechanism') continue;

    if (term.name === 'a' || term.name === 'mx' || term.name === 'ptr' || term.name === 'exists') {
      total += 1;
      continue;
    }

    if (term.name === 'include' && term.value) {
      total += 1;
      const target = term.value.trim().replace(/\.$/, '').toLowerCase();
      if (context.seen.has(target) || context.resolver.remainingBudget <= 2) continue;
      context.seen.add(target);
      const nested = await readSpf(context.resolver, target);
      if (nested) total += await countLookups(context, nested, depth + 1);
    }
  }

  return total;
}

/** What the flattened record still costs: one per preserved lookup term. */
function countStaticLookups(preserved: readonly PreservedTerm[]): number {
  return preserved.filter((entry) => {
    const term = entry.term.replace(/^[+\-~?]/, '');
    return (
      term.startsWith('include:') ||
      term.startsWith('exists:') ||
      term.startsWith('redirect=') ||
      term === 'ptr' ||
      term.startsWith('ptr:') ||
      term === 'a' ||
      term.startsWith('a:') ||
      term === 'mx' ||
      term.startsWith('mx:')
    );
  }).length;
}

/* Plumbing ----------------------------------------------------------------- */

async function readSpf(resolver: DohResolver, name: string): Promise<string | null> {
  const result = await resolver.query(name, 'TXT');
  const records = result.txt.map((entry) => entry.value).filter((value) => isSpfRecord(value));
  // More than one is a permanent error at that name; we flatten neither.
  return records.length === 1 ? (records[0] as string) : null;
}

function findAll(terms: readonly SpfTerm[]): string | null {
  for (const term of terms) {
    if (term.kind === 'mechanism' && term.name === 'all') return term.raw;
  }
  return null;
}

function hostFromMx(data: string): string | null {
  // "10 mail.example.com." or already just the host.
  const parts = data.trim().split(/\s+/);
  const host = (parts.length > 1 ? parts[1] : parts[0]) ?? '';
  const clean = host.replace(/\.$/, '').toLowerCase();
  return clean ? clean : null;
}

export function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

/**
 * Split a record into TXT strings of at most 255 characters, never mid-term.
 * A receiver concatenates the strings with nothing between them, so each
 * string except the last ends with the space that separates two terms.
 */
export function splitForTxt(record: string): string[] {
  if (byteLength(record) <= TXT_STRING_MAX) return [record];

  const strings: string[] = [];
  let current = '';

  for (const term of record.split(' ')) {
    const candidate = current === '' ? term : `${current} ${term}`;
    if (byteLength(candidate) + 1 > TXT_STRING_MAX && current !== '') {
      strings.push(`${current} `);
      current = term;
    } else {
      current = candidate;
    }
  }

  if (current) strings.push(current);
  return strings;
}

function empty(
  domain: string,
  original: string | null,
  notes: FlattenNote[],
  queriesUsed: number,
): FlattenResult {
  return {
    domain,
    original,
    flattened: null,
    strings: [],
    lookupsBefore: 0,
    lookupsAfter: 0,
    bytesBefore: original ? byteLength(original) : 0,
    bytesAfter: 0,
    ipv4: [],
    ipv6: [],
    expanded: [],
    preserved: [],
    allTerm: null,
    complete: false,
    queriesUsed,
    notes,
  };
}
