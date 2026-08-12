import type { DohResolver, ResolverNote } from '@maildoc/resolver';
import { isDmarcRecord, looksLikeDmarc } from './parse.js';

/**
 * DMARC policy discovery — the RFC 9989 §4.10 DNS Tree Walk.
 *
 * This replaces the Public Suffix List that DMARC used to depend on. The walk
 * queries `_dmarc.<target>`, and when nothing is found it removes labels from
 * the left and asks again, stopping after eight queries. That cap is not a
 * safety margin we chose — it is in the spec, to stop a domain with hundreds of
 * labels being used for a denial-of-service attack. A walk that exhausts it
 * means receivers apply no DMARC at all.
 *
 * The label rule (§4.10 step 4) is exact: with fewer than eight labels, remove
 * the leftmost one; with eight or more, remove labels until seven remain.
 */

export const DMARC_MAX_TREE_WALK_QUERIES = 8;

export type DiscoverySource = 'author' | 'parent' | 'none';

export interface DiscoveryStep {
  /** The domain whose `_dmarc` label was queried. */
  target: string;
  found: boolean;
  recordCount: number;
}

export interface DmarcDiscovery {
  authorDomain: string;
  found: boolean;
  /** The record receivers will apply, already concatenated. UNTRUSTED. */
  record: string | null;
  /** Every DMARC record at the winning name (more than one is discarded). */
  records: string[];
  /** Where the applicable record lives — the author domain, or a parent. */
  source: DiscoverySource;
  foundAt: string | null;
  /** Each name the walk asked about, in order. */
  path: DiscoveryStep[];
  queries: number;
  /** The walk hit the eight-query ceiling without finding a record. */
  capped: boolean;
  /** A name in the walk published more than one DMARC record. */
  multipleAt: string | null;
  multipleCount: number;
  /**
   * TXT records at the author domain's `_dmarc` that mean to be DMARC but are
   * not valid. Receivers discard them; we use them to explain why.
   */
  candidates: string[];
  /** The author domain does not exist at all. */
  nxdomain: boolean;
  /** `_dmarc` is a CNAME and the chain is broken or loops. */
  cnameTarget: string | null;
  cnameLoop: boolean;
  unresolved: boolean;
  notes: ResolverNote[];
}

/** Strip labels per §4.10 step 4. Returns null when nothing is left to ask. */
export function stepUp(domain: string): string | null {
  const labels = domain.split('.').filter(Boolean);
  if (labels.length <= 1) return null;

  const next = labels.length >= 8 ? labels.slice(labels.length - 7) : labels.slice(1);
  return next.length >= 1 ? next.join('.') : null;
}

export interface DiscoverOptions {
  /** Cross-check the author domain's record against a second resolver. */
  verify?: boolean;
  maxQueries?: number;
}

export async function discoverDmarc(
  domain: string,
  resolver: DohResolver,
  options: DiscoverOptions = {},
): Promise<DmarcDiscovery> {
  const authorDomain = domain.trim().replace(/\.$/, '').toLowerCase();
  const maxQueries = options.maxQueries ?? DMARC_MAX_TREE_WALK_QUERIES;

  const discovery: DmarcDiscovery = {
    authorDomain,
    found: false,
    record: null,
    records: [],
    source: 'none',
    foundAt: null,
    path: [],
    queries: 0,
    capped: false,
    multipleAt: null,
    multipleCount: 0,
    candidates: [],
    nxdomain: false,
    cnameTarget: null,
    cnameLoop: false,
    unresolved: false,
    notes: [],
  };

  const notes = new Set<ResolverNote>();
  let target: string | null = authorDomain;

  while (target !== null) {
    if (discovery.queries >= maxQueries) {
      discovery.capped = true;
      break;
    }

    const isAuthor = target === authorDomain;
    const result = await resolver.query(`_dmarc.${target}`, 'TXT', {
      verify: isAuthor && (options.verify ?? false),
    });
    discovery.queries += 1;
    for (const note of result.notes) notes.add(note);

    if (result.notes.includes('BUDGET_EXCEEDED')) {
      discovery.unresolved = true;
      break;
    }
    if (result.status === 'TIMEOUT' || result.status === 'ERROR') {
      // Our own trouble, not the domain's. Stop and say so.
      if (isAuthor) discovery.unresolved = true;
      break;
    }

    if (isAuthor) {
      inspectCnameChain(discovery, result.answers);
      if (result.status === 'NXDOMAIN' && result.answers.length === 0) {
        // `_dmarc.<domain>` not existing is normal; only note it for the walk.
        discovery.nxdomain = false;
      }
    }

    const values = result.txt.map((txt) => txt.value);
    const records = values.filter(isDmarcRecord);
    if (isAuthor) discovery.candidates = values.filter(looksLikeDmarc);
    discovery.path.push({ target, found: records.length === 1, recordCount: records.length });

    if (records.length === 1) {
      discovery.found = true;
      discovery.record = records[0] as string;
      discovery.records = records;
      discovery.foundAt = target;
      discovery.source = isAuthor ? 'author' : 'parent';
      break;
    }

    if (records.length > 1) {
      // §4.10 step 2: multiple records at one target are all discarded. The
      // walk continues, but this is fatal for the domain that published them.
      discovery.records = records;
      discovery.multipleAt = target;
      discovery.multipleCount = records.length;
    }

    target = stepUp(target);
  }

  discovery.notes = [...notes];
  return discovery;
}

/**
 * DoH follows CNAMEs for us, so the answer section shows the chain it walked.
 * That is enough to tell a broken delegation from a missing record — without
 * spending extra subrequests on a dedicated CNAME walk.
 */
function inspectCnameChain(
  discovery: DmarcDiscovery,
  answers: ReadonlyArray<{ type: number; data: string }>,
): void {
  const chain = answers.filter((answer) => answer.type === 5).map((answer) => answer.data);
  if (chain.length === 0) return;

  const seen = new Set<string>();
  for (const link of chain) {
    const name = link.trim().replace(/\.$/, '').toLowerCase();
    if (seen.has(name)) {
      discovery.cnameLoop = true;
      break;
    }
    seen.add(name);
  }

  discovery.cnameTarget = (chain[chain.length - 1] ?? '').trim().replace(/\.$/, '') || null;
}
