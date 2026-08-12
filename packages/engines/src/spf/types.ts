import type { Condition } from '@maildoc/catalog';
import type { ResolverNote } from '@maildoc/resolver';
import type { RecordStatus } from '@maildoc/shared';
import type { ParsedSpf, Qualifier, SpfTerm } from './parse.js';

export type SpfNodeStatus =
  | 'OK'
  /** The name resolves but publishes no SPF record. */
  | 'NO_RECORD'
  /** More than one SPF record — a permanent error at this name. */
  | 'MULTIPLE'
  /** The include/redirect target does not exist. */
  | 'VOID'
  /** Already an ancestor in this chain. */
  | 'CIRCULAR'
  /** DNS did not answer (timeout/SERVFAIL). */
  | 'UNRESOLVED'
  /** We stopped walking here: depth guard or query budget. */
  | 'TRUNCATED';

/** One domain in the SPF include/redirect tree. */
export interface SpfChainNode {
  domain: string;
  via: 'root' | 'include' | 'redirect';
  depth: number;
  /** The SPF record found here, already concatenated. UNTRUSTED — escape it. */
  record: string | null;
  /** DNS lookups this node's own terms cost (children counted separately). */
  lookups: number;
  status: SpfNodeStatus;
  children: SpfChainNode[];
}

export interface SpfAnalysis {
  domain: string;
  found: boolean;
  /** The record as a receiver assembles it. UNTRUSTED — escape before render. */
  record: string | null;
  /** Every v=spf1 record at the apex (more than one is a permanent error). */
  records: string[];
  parsed: ParsedSpf | null;
  terms: SpfTerm[];
  /** Qualifier on the apex `all` mechanism, or null when there isn't one. */
  allQualifier: Qualifier | null;
  redirect: string | null;
  /** Total DNS-lookup-consuming terms across the whole chain (limit: 10). */
  lookupCount: number;
  /** False when a guard stopped the walk, so the count is a floor, not a total. */
  lookupCountExact: boolean;
  voidLookupCount: number;
  voidDomains: string[];
  voidCountExact: boolean;
  chain: SpfChainNode | null;
  conditions: Condition[];
  status: RecordStatus;
  /** Upstream DNS queries this analysis spent. */
  queriesUsed: number;
  notes: ResolverNote[];
}
