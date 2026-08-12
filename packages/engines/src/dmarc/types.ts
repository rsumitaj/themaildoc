import type { Condition } from '@maildoc/catalog';
import type { ResolverNote } from '@maildoc/resolver';
import type { RecordStatus } from '@maildoc/shared';
import type { DmarcPolicy, ParsedDmarc } from './parse.js';
import type { DmarcDiscovery } from './discover.js';

export type EdvStatus = 'AUTHORIZED' | 'MISSING' | 'MALFORMED' | 'UNVERIFIED';

export interface EdvResult {
  destination: string;
  status: EdvStatus;
}

export interface DmarcAnalysis {
  domain: string;
  found: boolean;
  /** The applicable record, already concatenated. UNTRUSTED — escape it. */
  record: string | null;
  discovery: DmarcDiscovery;
  parsed: ParsedDmarc | null;
  tags: Record<string, string>;

  /** Policy tags after inheritance (§4.7.4, §4.7.9). */
  policy: DmarcPolicy;
  subdomainPolicy: DmarcPolicy;
  nonExistentPolicy: DmarcPolicy;
  /**
   * The policy that actually governs mail from the domain we were asked about.
   * When the record came from a parent, that is `sp`, not `p` — which is the
   * whole reason spoofability verdicts get this wrong elsewhere.
   */
  appliedPolicy: DmarcPolicy;
  /** True when receivers will ignore the record entirely (bad `v`). */
  ignored: boolean;
  /** `t=y` makes receivers apply p=none whatever the policy says. */
  testMode: boolean;
  /** Enforcement receivers really apply, after test mode is taken into account. */
  effectivePolicy: DmarcPolicy;

  alignment: { dkim: 'r' | 's'; spf: 'r' | 's' };
  rua: string[];
  ruf: string[];
  edv: EdvResult[];

  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}
