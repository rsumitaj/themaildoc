import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  sortConditions,
  type Condition,
  type IssueVars,
} from '@maildoc/catalog';
import type { DohResolver, ResolverNote } from '@maildoc/resolver';
import type { RecordStatus } from '@maildoc/shared';
import { isPrivateIpv4, isPrivateIpv6 } from '../spf/ip.js';

export interface AddressAnalysis {
  domain: string;
  ipv4: string[];
  ipv6: string[];
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface DnssecAnalysis {
  domain: string;
  /** The resolver validated the answer (AD flag). */
  authenticated: boolean;
  signed: boolean;
  hasDelegationSigner: boolean;
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
}

/** A / AAAA — RFC 1035, RFC 3596. Address records are informational for mail. */
export async function analyzeAddresses(
  domain: string,
  resolver: DohResolver,
): Promise<AddressAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const [v4, v6] = await Promise.all([
    resolver.query(name, 'A'),
    resolver.query(name, 'AAAA'),
  ]);
  for (const note of [...v4.notes, ...v6.notes]) ctx.notes.add(note);

  const ipv4 = v4.records.map((record) => record.data);
  const ipv6 = v6.records.map((record) => record.data);

  if (ipv4.length === 0 && ipv6.length === 0) {
    emit(ctx, 'A_MISSING', { domain: name });
  } else if (ipv6.length === 0) {
    emit(ctx, 'AAAA_MISSING', { domain: name });
  }

  for (const address of ipv4) {
    if (isPrivateIpv4(address)) {
      emit(ctx, 'A_PRIVATE_IP', { domain: name, offending_term: address });
    }
  }
  for (const address of ipv6) {
    if (isPrivateIpv6(address)) {
      emit(ctx, 'A_PRIVATE_IP', { domain: name, offending_term: address });
    }
  }

  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain: name,
    ipv4,
    ipv6,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

/**
 * DNSSEC — RFC 4033/4034/4035.
 *
 * We read what a validating resolver tells us: the authenticated-data flag,
 * whether the zone publishes keys, and whether the parent publishes the DS that
 * links them to the chain of trust. A zone signed with no DS at the parent is
 * the classic half-finished setup — all of the cost, none of the protection.
 */
export async function analyzeDnssec(
  domain: string,
  resolver: DohResolver,
): Promise<DnssecAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const dnskey = await resolver.query(name, 'DNSKEY');
  for (const note of dnskey.notes) ctx.notes.add(note);

  if (dnskey.status === 'TIMEOUT' || dnskey.status === 'ERROR') {
    emit(ctx, 'RESOLVER_TIMEOUT', { domain: name, record: 'DNSSEC' });
    return finishDnssec(ctx, name, false, false, false, resolver, startQueries);
  }

  const signed = dnskey.records.length > 0;
  const authenticated = dnskey.authenticated;

  if (!signed) {
    emit(ctx, 'DNSSEC_UNSIGNED', { domain: name });
    return finishDnssec(ctx, name, authenticated, false, false, resolver, startQueries);
  }

  if (authenticated) {
    // Keys published and the resolver validated them: the chain is intact.
    return finishDnssec(ctx, name, true, true, true, resolver, startQueries);
  }

  const ds = await resolver.query(name, 'DS');
  for (const note of ds.notes) ctx.notes.add(note);

  const hasDs = ds.records.length > 0;
  if (!hasDs) emit(ctx, 'DNSSEC_DS_MISSING', { domain: name });
  else emit(ctx, 'DNSSEC_BOGUS', { domain: name });

  return finishDnssec(ctx, name, false, true, hasDs, resolver, startQueries);
}

function finishDnssec(
  ctx: Ctx,
  domain: string,
  authenticated: boolean,
  signed: boolean,
  hasDelegationSigner: boolean,
  resolver: DohResolver,
  startQueries: number,
): DnssecAnalysis {
  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain,
    authenticated,
    signed,
    hasDelegationSigner,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

function emit(ctx: Ctx, code: string, vars: IssueVars): void {
  ctx.conditions.push(createCondition(code, vars));
}
