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
import { isValidIpv4 } from '../spf/ip.js';

/**
 * Reverse DNS and forward-confirmed reverse DNS — RFC 1912 §2.1.
 *
 * The hard part is knowing *which* IPs to judge. Without a message in hand we
 * cannot know what address a domain sends from, and flagging a vendor's shared
 * range would be both wrong and useless — you cannot set a PTR on SendGrid's
 * machines, and SendGrid already has.
 *
 * So we only check addresses the domain publishes as its own: its MX hosts,
 * and the targets of `a`/`mx` mechanisms in its own SPF record. Anything
 * reached through an `include:` belongs to somebody else and is left alone.
 */

/** PTR names a provider hands out automatically, rather than one you chose. */
const GENERIC_PTR =
  /(^|\.)(\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3})|(^|\.)(ip|host|static|dynamic|dsl|pool|cust|client|node|vps|server|ec2|compute|cloud)[-.]?\d/i;

export interface PtrRecord {
  ip: string;
  /** The hostname the PTR points at, if any. UNTRUSTED. */
  pointer: string | null;
  /** The pointer resolves back to this same IP. */
  forwardConfirmed: boolean;
  generic: boolean;
}

export interface PtrAnalysis {
  domain: string;
  /** Addresses we judged, and why we believed they belong to the domain. */
  checked: PtrRecord[];
  /** True when the domain publishes no addresses of its own to check. */
  noOwnServers: boolean;
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface PtrOptions {
  /** IPs the domain publishes as its own (MX hosts, SPF a/mx targets). */
  addresses: readonly string[];
  /** Reverse lookups are two queries each; keep the budget honest. */
  maxAddresses?: number;
}

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
}

export async function analyzePtr(
  domain: string,
  resolver: DohResolver,
  options: PtrOptions,
): Promise<PtrAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const unique = [...new Set(options.addresses)].filter(isValidIpv4);
  const addresses = unique.slice(0, options.maxAddresses ?? 2);
  const checked: PtrRecord[] = [];

  for (const ip of addresses) {
    if (resolver.remainingBudget <= 2) break;

    const reverse = await resolver.query(reverseName(ip), 'PTR');
    for (const note of reverse.notes) ctx.notes.add(note);

    if (reverse.status === 'TIMEOUT' || reverse.status === 'ERROR') continue;

    const pointer = reverse.records[0]?.data.trim().replace(/\.$/, '').toLowerCase() ?? null;
    if (pointer === null) {
      checked.push({ ip, pointer: null, forwardConfirmed: false, generic: false });
      emit(ctx, 'PTR_MISSING', { offending_term: ip, domain: name });
      continue;
    }

    const generic = GENERIC_PTR.test(pointer);
    let forwardConfirmed = false;

    if (resolver.remainingBudget > 1) {
      const forward = await resolver.query(pointer, 'A');
      for (const note of forward.notes) ctx.notes.add(note);
      forwardConfirmed = forward.records.some((record) => record.data.trim() === ip);

      if (forward.status !== 'TIMEOUT' && forward.status !== 'ERROR' && !forwardConfirmed) {
        emit(ctx, 'FCRDNS_FAIL', { offending_term: ip, target: pointer });
      }
    }

    if (generic) {
      emit(ctx, 'PTR_GENERIC', { offending_term: ip, target: pointer, domain: name });
    }

    checked.push({ ip, pointer, forwardConfirmed, generic });
  }

  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain: name,
    checked,
    noOwnServers: unique.length === 0,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

/** 203.0.113.10 → 10.113.0.203.in-addr.arpa */
export function reverseName(ip: string): string {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

function emit(ctx: Ctx, code: string, vars: IssueVars): void {
  ctx.conditions.push(createCondition(code, vars));
}
