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
import { isValidIpv4, isValidIpv6 } from '../spf/ip.js';

export interface MxHost {
  priority: number;
  /** The mail exchanger hostname. UNTRUSTED — escape before rendering. */
  host: string;
  addresses: string[];
  resolved: boolean;
  isCname: boolean;
}

export interface MxAnalysis {
  domain: string;
  found: boolean;
  /** True when the domain publishes a null MX: it accepts no mail, by design. */
  acceptsNoMail: boolean;
  hosts: MxHost[];
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface MxEngineOptions {
  /** Resolve at most this many MX targets to addresses. */
  maxTargets?: number;
  /** Skip address resolution entirely when the subrequest budget is tight. */
  resolveTargets?: boolean;
}

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
}

/**
 * Analyze a domain's mail exchangers — RFC 5321 §5.1, RFC 7505 (null MX).
 *
 * A domain with no MX is not automatically broken: plenty of domains only send.
 * We report it, we explain the null-MX alternative, and we never pretend a
 * send-only domain is misconfigured.
 */
export async function analyzeMx(
  domain: string,
  resolver: DohResolver,
  options: MxEngineOptions = {},
): Promise<MxAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const result = await resolver.query(name, 'MX');
  for (const note of result.notes) ctx.notes.add(note);

  if (result.status === 'TIMEOUT' || result.status === 'ERROR') {
    emit(ctx, 'RESOLVER_TIMEOUT', { domain: name, record: 'MX' });
    return finish(ctx, name, false, false, [], resolver, startQueries);
  }

  const hosts = result.records
    .map((record) => parseMx(record.data))
    .filter((host): host is { priority: number; host: string } => host !== null);

  if (hosts.length === 0) {
    emit(ctx, 'MX_MISSING', { domain: name });
    return finish(ctx, name, false, false, [], resolver, startQueries);
  }

  // RFC 7505: a single MX with priority 0 and a target of "." means this
  // domain accepts no mail at all — a statement, not a fault.
  const nullMx = hosts.length === 1 && hosts[0]?.host === '' && hosts[0]?.priority === 0;
  if (nullMx) {
    emit(ctx, 'MX_NULL', { domain: name });
    return finish(ctx, name, true, true, [], resolver, startQueries);
  }

  // Deliberately no finding for mail exchangers sharing a priority.
  //
  // Equal priority is how load balancing is spelled in DNS, and it is what
  // Google Workspace, Microsoft 365, Proofpoint and Mimecast all publish. It
  // was being reported as a fault, once per shared priority level, on domains
  // whose mail routing is entirely correct.

  const maxTargets = options.maxTargets ?? 5;
  const resolveTargets = options.resolveTargets ?? true;
  const detailed: MxHost[] = [];

  for (const host of hosts) {
    const entry: MxHost = {
      priority: host.priority,
      host: host.host,
      addresses: [],
      resolved: false,
      isCname: false,
    };

    if (isValidIpv4(host.host) || isValidIpv6(host.host)) {
      emit(ctx, 'MX_POINTS_TO_IP', { offending_term: host.host, domain: name });
      detailed.push(entry);
      continue;
    }

    if (!resolveTargets || detailed.length >= maxTargets || resolver.remainingBudget <= 2) {
      detailed.push(entry);
      continue;
    }

    const addresses = await resolver.query(host.host, 'A');
    for (const note of addresses.notes) ctx.notes.add(note);

    if (addresses.status === 'TIMEOUT' || addresses.status === 'ERROR') {
      detailed.push(entry);
      continue;
    }

    entry.addresses = addresses.records.map((record) => record.data);
    entry.resolved = entry.addresses.length > 0;
    // The answer chain shows a CNAME when the target is an alias, which RFC
    // 5321 forbids for a mail exchanger.
    entry.isCname = addresses.answers.some((answer) => answer.type === 5);

    if (entry.isCname) emit(ctx, 'MX_TARGET_IS_CNAME', { target: host.host });
    if (!entry.resolved) emit(ctx, 'MX_TARGET_NO_ADDRESS', { target: host.host, domain: name });

    detailed.push(entry);
  }

  // Redundancy is about reachable addresses, not hostnames: one MX name backed
  // by several addresses is exactly how the large providers publish.
  const totalAddresses = detailed.reduce((sum, host) => sum + host.addresses.length, 0);
  if (detailed.length === 1 && totalAddresses <= 1 && detailed[0]?.resolved === true) {
    emit(ctx, 'MX_SINGLE_POINT_OF_FAILURE', { domain: name });
  }

  return finish(ctx, name, true, false, detailed, resolver, startQueries);
}

/** DoH renders MX rdata as `10 mail.example.com.` */
function parseMx(data: string): { priority: number; host: string } | null {
  const match = /^\s*(\d+)\s+(\S*)\s*$/.exec(data);
  if (!match) return null;
  const priority = Number(match[1]);
  const host = (match[2] ?? '').replace(/\.$/, '').toLowerCase();
  return { priority, host };
}

function finish(
  ctx: Ctx,
  domain: string,
  found: boolean,
  acceptsNoMail: boolean,
  hosts: MxHost[],
  resolver: DohResolver,
  startQueries: number,
): MxAnalysis {
  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain,
    found,
    acceptsNoMail,
    hosts,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

function emit(ctx: Ctx, code: string, vars: IssueVars): void {
  ctx.conditions.push(createCondition(code, vars));
}
