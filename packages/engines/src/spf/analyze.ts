import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  sortConditions,
  type Condition,
  type IssueVars,
} from '@maildoc/catalog';
import type { DohResolver, ResolverNote, TxtRecord } from '@maildoc/resolver';
import {
  SPF_APPROACHING_LOOKUP_LIMIT,
  SPF_MAX_DNS_LOOKUPS,
  SPF_MAX_MX_NAMES,
  SPF_MAX_RECURSION_DEPTH,
  SPF_MAX_VOID_LOOKUPS,
  TXT_STRING_MAX_BYTES,
  UDP_TRUNCATION_RISK_BYTES,
} from '@maildoc/shared';
import { containsMacro, isValidMacroString } from './macro.js';
import {
  isPrivateIpv4,
  isPrivateIpv6,
  isValidIpv4,
  isValidIpv6,
  isValidPrefix,
} from './ip.js';
import {
  isSpfRecord,
  looksLikeBrokenSpf,
  MECHANISM_NAMES,
  parseSpf,
  type ParsedSpf,
  type Qualifier,
  type SpfMechanism,
  type SpfModifier,
} from './parse.js';
import type { SpfAnalysis, SpfChainNode } from './types.js';

export interface SpfEngineOptions {
  /**
   * Cross-check the apex TXT lookup against a second resolver. Costs one extra
   * subrequest and is how we avoid diagnosing a record mid-propagation.
   */
  verifyApex?: boolean;
  /** include/redirect recursion depth guard. */
  maxDepth?: number;
  /**
   * Ceiling on chain nodes expanded. A diamond-shaped include graph is
   * legitimately re-walked (each path costs its own lookups), so this stops a
   * pathological record from burning CPU.
   */
  maxNodes?: number;
}

interface WalkContext {
  resolver: DohResolver;
  conditions: Condition[];
  lookups: number;
  lookupsExact: boolean;
  voidCount: number;
  voidDomains: string[];
  voidExact: boolean;
  notes: Set<ResolverNote>;
  nodes: number;
  maxNodes: number;
  maxDepth: number;
  verifyApex: boolean;
  /** A loop was found, so the chain can never be fully evaluated. */
  circular: boolean;
}

/**
 * Analyze a domain's SPF record — RFC 7208.
 *
 * Walks the full include/redirect chain, counts DNS-lookup-consuming terms and
 * void lookups exactly as a receiver would, and emits catalog codes. It never
 * throws: DNS trouble becomes a note and a partial result, never a wrong
 * verdict.
 */
export async function analyzeSpf(
  domain: string,
  resolver: DohResolver,
  options: SpfEngineOptions = {},
): Promise<SpfAnalysis> {
  const startQueries = resolver.queriesIssued;
  const context: WalkContext = {
    resolver,
    conditions: [],
    lookups: 0,
    lookupsExact: true,
    voidCount: 0,
    voidDomains: [],
    voidExact: true,
    notes: new Set(),
    nodes: 0,
    maxNodes: options.maxNodes ?? 64,
    maxDepth: options.maxDepth ?? SPF_MAX_RECURSION_DEPTH,
    verifyApex: options.verifyApex ?? true,
    circular: false,
  };

  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const root = await walk(context, name, 0, 'root', []);

  const parsed = root.record ? parseSpf(root.record) : null;
  const apex = parsed ? summarizeApex(parsed) : null;

  if (root.record && apex) {
    judgeApexPolicy(context, name, apex);
  }
  judgeLookupBudget(context);

  const conditions = sortConditions(dedupeConditions(context.conditions));

  return {
    domain: name,
    found: root.record !== null,
    record: root.record,
    records: root.records ?? [],
    parsed,
    terms: parsed?.terms ?? [],
    allQualifier: apex?.allQualifier ?? null,
    redirect: apex?.redirect ?? null,
    lookupCount: context.lookups,
    lookupCountExact: context.lookupsExact,
    voidLookupCount: context.voidCount,
    voidDomains: [...context.voidDomains],
    voidCountExact: context.voidExact,
    chain: root.node,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...context.notes],
  };
}

interface WalkResult {
  node: SpfChainNode;
  record: string | null;
  records?: string[];
}

async function walk(
  context: WalkContext,
  domain: string,
  depth: number,
  via: SpfChainNode['via'],
  ancestors: string[],
): Promise<WalkResult> {
  const node: SpfChainNode = {
    domain,
    via,
    depth,
    record: null,
    lookups: 0,
    status: 'OK',
    children: [],
  };

  if (context.nodes >= context.maxNodes || depth > context.maxDepth) {
    node.status = 'TRUNCATED';
    context.lookupsExact = false;
    context.voidExact = false;
    return { node, record: null };
  }
  context.nodes += 1;

  const result = await context.resolver.query(domain, 'TXT', {
    verify: depth === 0 && context.verifyApex,
  });
  for (const note of result.notes) context.notes.add(note);

  // Resolvers disagreeing about the apex record means the domain is mid-change;
  // say so rather than diagnosing a record that is already stale.
  if (depth === 0 && result.notes.includes('PROPAGATION_IN_PROGRESS')) {
    emit(context, 'PROPAGATION_IN_PROGRESS', { domain, record: 'SPF' });
  }

  if (result.notes.includes('BUDGET_EXCEEDED')) {
    node.status = 'TRUNCATED';
    context.lookupsExact = false;
    context.voidExact = false;
    return { node, record: null };
  }

  if (result.status === 'TIMEOUT' || result.status === 'ERROR') {
    node.status = 'UNRESOLVED';
    context.lookupsExact = false;
    context.voidExact = false;
    emit(context, 'RESOLVER_TIMEOUT', { domain, record: 'SPF' });
    return { node, record: null };
  }

  // A void lookup only counts when a mechanism caused it (RFC 7208 §4.6.4);
  // the apex query is ours, not the record's.
  if (depth > 0 && result.isVoid) countVoid(context, domain);

  if (depth === 0 && result.status === 'NXDOMAIN') {
    node.status = 'VOID';
    emit(context, 'DOMAIN_NXDOMAIN', { domain });
    return { node, record: null };
  }

  const txtRecords = result.txt;
  const spfRecords = txtRecords.filter((record) => isSpfRecord(record.value));

  if (spfRecords.length === 0) {
    node.status = 'NO_RECORD';
    if (depth === 0) {
      const broken = txtRecords.find((record) => looksLikeBrokenSpf(record.value));
      if (broken) {
        emit(context, 'SPF_INVALID_VERSION', { domain }, broken.value);
      } else {
        emit(context, 'SPF_RECORD_MISSING', { domain });
      }
    } else if (via === 'redirect') {
      // A redirect hands the whole policy over; nothing there is fatal.
      emit(context, 'SPF_REDIRECT_NXDOMAIN', { target: domain });
    } else {
      // include: pointing at a name with no SPF record is a permanent error
      // for the *including* domain.
      emit(context, 'SPF_INCLUDE_NXDOMAIN', { target: domain });
    }
    return { node, record: null, records: [] };
  }

  const values = spfRecords.map((record) => record.value);

  if (spfRecords.length > 1) {
    // More than one record is a PermError: a receiver stops here, so we do too
    // rather than arbitrarily analyzing one of them.
    node.status = 'MULTIPLE';
    emit(context, 'SPF_MULTIPLE_RECORDS', { domain, count: spfRecords.length }, values.join(' | '));
    return { node, record: null, records: values };
  }

  const record = spfRecords[0] as TxtRecord;
  node.record = record.value;

  if (depth === 0) {
    judgeRecordSize(context, record);
    judgeWhitespace(context, record.value);
  }

  const parsed = parseSpf(record.value);
  await analyzeTerms(context, node, parsed, [...ancestors, domain]);

  return { node, record: record.value, records: values };
}

async function analyzeTerms(
  context: WalkContext,
  node: SpfChainNode,
  parsed: ParsedSpf,
  path: string[],
): Promise<void> {
  const includeCounts = new Map<string, number>();
  const mechanismCounts = new Map<string, number>();
  const modifierCounts = new Map<string, number>();
  const pending: Array<{ target: string; via: 'include' | 'redirect' }> = [];
  let allMechanism: SpfMechanism | null = null;
  let redirect: SpfModifier | null = null;

  for (const term of parsed.terms) {
    if (term.kind === 'unknown') {
      emit(context, 'SPF_UNKNOWN_TERM', { offending_term: term.raw }, node.record ?? undefined);
      continue;
    }

    if (term.kind === 'modifier') {
      // `include=example.com` parses as a modifier named "include". It is a
      // mechanism written with the wrong separator, and receivers ignore it —
      // which silently unauthorises whatever it names.
      if ((MECHANISM_NAMES as readonly string[]).includes(term.name)) {
        emit(context, 'SPF_INVALID_TERM_SEPARATOR', { offending_term: term.raw });
        continue;
      }
      if (!isValidMacroString(term.value)) {
        emit(context, 'SPF_INVALID_MACRO', { offending_term: term.raw });
      }
      modifierCounts.set(term.name, (modifierCounts.get(term.name) ?? 0) + 1);
      if (term.name !== 'redirect' && term.name !== 'exp') {
        emit(context, 'SPF_UNKNOWN_MODIFIER', { offending_term: term.raw });
      }
      // An included record's exp= is never used by receivers (§6.2).
      if (term.name === 'exp' && node.depth > 0) {
        emit(context, 'SPF_EXP_IN_INCLUDE', { target: node.domain });
      }
      if (term.name === 'redirect' && redirect === null) redirect = term;
      continue;
    }

    if (/[A-Z]/.test(term.raw.replace(/^[+\-~?]/, '').split(':')[0] ?? '')) {
      emit(context, 'SPF_MECHANISM_CASE', { offending_term: term.raw });
    }
    const mechanismKey = term.raw.toLowerCase();
    mechanismCounts.set(mechanismKey, (mechanismCounts.get(mechanismKey) ?? 0) + 1);

    // Anything after `all` is never evaluated.
    if (allMechanism !== null) {
      emit(context, 'SPF_ALL_NOT_LAST', { offending_term: term.raw });
    }

    if (term.value !== null && containsMacro(term.value) && !isValidMacroString(term.value)) {
      emit(context, 'SPF_INVALID_MACRO', { offending_term: term.raw });
    }

    switch (term.name) {
      case 'all': {
        if (allMechanism === null) allMechanism = term;
        // A `+all` inside an included record hands the same free pass to
        // anyone, so it is worth flagging wherever it appears.
        if (node.depth > 0 && term.qualifier === '+') {
          emit(context, 'SPF_ALL_TOO_PERMISSIVE', {
            domain: node.domain,
            offending_term: term.raw,
          });
        }
        break;
      }

      case 'include': {
        spendLookup(context, node);
        const target = normalizeTarget(term.value);
        if (!target) {
          emit(context, 'SPF_UNKNOWN_TERM', { offending_term: term.raw });
          break;
        }
        includeCounts.set(target, (includeCounts.get(target) ?? 0) + 1);
        if (containsMacro(target)) break; // can't expand statically
        if (path.includes(target)) {
          emit(context, 'SPF_CIRCULAR_INCLUDE', {
            chain_path: [...path, target].join(' → '),
          });
          node.children.push(circularNode(target, node.depth + 1, 'include'));
          context.circular = true;
          break;
        }
        pending.push({ target, via: 'include' });
        break;
      }

      case 'a':
      case 'mx': {
        spendLookup(context, node);
        checkDualCidr(context, term);
        const target = normalizeTarget(term.value) ?? node.domain;
        if (!containsMacro(target)) {
          await probeTarget(context, target, term.name === 'mx' ? 'MX' : 'A');
        }
        break;
      }

      case 'ptr': {
        spendLookup(context, node);
        emit(context, 'SPF_PTR_MECHANISM', { offending_term: term.raw });
        break;
      }

      case 'exists': {
        spendLookup(context, node);
        const target = normalizeTarget(term.value);
        if (!target) {
          emit(context, 'SPF_UNKNOWN_TERM', { offending_term: term.raw });
          break;
        }
        if (!containsMacro(target)) await probeTarget(context, target, 'A');
        break;
      }

      case 'ip4': {
        checkIp4(context, term);
        break;
      }

      case 'ip6': {
        checkIp6(context, term);
        break;
      }
    }
  }

  for (const [target, count] of includeCounts) {
    if (count > 1) emit(context, 'SPF_DUPLICATE_INCLUDE', { target, count });
  }

  for (const [name, count] of modifierCounts) {
    // RFC 7208 §6: redirect and exp may appear at most once each.
    if (count > 1 && (name === 'redirect' || name === 'exp')) {
      emit(context, 'SPF_DUPLICATE_MODIFIER', { offending_term: `${name}=` });
    }
  }

  for (const [raw, count] of mechanismCounts) {
    // include duplicates have their own, more useful condition.
    if (count > 1 && !raw.startsWith('include:')) {
      emit(context, 'SPF_DUPLICATE_MECHANISM', { offending_term: raw });
    }
  }

  if (redirect !== null) {
    const target = normalizeTarget(redirect.value);
    if (allMechanism !== null) {
      // With an `all` mechanism present, redirect= is ignored entirely — and
      // so is the DNS lookup it would have cost.
      emit(context, 'SPF_REDIRECT_ALL_CONFLICT', { target: target ?? redirect.value });
    } else if (target && !containsMacro(target)) {
      spendLookup(context, node);
      if (path.includes(target)) {
        emit(context, 'SPF_REDIRECT_LOOP', { chain_path: [...path, target].join(' → ') });
        node.children.push(circularNode(target, node.depth + 1, 'redirect'));
        context.circular = true;
      } else {
        pending.push({ target, via: 'redirect' });
      }
    }
  }

  for (const next of pending) {
    const child = await walk(context, next.target, node.depth + 1, next.via, path);
    node.children.push(child.node);
  }
}

interface ApexSummary {
  allQualifier: Qualifier | null;
  redirect: string | null;
}

function summarizeApex(parsed: ParsedSpf): ApexSummary {
  let allQualifier: Qualifier | null = null;
  let redirect: string | null = null;

  for (const term of parsed.terms) {
    if (term.kind === 'mechanism' && term.name === 'all' && allQualifier === null) {
      allQualifier = term.qualifier;
    }
    if (term.kind === 'modifier' && term.name === 'redirect' && redirect === null) {
      redirect = term.value;
    }
  }
  return { allQualifier, redirect };
}

/** The apex policy questions: does the record ever say "no", and how firmly? */
function judgeApexPolicy(context: WalkContext, domain: string, apex: ApexSummary): void {
  const { allQualifier, redirect } = apex;

  if (allQualifier === null) {
    // A record with redirect= and no `all` inherits the target's policy, which
    // is legitimate.
    if (redirect === null) emit(context, 'SPF_ALL_MISSING', { domain });
    return;
  }

  if (allQualifier === '+' || allQualifier === '?') {
    emit(context, 'SPF_ALL_TOO_PERMISSIVE', { domain, offending_term: `${allQualifier}all` });
    return;
  }

  if (allQualifier === '~') emit(context, 'SPF_SOFTFAIL_ADVISORY', { domain });
}

function judgeLookupBudget(context: WalkContext): void {
  if (context.lookups > SPF_MAX_DNS_LOOKUPS) {
    emit(context, 'SPF_LOOKUP_LIMIT_EXCEEDED', { count: context.lookups });
  } else if (context.lookups >= SPF_APPROACHING_LOOKUP_LIMIT) {
    emit(context, 'SPF_LOOKUP_APPROACHING_LIMIT', { count: context.lookups });
  }

  if (context.voidCount > SPF_MAX_VOID_LOOKUPS) {
    emit(context, 'SPF_VOID_LOOKUP_EXCEEDED', {
      count: context.voidCount,
      void_domains: context.voidDomains.join(', '),
    });
  }
}

function judgeWhitespace(context: WalkContext, record: string): void {
  if (/\s{2,}/.test(record) || record !== record.trim()) {
    emit(context, 'SPF_EXTRA_WHITESPACE', {});
  }
}

function judgeRecordSize(context: WalkContext, record: TxtRecord): void {
  // Only a resolver that preserves character-strings can tell us whether an
  // over-255-byte record was split properly. Google's DoH concatenates them
  // away, and accusing a correctly-split record of being malformed is exactly
  // the kind of wrong answer that costs a diagnosis its credibility.
  if (record.segmented) {
    const overlong = record.strings.some((part) => part.length > TXT_STRING_MAX_BYTES);
    const unsplit = record.strings.length === 1 && record.value.length > TXT_STRING_MAX_BYTES;
    if (overlong || unsplit) {
      emit(context, 'SPF_RECORD_STRING_TOO_LONG', { count: record.value.length });
    }
  }
  if (record.bytes > UDP_TRUNCATION_RISK_BYTES) {
    emit(context, 'SPF_UDP_TRUNCATION_RISK', { count: record.bytes });
  }
}

function checkIp4(context: WalkContext, term: SpfMechanism): void {
  const address = term.value;
  if (!address || !isValidIpv4(address)) {
    emit(context, 'SPF_INVALID_IPV4', { offending_term: term.raw });
    return;
  }
  const prefix = term.cidr4 ?? term.cidr6;
  if (prefix !== null && !isValidPrefix(prefix, 32)) {
    emit(context, 'SPF_INVALID_IPV4_CIDR', { offending_term: term.raw });
    return;
  }
  if (isPrivateIpv4(address)) {
    emit(context, 'SPF_PRIVATE_IP_IN_SPF', { offending_term: term.raw });
  }
}

function checkIp6(context: WalkContext, term: SpfMechanism): void {
  const address = term.value;
  if (!address || !isValidIpv6(address)) {
    emit(context, 'SPF_INVALID_IPV6', { offending_term: term.raw });
    return;
  }
  const prefix = term.cidr4 ?? term.cidr6;
  if (prefix !== null && !isValidPrefix(prefix, 128)) {
    emit(context, 'SPF_INVALID_IPV6_CIDR', { offending_term: term.raw });
    return;
  }
  if (isPrivateIpv6(address)) {
    emit(context, 'SPF_PRIVATE_IP_IN_SPF', { offending_term: term.raw });
  }
}

/** `a` and `mx` may carry dual-CIDR prefixes: /24 for IPv4, //64 for IPv6. */
function checkDualCidr(context: WalkContext, term: SpfMechanism): void {
  if (term.cidr4 !== null && !isValidPrefix(term.cidr4, 32)) {
    emit(context, 'SPF_INVALID_IPV4_CIDR', { offending_term: term.raw });
  }
  if (term.cidr6 !== null && !isValidPrefix(term.cidr6, 128)) {
    emit(context, 'SPF_INVALID_IPV6_CIDR', { offending_term: term.raw });
  }
}

/**
 * Resolve an `a`/`mx`/`exists` target to see whether it answers, and — for
 * `mx` — whether it stays inside the separate 10-name cap that RFC 7208 §4.6.4
 * puts on a single mx mechanism.
 *
 * Skipped when the query budget is nearly spent: an approximate void count is
 * reported as approximate, never as fact.
 */
async function probeTarget(
  context: WalkContext,
  target: string,
  type: 'A' | 'MX',
): Promise<void> {
  if (context.resolver.remainingBudget <= 3) {
    context.voidExact = false;
    return;
  }
  const result = await context.resolver.query(target, type);
  for (const note of result.notes) context.notes.add(note);

  if (
    result.notes.includes('BUDGET_EXCEEDED') ||
    result.status === 'TIMEOUT' ||
    result.status === 'ERROR'
  ) {
    context.voidExact = false;
    return;
  }

  if (result.isVoid) {
    countVoid(context, target);
    emit(context, type === 'MX' ? 'SPF_MX_TARGET_VOID' : 'SPF_A_TARGET_VOID', { target });
    return;
  }

  if (type === 'MX' && result.records.length > SPF_MAX_MX_NAMES) {
    emit(context, 'SPF_MX_LIMIT_EXCEEDED', { target, count: result.records.length });
  }
}

function countVoid(context: WalkContext, domain: string): void {
  context.voidCount += 1;
  if (!context.voidDomains.includes(domain)) context.voidDomains.push(domain);
}

function spendLookup(context: WalkContext, node: SpfChainNode): void {
  context.lookups += 1;
  node.lookups += 1;
}

function normalizeTarget(value: string | null): string | null {
  if (!value) return null;
  const target = value.trim().replace(/\.$/, '').toLowerCase();
  return target || null;
}

function circularNode(domain: string, depth: number, via: 'include' | 'redirect'): SpfChainNode {
  return { domain, via, depth, record: null, lookups: 0, status: 'CIRCULAR', children: [] };
}

function emit(
  context: WalkContext,
  code: string,
  vars: IssueVars,
  evidence?: string,
): void {
  context.conditions.push(
    createCondition(code, vars, evidence === undefined ? {} : { evidence }),
  );
}
