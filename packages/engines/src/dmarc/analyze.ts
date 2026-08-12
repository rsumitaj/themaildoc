import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  sortConditions,
  type Condition,
  type IssueVars,
} from '@maildoc/catalog';
import type { DohResolver, ResolverNote } from '@maildoc/resolver';
import { TXT_STRING_MAX_BYTES, UDP_TRUNCATION_RISK_BYTES } from '@maildoc/shared';
import { discoverDmarc, type DmarcDiscovery } from './discover.js';
import {
  isValidFo,
  OBSOLETE_TAGS,
  parseDmarc,
  parseReportUris,
  POLICY_RANK,
  POLICY_VALUES,
  type DmarcPolicy,
  type ParsedDmarc,
} from './parse.js';
import type { DmarcAnalysis, EdvResult } from './types.js';

export interface DmarcEngineOptions {
  /** Cross-check the author domain's record against a second resolver. */
  verifyApex?: boolean;
  /** External destinations to verify. Each costs one subrequest. */
  maxEdvChecks?: number;
  /**
   * Tree-walk query ceiling. Defaults to the spec's 8; the orchestrator lowers
   * it when other records have already spent the request's subrequest budget.
   */
  maxQueries?: number;
}

/**
 * Generic top-level domains where `psd=y` is certainly wrong. Kept to a short,
 * safe list on purpose: a ccTLD registry legitimately publishing psd=y must
 * never be told it is misconfigured, and we have no Public Suffix List to
 * consult (RFC 9989 removed the need for one).
 */
const GENERIC_TLDS = new Set([
  'com', 'net', 'org', 'io', 'co', 'dev', 'app', 'ai', 'me', 'info', 'biz', 'xyz',
]);

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
  domain: string;
}

/**
 * Analyze a domain's DMARC — RFC 9989, with reporting rules from RFC 9990 and
 * RFC 9991.
 *
 * Three behaviours here differ from most checkers, and each follows the current
 * standard rather than the retired one:
 *
 *   - A record with no `p` is valid and means `p=none` (§4.8). It is not
 *     discarded, so we report it as monitoring-only rather than as broken.
 *   - When the record was inherited from a parent, the policy governing this
 *     domain is `sp`, not `p`.
 *   - `t=y` overrides the published policy with `none`, so the effective
 *     enforcement — the one spoofability depends on — is not what `p` says.
 */
export async function analyzeDmarc(
  domain: string,
  resolver: DohResolver,
  options: DmarcEngineOptions = {},
): Promise<DmarcAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set(), domain: name };

  const discovery = await discoverDmarc(name, resolver, {
    verify: options.verifyApex ?? true,
    ...(options.maxQueries === undefined ? {} : { maxQueries: options.maxQueries }),
  });
  for (const note of discovery.notes) ctx.notes.add(note);

  if (!discovery.found) {
    // A record that receivers discard still needs explaining — "no DMARC
    // record" is true of the outcome and useless to whoever published one.
    const candidate = discovery.candidates[0];
    if (candidate !== undefined) {
      const broken = parseDmarc(candidate);
      judgeSyntax(ctx, broken, name);
      return finish(ctx, name, discovery, broken, resolver, startQueries, []);
    }
    reportNoRecord(ctx, discovery);
    return finish(ctx, name, discovery, null, resolver, startQueries, []);
  }

  if (discovery.multipleAt !== null) {
    emit(ctx, 'DMARC_MULTIPLE_RECORDS', {
      domain: discovery.multipleAt,
      count: discovery.multipleCount,
    });
  }

  if (discovery.source === 'parent') {
    emit(ctx, 'DMARC_POLICY_INHERITED', {
      domain: name,
      source_domain: discovery.foundAt ?? '',
    });
  }

  const record = discovery.record as string;
  const parsed = parseDmarc(record);

  const ignored = judgeSyntax(ctx, parsed, name);
  judgeSize(ctx, record);

  const tags = parsed.tags;
  const policy = judgePolicy(ctx, tags);
  const subdomainPolicy = judgeSubdomainPolicy(ctx, tags, policy, name);
  const nonExistentPolicy = judgeNonExistentPolicy(ctx, tags, subdomainPolicy);

  // A record inherited from a parent governs this domain through sp.
  const appliedPolicy = discovery.source === 'parent' ? subdomainPolicy : policy;
  const testMode = tags['t'] === 'y';
  const effectivePolicy: DmarcPolicy = ignored ? 'none' : testMode ? 'none' : appliedPolicy;

  judgeTestMode(ctx, tags, appliedPolicy);
  const alignment = judgeAlignment(ctx, tags, name);
  judgePsd(ctx, tags, name);
  judgeObsolete(ctx, tags);

  if (!ignored) judgeAppliedPolicy(ctx, name, appliedPolicy, testMode);

  judgeFailureOptions(ctx, tags);
  const rua = judgeReportTag(ctx, tags['rua'], 'rua', name);
  const ruf = judgeReportTag(ctx, tags['ruf'], 'ruf', name);

  if (tags['rua'] === undefined) {
    emit(ctx, 'DMARC_RUA_MISSING', { domain: name });
  }
  if (effectivePolicy !== 'none' && rua.length === 0) {
    emit(ctx, 'DMARC_BLIND_REJECT', { domain: name, policy: appliedPolicy });
  }

  const orgDomain = discovery.foundAt ?? name;
  const edv = await verifyExternalDestinations(
    ctx,
    resolver,
    orgDomain,
    [...rua, ...ruf],
    options.maxEdvChecks ?? 3,
  );

  return finish(ctx, name, discovery, parsed, resolver, startQueries, edv, {
    policy,
    subdomainPolicy,
    nonExistentPolicy,
    appliedPolicy,
    effectivePolicy,
    ignored,
    testMode,
    alignment,
    rua,
    ruf,
  });
}

// ---------------------------------------------------------------------------

function reportNoRecord(ctx: Ctx, discovery: DmarcDiscovery): void {
  if (discovery.unresolved) {
    emit(ctx, 'RESOLVER_TIMEOUT', { domain: ctx.domain, record: 'DMARC' });
    return;
  }
  if (discovery.cnameLoop) {
    emit(ctx, 'DMARC_CNAME_LOOP', {
      domain: ctx.domain,
      chain_path: discovery.cnameTarget ?? '',
    });
    return;
  }
  if (discovery.cnameTarget !== null) {
    emit(ctx, 'DMARC_CNAME_BROKEN', { domain: ctx.domain, target: discovery.cnameTarget });
    return;
  }
  if (discovery.multipleAt !== null) {
    emit(ctx, 'DMARC_MULTIPLE_RECORDS', {
      domain: discovery.multipleAt,
      count: discovery.multipleCount,
    });
    return;
  }
  if (discovery.capped) {
    emit(ctx, 'DMARC_TREE_WALK_CAPPED', { domain: ctx.domain });
    return;
  }
  emit(ctx, 'DMARC_RECORD_MISSING', { domain: ctx.domain });
}

/** Returns true when receivers will ignore the record outright. */
function judgeSyntax(ctx: Ctx, parsed: ParsedDmarc, domain: string): boolean {
  if (parsed.order.length === 0) {
    emit(ctx, 'DMARC_UNPARSEABLE', { domain });
    return true;
  }

  let ignored = false;
  const version = parsed.tags['v'];

  if (version === undefined || version !== 'DMARC1') {
    emit(ctx, 'DMARC_V_CASE_INVALID', {});
    ignored = true;
  } else if (parsed.order[0] !== 'v') {
    emit(ctx, 'DMARC_V_OUT_OF_ORDER', {});
    ignored = true;
  }

  for (const segment of parsed.malformed) {
    emit(ctx, 'DMARC_SYNTAX_DELIMITER', { offending_term: segment });
  }
  for (const duplicate of new Set(parsed.duplicates)) {
    emit(ctx, 'DMARC_DUPLICATE_TAG', { offending_term: duplicate });
  }
  if (parsed.uppercase.length > 0) {
    emit(ctx, 'DMARC_UPPERCASE_TAGS', { offending_term: [...new Set(parsed.uppercase)].join(', ') });
  }
  // A record carrying only `v=DMARC1` parses but says nothing.
  if (parsed.order.length === 1 && parsed.order[0] === 'v') {
    emit(ctx, 'DMARC_EMPTY_RECORD', { domain });
  }

  return ignored;
}

function judgeSize(ctx: Ctx, record: string): void {
  if (record.length > TXT_STRING_MAX_BYTES) {
    emit(ctx, 'DMARC_STRING_TOO_LONG', { count: record.length });
  }
  if (record.length > UDP_TRUNCATION_RISK_BYTES) {
    emit(ctx, 'DMARC_UDP_TRUNCATION', { count: record.length });
  }
}

function judgePolicy(ctx: Ctx, tags: Record<string, string>): DmarcPolicy {
  const p = tags['p'];
  if (p === undefined) {
    // §4.8: a valid record with no p is treated as p=none. The record works —
    // it just protects nothing, which is exactly why this goes unnoticed.
    emit(ctx, 'DMARC_P_MISSING', {});
    return 'none';
  }
  if (!POLICY_VALUES.includes(p)) {
    emit(ctx, 'DMARC_P_INVALID', { offending_term: p });
    return 'none';
  }
  return p as DmarcPolicy;
}

function judgeSubdomainPolicy(
  ctx: Ctx,
  tags: Record<string, string>,
  policy: DmarcPolicy,
  domain: string,
): DmarcPolicy {
  const sp = tags['sp'];
  if (sp === undefined) return policy;
  if (!POLICY_VALUES.includes(sp)) {
    emit(ctx, 'DMARC_SP_INVALID', { offending_term: sp });
    return policy;
  }
  const value = sp as DmarcPolicy;
  if (POLICY_RANK[value] < POLICY_RANK[policy]) {
    emit(ctx, 'DMARC_WEAKER_SP', {
      domain,
      policy,
      subdomain_policy: value,
    });
  }
  return value;
}

function judgeNonExistentPolicy(
  ctx: Ctx,
  tags: Record<string, string>,
  subdomainPolicy: DmarcPolicy,
): DmarcPolicy {
  const np = tags['np'];
  if (np === undefined) return subdomainPolicy;
  if (!POLICY_VALUES.includes(np)) {
    emit(ctx, 'DMARC_NP_INVALID', { offending_term: np });
    return subdomainPolicy;
  }
  const value = np as DmarcPolicy;
  if (POLICY_RANK[value] < POLICY_RANK[subdomainPolicy]) {
    emit(ctx, 'DMARC_WEAKER_NP', {
      np_policy: value,
      subdomain_policy: subdomainPolicy,
    });
  }
  return value;
}

function judgeTestMode(
  ctx: Ctx,
  tags: Record<string, string>,
  appliedPolicy: DmarcPolicy,
): void {
  const t = tags['t'];
  if (t === undefined) return;
  if (t !== 'y' && t !== 'n') {
    emit(ctx, 'DMARC_T_INVALID', { offending_term: t });
    return;
  }
  if (t === 'y' && appliedPolicy !== 'none') {
    emit(ctx, 'DMARC_STALE_TEST_MODE', { policy: appliedPolicy });
  }
}

function judgeAppliedPolicy(
  ctx: Ctx,
  domain: string,
  applied: DmarcPolicy,
  testMode: boolean,
): void {
  // Test mode already has its own, louder condition.
  if (testMode) return;
  if (applied === 'none') emit(ctx, 'DMARC_P_NONE', { domain });
  else if (applied === 'quarantine') emit(ctx, 'DMARC_P_QUARANTINE', { domain });
}

function judgeAlignment(
  ctx: Ctx,
  tags: Record<string, string>,
  domain: string,
): { dkim: 'r' | 's'; spf: 'r' | 's' } {
  const read = (tag: string, invalidCode: string, strictCode: string): 'r' | 's' => {
    const value = tags[tag];
    if (value === undefined) return 'r';
    if (value !== 'r' && value !== 's') {
      emit(ctx, invalidCode, { offending_term: value });
      return 'r';
    }
    if (value === 's') emit(ctx, strictCode, { domain });
    return value;
  };

  return {
    dkim: read('adkim', 'DMARC_ADKIM_INVALID', 'DMARC_ADKIM_STRICT_ADV'),
    spf: read('aspf', 'DMARC_ASPF_INVALID', 'DMARC_ASPF_STRICT_ADV'),
  };
}

function judgePsd(ctx: Ctx, tags: Record<string, string>, domain: string): void {
  const psd = tags['psd'];
  if (psd === undefined) return;
  // §4.7.6 allows y, n and u. Rejecting u is a bug other checkers still have.
  if (psd !== 'y' && psd !== 'n' && psd !== 'u') {
    emit(ctx, 'DMARC_PSD_INVALID', { offending_term: psd });
    return;
  }
  if (psd !== 'y') return;

  const labels = domain.split('.');
  const tld = labels[labels.length - 1] ?? '';
  if (labels.length >= 2 && GENERIC_TLDS.has(tld)) {
    emit(ctx, 'DMARC_ORG_DOMAIN_IS_PSD', { domain });
  }
}

function judgeObsolete(ctx: Ctx, tags: Record<string, string>): void {
  const present = OBSOLETE_TAGS.filter((tag) => tags[tag] !== undefined);
  if (present.length > 0) {
    emit(ctx, 'DMARC_OBSOLETE_TAGS', { offending_term: present.join(', ') });
  }
}

/** Validates a rua/ruf value and returns the addresses receivers would use. */
function judgeReportTag(
  ctx: Ctx,
  value: string | undefined,
  kind: 'rua' | 'ruf',
  domain: string,
): string[] {
  if (value === undefined) return [];

  const { uris, spaceDelimited } = parseReportUris(value);
  if (spaceDelimited && kind === 'rua') emit(ctx, 'DMARC_RUA_BAD_DELIMITER', {});
  if (uris.length > 3 && kind === 'rua') emit(ctx, 'DMARC_TOO_MANY_URIS', { count: uris.length });

  const usable: string[] = [];
  for (const uri of uris) {
    if (!uri.hasMailto) {
      emit(ctx, kind === 'rua' ? 'DMARC_RUA_NO_MAILTO' : 'DMARC_RUF_NO_MAILTO', {
        offending_term: uri.raw,
        domain,
      });
      continue;
    }
    if (/[,!]/.test(uri.address)) {
      emit(ctx, 'DMARC_URI_UNENCODED', { offending_term: uri.raw });
      continue;
    }
    if (uri.size !== null && !/^![0-9]+[kmgt]?$/i.test(uri.size)) {
      if (kind === 'rua') emit(ctx, 'DMARC_RUA_SIZE_INVALID', { offending_term: uri.size });
    }
    if (!uri.wellFormed && uri.size === null) {
      emit(ctx, kind === 'rua' ? 'DMARC_RUA_MALFORMED' : 'DMARC_RUF_MALFORMED', {
        offending_term: uri.raw,
      });
      continue;
    }
    usable.push(uri.address);
  }
  return usable;
}

function judgeFailureOptions(ctx: Ctx, tags: Record<string, string>): void {
  const fo = tags['fo'];
  if (fo !== undefined && !isValidFo(fo)) {
    emit(ctx, 'DMARC_FO_INVALID', { offending_term: fo });
  }
}

/**
 * RFC 9990 §4 / RFC 9991 §5: a destination outside the domain's own
 * organizational domain must publish permission at
 * `<org-domain>._report._dmarc.<destination>`.
 *
 * A lookup that fails for transport reasons is reported as unverified — never
 * as unauthorized. Telling somebody their reporting is broken because a
 * nameserver was slow is exactly the sort of wrong answer that costs trust.
 */
async function verifyExternalDestinations(
  ctx: Ctx,
  resolver: DohResolver,
  orgDomain: string,
  addresses: string[],
  maxChecks: number,
): Promise<EdvResult[]> {
  const destinations: string[] = [];
  // An address inside the domain needs no authorisation and always receives.
  // Whether one exists decides how bad an unauthorised external one is: losing
  // a copy is not the same as being blind.
  let hasOwnAddress = false;

  for (const address of addresses) {
    const at = address.lastIndexOf('@');
    if (at === -1) continue;
    const destination = address.slice(at + 1).toLowerCase().replace(/\.$/, '');
    if (!destination) continue;
    if (destination === orgDomain || destination.endsWith(`.${orgDomain}`)) {
      hasOwnAddress = true;
      continue;
    }
    if (!destinations.includes(destination)) destinations.push(destination);
  }

  const results: EdvResult[] = [];
  for (const destination of destinations.slice(0, maxChecks)) {
    if (resolver.remainingBudget <= 2) break;

    const authName = `${orgDomain}._report._dmarc.${destination}`;
    const result = await resolver.query(authName, 'TXT');
    for (const note of result.notes) ctx.notes.add(note);

    if (
      result.notes.includes('BUDGET_EXCEEDED') ||
      result.status === 'TIMEOUT' ||
      result.status === 'ERROR'
    ) {
      results.push({ destination, status: 'UNVERIFIED' });
      emit(ctx, 'DMARC_EDV_UNVERIFIED', { target: destination });
      continue;
    }

    const values = result.txt.map((txt) => txt.value);
    if (values.length === 0) {
      results.push({ destination, status: 'MISSING' });
      emit(
        ctx,
        hasOwnAddress ? 'DMARC_EDV_MISSING_PARTIAL' : 'DMARC_EDV_MISSING',
        { domain: orgDomain, target: destination },
      );
      continue;
    }
    if (!values.some((value) => /^\s*v\s*=\s*DMARC1\b/i.test(value))) {
      results.push({ destination, status: 'MALFORMED' });
      emit(
        ctx,
        hasOwnAddress ? 'DMARC_EDV_MALFORMED_PARTIAL' : 'DMARC_EDV_MALFORMED',
        { domain: orgDomain, target: destination },
      );
      continue;
    }
    results.push({ destination, status: 'AUTHORIZED' });
  }

  return results;
}

// ---------------------------------------------------------------------------

interface Resolved {
  policy: DmarcPolicy;
  subdomainPolicy: DmarcPolicy;
  nonExistentPolicy: DmarcPolicy;
  appliedPolicy: DmarcPolicy;
  effectivePolicy: DmarcPolicy;
  ignored: boolean;
  testMode: boolean;
  alignment: { dkim: 'r' | 's'; spf: 'r' | 's' };
  rua: string[];
  ruf: string[];
}

function finish(
  ctx: Ctx,
  domain: string,
  discovery: DmarcDiscovery,
  parsed: ParsedDmarc | null,
  resolver: DohResolver,
  startQueries: number,
  edv: EdvResult[],
  resolved?: Resolved,
): DmarcAnalysis {
  const conditions = sortConditions(dedupeConditions(ctx.conditions));

  return {
    domain,
    found: discovery.found,
    record: discovery.record,
    discovery,
    parsed,
    tags: parsed?.tags ?? {},
    policy: resolved?.policy ?? 'none',
    subdomainPolicy: resolved?.subdomainPolicy ?? 'none',
    nonExistentPolicy: resolved?.nonExistentPolicy ?? 'none',
    appliedPolicy: resolved?.appliedPolicy ?? 'none',
    ignored: resolved?.ignored ?? !discovery.found,
    testMode: resolved?.testMode ?? false,
    effectivePolicy: resolved?.effectivePolicy ?? 'none',
    alignment: resolved?.alignment ?? { dkim: 'r', spf: 'r' },
    rua: resolved?.rua ?? [],
    ruf: resolved?.ruf ?? [],
    edv,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

function emit(ctx: Ctx, code: string, vars: IssueVars, evidence?: string): void {
  ctx.conditions.push(createCondition(code, vars, evidence === undefined ? {} : { evidence }));
}
