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

/** TLS-RPT (RFC 8460), BIMI (Internet-Draft) and CAA (RFC 8659). */

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
}

interface BaseAnalysis {
  domain: string;
  found: boolean;
  /** The record as published. UNTRUSTED — escape before rendering. */
  record: string | null;
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface TlsRptAnalysis extends BaseAnalysis {
  destinations: string[];
}

export interface BimiAnalysis extends BaseAnalysis {
  logo: string | null;
  authority: string | null;
  declined: boolean;
}

export interface CaaAnalysis extends BaseAnalysis {
  issuers: string[];
  wildcardIssuers: string[];
  forbidsAll: boolean;
}

// ---------------------------------------------------------------------------

/** TLS-RPT — RFC 8460 §3. */
export async function analyzeTlsRpt(
  domain: string,
  resolver: DohResolver,
): Promise<TlsRptAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const result = await resolver.query(`_smtp._tls.${name}`, 'TXT');
  for (const note of result.notes) ctx.notes.add(note);

  const candidates = result.txt.map((txt) => txt.value).filter((value) => /v\s*=\s*TLSRPT/i.test(value));

  if (candidates.length === 0) {
    emit(ctx, 'TLSRPT_MISSING', { domain: name });
    return { ...base(ctx, name, false, null, resolver, startQueries), destinations: [] };
  }

  const record = candidates[0] as string;
  const tags = parseTags(record, ';');

  // The version string is case-sensitive.
  if (tags['v'] !== 'TLSRPTv1') {
    emit(ctx, 'TLSRPT_INVALID', { domain: name }, record);
    return { ...base(ctx, name, true, record, resolver, startQueries), destinations: [] };
  }

  const rua = tags['rua'];
  if (rua === undefined || rua.trim() === '') {
    emit(ctx, 'TLSRPT_INVALID', { domain: name }, record);
    return { ...base(ctx, name, true, record, resolver, startQueries), destinations: [] };
  }

  const destinations: string[] = [];
  for (const entry of rua.split(',').map((part) => part.trim()).filter(Boolean)) {
    if (/^mailto:[^\s@]+@[^\s@]+\.[a-z0-9-]+$/i.test(entry) || /^https:\/\/\S+$/i.test(entry)) {
      destinations.push(entry);
    } else {
      emit(ctx, 'TLSRPT_RUA_INVALID', { offending_term: entry, domain: name });
    }
  }

  return { ...base(ctx, name, true, record, resolver, startQueries), destinations };
}

// ---------------------------------------------------------------------------

/**
 * BIMI — draft-brand-indicators-for-message-identification §4.3.
 *
 * `dmarcPolicy` is the *effective* policy from the DMARC engine, because a
 * BIMI record only ever displays for a domain that actually enforces.
 */
export async function analyzeBimi(
  domain: string,
  resolver: DohResolver,
  options: { dmarcPolicy?: 'none' | 'quarantine' | 'reject' } = {},
): Promise<BimiAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const result = await resolver.query(`default._bimi.${name}`, 'TXT');
  for (const note of result.notes) ctx.notes.add(note);

  const candidates = result.txt.map((txt) => txt.value).filter((value) => /v\s*=\s*BIMI/i.test(value));

  if (candidates.length === 0) {
    emit(ctx, 'BIMI_MISSING', { domain: name });
    return {
      ...base(ctx, name, false, null, resolver, startQueries),
      logo: null,
      authority: null,
      declined: false,
    };
  }

  const record = candidates[0] as string;
  const tags = parseTags(record, ';');
  const logo = tags['l'] ?? null;
  const authority = tags['a'] ?? null;

  // Receivers are told not to fix capitalisation, so neither do we.
  if (tags['v'] !== 'BIMI1') emit(ctx, 'BIMI_SYNTAX', {}, record);

  const declined = logo !== null && logo.trim() === '';
  if (declined) {
    emit(ctx, 'BIMI_DECLINED', {});
  } else if (logo === null || !/^https:\/\//i.test(logo)) {
    emit(ctx, 'BIMI_LOGO_INSECURE', { offending_term: logo === null ? 'missing' : logo });
  }

  const policy = options.dmarcPolicy;
  if (policy !== undefined && policy !== 'quarantine' && policy !== 'reject') {
    emit(ctx, 'BIMI_DMARC_NOT_ENFORCED', { domain: name, policy });
  }

  if (!declined && (authority === null || authority.trim() === '')) {
    emit(ctx, 'BIMI_VMC_MISSING', { domain: name });
  }

  return {
    ...base(ctx, name, true, record, resolver, startQueries),
    logo,
    authority,
    declined,
  };
}

// ---------------------------------------------------------------------------

/** CAA — RFC 8659 §4. */
export async function analyzeCaa(domain: string, resolver: DohResolver): Promise<CaaAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const result = await resolver.query(name, 'CAA');
  for (const note of result.notes) ctx.notes.add(note);

  if (result.records.length === 0) {
    emit(ctx, 'CAA_MISSING', { domain: name });
    return {
      ...base(ctx, name, false, null, resolver, startQueries),
      issuers: [],
      wildcardIssuers: [],
      forbidsAll: false,
    };
  }

  const issuers: string[] = [];
  const wildcardIssuers: string[] = [];
  let forbidsAll = false;

  for (const record of result.records) {
    // DoH renders CAA rdata as: 0 issue "letsencrypt.org"
    const match = /^\s*(\d+)\s+([a-z0-9]+)\s+"?([^"]*)"?\s*$/i.exec(record.data);
    if (!match) continue;

    const property = (match[2] ?? '').toLowerCase();
    const value = (match[3] ?? '').trim();

    if (property === 'issue') {
      if (value === ';') forbidsAll = true;
      else if (value) issuers.push(value);
    } else if (property === 'issuewild') {
      if (value && value !== ';') wildcardIssuers.push(value);
    } else if (property !== 'iodef') {
      emit(ctx, 'CAA_SYNTAX', { offending_term: property });
    }
  }

  if (forbidsAll && issuers.length === 0) emit(ctx, 'CAA_FORBIDS_ALL', { domain: name });

  const evidence = result.records.map((record) => record.data).join(' | ');
  return {
    ...base(ctx, name, true, evidence, resolver, startQueries),
    issuers,
    wildcardIssuers,
    forbidsAll,
  };
}

// ---------------------------------------------------------------------------

function parseTags(record: string, separator: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const segment of record.split(separator)) {
    const equals = segment.indexOf('=');
    if (equals === -1) continue;
    const key = segment.slice(0, equals).trim().toLowerCase();
    if (key) tags[key] = segment.slice(equals + 1).trim();
  }
  return tags;
}

function base(
  ctx: Ctx,
  domain: string,
  found: boolean,
  record: string | null,
  resolver: DohResolver,
  startQueries: number,
): BaseAnalysis {
  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain,
    found,
    record,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

function emit(ctx: Ctx, code: string, vars: IssueVars, evidence?: string): void {
  ctx.conditions.push(createCondition(code, vars, evidence === undefined ? {} : { evidence }));
}
