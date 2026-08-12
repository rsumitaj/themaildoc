import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  sortConditions,
  type Condition,
  type IssueVars,
} from '@maildoc/catalog';
import type { DohResolver, ResolverNote } from '@maildoc/resolver';
import {
  fetchCertificate,
  fetchLogo,
  type CertReport,
  type FetchLike,
  type LogoReport,
} from '../bimi/assets.js';
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
  /** What the logo URL actually served. Null when we did not fetch it. */
  logoReport: LogoReport | null;
  certReport: CertReport | null;
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
  options: {
    dmarcPolicy?: 'none' | 'quarantine' | 'reject';
    /** Absent means DNS only, which is what the full checkup uses. */
    fetchImpl?: FetchLike;
  } = {},
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
      logoReport: null,
      certReport: null,
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

  // The record is two URLs. Whether a mailbox shows the logo depends entirely
  // on what they serve, so saying the record is fine without looking is the
  // one claim this tool must never make.
  let logoReport: LogoReport | null = null;
  let certReport: CertReport | null = null;

  if (options.fetchImpl && !declined) {
    if (logo && /^https:\/\//i.test(logo)) {
      logoReport = await fetchLogo(logo, options.fetchImpl);
      judgeLogo(ctx, name, logo, logoReport);
    }
    if (authority && /^https:\/\//i.test(authority)) {
      certReport = await fetchCertificate(authority, options.fetchImpl);
      judgeCertificate(ctx, name, authority, certReport);
    }
  }

  return {
    ...base(ctx, name, true, record, resolver, startQueries),
    logo,
    authority,
    declined,
    logoReport,
    certReport,
  };
}

function judgeLogo(ctx: Ctx, domain: string, url: string, report: LogoReport): void {
  if (!report.ok) {
    emit(ctx, 'BIMI_LOGO_UNREACHABLE', { domain, offending_term: report.detail ?? 'no response' }, url);
    return;
  }
  if (report.tinyPs !== true) {
    emit(ctx, 'BIMI_LOGO_WRONG_PROFILE', { domain }, url);
  }
  if (report.hasTitle !== true) {
    emit(ctx, 'BIMI_LOGO_NO_TITLE', { domain }, url);
  }
  if (report.square !== true) {
    emit(ctx, 'BIMI_LOGO_NOT_SQUARE', { offending_term: report.viewBox ?? 'no viewBox' }, url);
  }
  if (report.forbidden && report.forbidden.length > 0) {
    emit(ctx, 'BIMI_LOGO_FORBIDDEN_CONTENT', { offending_term: report.forbidden.join(', ') }, url);
  }
}

/** Renewal takes weeks, so the warning has to arrive well before the date. */
const CERT_EXPIRY_WARNING_DAYS = 45;

function judgeCertificate(ctx: Ctx, domain: string, url: string, report: CertReport): void {
  if (!report.ok) {
    emit(ctx, 'BIMI_VMC_UNREACHABLE', { domain, offending_term: report.detail ?? 'no response' }, url);
    return;
  }
  const days = report.daysRemaining;
  if (days === null || days === undefined) return;

  if (days < 0) {
    emit(ctx, 'BIMI_VMC_EXPIRED', { domain, count: Math.abs(days) }, url);
  } else if (days <= CERT_EXPIRY_WARNING_DAYS) {
    emit(ctx, 'BIMI_VMC_EXPIRING', { domain, count: days }, url);
  }
}

// ---------------------------------------------------------------------------

/**
 * Every property tag in IANA's "Certification Authority Restriction
 * Properties" registry, not just the three RFC 8659 defines.
 *
 * The registry is the authority here, and it has grown well past that RFC.
 * Treating anything outside `issue`, `issuewild` and `iodef` as a syntax error
 * reported microsoft.com's perfectly valid `contactemail` record as a fault
 * worth fifteen points.
 *
 *   issue, issuewild, iodef      RFC 8659 §4.2, §4.3, §4.4
 *   contactemail, contactphone   CA/Browser Forum, used for domain validation
 *   issuemail                    RFC 9495 §3, S/MIME certificates
 *   issuevmc                     verified mark certificates, which is BIMI
 *   accounturi, validationmethods  RFC 8657 §3, §4
 */
const KNOWN_CAA_PROPERTIES: ReadonlySet<string> = new Set([
  'iodef',
  'contactemail',
  'contactphone',
  'issuemail',
  'issuewildmail',
  'issuevmc',
  'accounturi',
  'validationmethods',
]);

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
    // Handled below; `issue` and `issuewild` carry the answer, the rest of the
    // registry is legitimate and must not be called a syntax error.
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
    } else if (!KNOWN_CAA_PROPERTIES.has(property)) {
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
