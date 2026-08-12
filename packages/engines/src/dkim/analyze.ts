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
import { inspectKey, type DkimKey } from './key.js';

/**
 * Selectors real providers publish, most common first.
 *
 * DKIM has no index: without a signed message you cannot know a domain's
 * selector, so every checker probes. We probe the ones that actually pay for
 * themselves and say plainly when none answer, rather than announcing that a
 * domain has no DKIM because we guessed wrong.
 */
export const COMMON_SELECTORS: readonly string[] = [
  'google', // Google Workspace
  'selector1', // Microsoft 365
  'selector2',
  's1', // SendGrid, Amazon SES and others
  's2',
  'k1', // Mailchimp / Mandrill
  'k2',
  'default',
  'dkim', // Zoho and various
  'mail',
  'smtp',
  'mandrill',
  'sig1', // Yahoo / Proofpoint
];

export interface DkimKeyRecord {
  selector: string;
  name: string;
  /** The record as published. UNTRUSTED — escape before rendering. */
  record: string;
  tags: Record<string, string>;
  key: DkimKey | null;
  revoked: boolean;
}

export interface DkimAnalysis {
  domain: string;
  found: boolean;
  /** Selectors that answered with a usable key record. */
  keys: DkimKeyRecord[];
  /** Selectors probed, in order. */
  probed: string[];
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface DkimEngineOptions {
  /** Selectors to try. Defaults to `COMMON_SELECTORS`. */
  selectors?: readonly string[];
  /** Stop after this many probes — each one is a subrequest. */
  maxProbes?: number;
  /** Stop at the first selector that answers (the default is to find them all). */
  stopAtFirst?: boolean;
  /**
   * The patient told us their selector (from a DKIM-Signature header). Then a
   * missing key is a real fault, not "we guessed and missed".
   */
  explicitSelector?: string;
}

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
}

export async function analyzeDkim(
  domain: string,
  resolver: DohResolver,
  options: DkimEngineOptions = {},
): Promise<DkimAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const explicit = options.explicitSelector?.trim().toLowerCase();
  const selectors = explicit ? [explicit] : (options.selectors ?? COMMON_SELECTORS);
  const maxProbes = options.maxProbes ?? selectors.length;
  const probed: string[] = [];
  const keys: DkimKeyRecord[] = [];
  const answered: { selector: string; record: string; values: string[] }[] = [];

  for (const selector of selectors.slice(0, maxProbes)) {
    if (resolver.remainingBudget <= 1) break;

    const recordName = `${selector}._domainkey.${name}`;
    const result = await resolver.query(recordName, 'TXT');
    probed.push(selector);
    for (const note of result.notes) ctx.notes.add(note);

    if (result.notes.includes('BUDGET_EXCEEDED')) break;
    if (result.status === 'TIMEOUT' || result.status === 'ERROR') continue;

    const values = result.txt.map((txt) => txt.value).filter(looksLikeDkim);
    if (values.length === 0) continue;

    answered.push({ selector, record: values[0] as string, values });

    if (options.stopAtFirst === true) break;
  }

  // A wildcard answers for every name we ask about, so what looks like a dozen
  // broken selectors is one record. Judging it a dozen times would report a
  // dozen conditions for a single fact and charge the score for all of them.
  const wildcard = explicit ? null : await confirmWildcard(resolver, name, answered);

  if (wildcard) {
    emit(
      ctx,
      isRevoked(wildcard) ? 'DKIM_WILDCARD_REVOKED' : 'DKIM_WILDCARD_KEY',
      { domain: name, count: answered.length },
      wildcard,
    );
    keys.push(judgeRecord(ctx, '*', name, wildcard, { quiet: isRevoked(wildcard) }));
  } else {
    for (const entry of answered) {
      if (entry.values.length > 1) {
        emit(ctx, 'DKIM_MULTIPLE_RECORDS', {
          selector: entry.selector,
          domain: name,
          count: entry.values.length,
        });
      }
      keys.push(judgeRecord(ctx, entry.selector, name, entry.record));
    }
  }

  if (keys.length === 0) {
    if (explicit) emit(ctx, 'DKIM_RECORD_MISSING', { selector: explicit, domain: name });
    else emit(ctx, 'DKIM_SELECTOR_NOT_FOUND', { domain: name, count: probed.length });
  }

  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain: name,
    found: keys.length > 0,
    keys,
    probed,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

/** A TXT record at a `_domainkey` name that is trying to be a DKIM key. */
function looksLikeDkim(value: string): boolean {
  return /(^|;)\s*(v\s*=\s*DKIM1|p\s*=|k\s*=)/i.test(value);
}

function parseTags(record: string): { tags: Record<string, string>; duplicates: string[] } {
  const tags: Record<string, string> = {};
  const duplicates: string[] = [];

  for (const segment of record.split(';')) {
    if (segment.trim() === '') continue;
    const equals = segment.indexOf('=');
    if (equals === -1) continue;
    const key = segment.slice(0, equals).trim().toLowerCase();
    // Base64 key material contains '=' padding, so only split on the first one.
    const value = segment.slice(equals + 1).trim();
    if (!/^[a-z][a-z0-9_]*$/i.test(key)) continue;
    if (Object.prototype.hasOwnProperty.call(tags, key)) duplicates.push(key);
    else tags[key] = value;
  }

  return { tags, duplicates };
}

/** A published key with an empty `p=` has been revoked (RFC 6376 §3.6.1). */
function isRevoked(record: string): boolean {
  const match = /(^|;)\s*p\s*=([^;]*)/i.exec(record);
  return match !== null && (match[2] ?? '').replace(/\s+/g, '') === '';
}

/**
 * Prove a wildcard rather than infer one.
 *
 * Several identical answers is a strong hint; asking for a selector nobody
 * would ever publish settles it for one query. Without the confirmation we
 * would mislabel a domain that genuinely rotates the same key across selectors.
 */
async function confirmWildcard(
  resolver: DohResolver,
  domain: string,
  answered: readonly { record: string }[],
): Promise<string | null> {
  if (answered.length < 3) return null;

  const first = answered[0]?.record;
  if (!first || !answered.every((entry) => entry.record === first)) return null;
  if (resolver.remainingBudget <= 1) return null;

  const probe = await resolver.query(`md-wildcard-probe._domainkey.${domain}`, 'TXT');
  const values = probe.txt.map((txt) => txt.value).filter(looksLikeDkim);
  return values[0] === first ? first : null;
}

function judgeRecord(
  ctx: Ctx,
  selector: string,
  domain: string,
  record: string,
  options: { quiet?: boolean } = {},
): DkimKeyRecord {
  const { tags, duplicates } = parseTags(record);
  const name = `${selector}._domainkey.${domain}`;

  for (const duplicate of new Set(duplicates)) {
    emit(ctx, 'DKIM_DUPLICATE_TAG', { selector, offending_term: duplicate });
  }

  const publicKey = tags['p'];
  if (publicKey === undefined) {
    emit(ctx, 'DKIM_RECORD_BROKEN', { selector, domain }, record);
    return { selector, name, record, tags, key: null, revoked: false };
  }
  if (publicKey.replace(/\s+/g, '') === '') {
    if (options.quiet !== true) emit(ctx, 'DKIM_KEY_REVOKED', { selector, domain }, record);
    return { selector, name, record, tags, key: null, revoked: true };
  }

  const algorithm = tags['k']?.toLowerCase();
  if (algorithm !== undefined && algorithm !== 'rsa' && algorithm !== 'ed25519') {
    emit(ctx, 'DKIM_ALGO_UNKNOWN', { selector, offending_term: algorithm });
    return { selector, name, record, tags, key: null, revoked: false };
  }

  const key = inspectKey(publicKey, algorithm);
  if (key === null) {
    emit(ctx, 'DKIM_RECORD_BROKEN', { selector, domain }, record);
    return { selector, name, record, tags, key: null, revoked: false };
  }

  if (key.algorithm === 'ed25519') {
    if (!key.valid) emit(ctx, 'DKIM_ED25519_INVALID', { selector, bits: key.bits });
  } else if (key.bits < 1024) {
    // RFC 8301 §3.2: verifiers MUST NOT accept these.
    emit(ctx, 'DKIM_KEY_TOO_WEAK', { selector, bits: key.bits });
  } else if (key.bits < 2048) {
    emit(ctx, 'DKIM_KEY_WEAK_1024', { selector });
  }

  // h= restricts which hash algorithms may be used with this key.
  const hashes = tags['h'];
  if (hashes !== undefined) {
    const list = hashes.split(':').map((entry) => entry.trim().toLowerCase()).filter(Boolean);
    if (list.length > 0 && !list.includes('sha256')) {
      emit(ctx, 'DKIM_ALGO_SHA1', { selector });
    }
  }

  const flags = tags['t'];
  if (flags !== undefined) {
    const list = flags.split(':').map((entry) => entry.trim().toLowerCase());
    if (list.includes('y')) emit(ctx, 'DKIM_TESTING_MODE', { selector });
  }

  const services = tags['s'];
  if (services !== undefined) {
    const list = services.split(':').map((entry) => entry.trim().toLowerCase()).filter(Boolean);
    if (list.length > 0 && !list.includes('*') && !list.includes('email')) {
      emit(ctx, 'DKIM_SERVICE_RESTRICTED', { selector, offending_term: services });
    }
  }

  return { selector, name, record, tags, key, revoked: false };
}

function emit(ctx: Ctx, code: string, vars: IssueVars, evidence?: string): void {
  ctx.conditions.push(createCondition(code, vars, evidence === undefined ? {} : { evidence }));
}
