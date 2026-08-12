import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  sortConditions,
  type Condition,
  type IssueVars,
} from '@maildoc/catalog';
import type { DohResolver, FetchLike, ResolverNote } from '@maildoc/resolver';
import type { RecordStatus } from '@maildoc/shared';

/**
 * MTA-STS — RFC 8461.
 *
 * The only check in the product that fetches something other than DNS: the
 * policy lives at an HTTPS URL, and §3.3 is strict about how it must be
 * served. Two rules do most of the work here:
 *
 *   - redirects MUST NOT be followed, so a policy behind one does not exist
 *     as far as any sending server is concerned;
 *   - the certificate must validate, which `fetch` enforces for us by failing.
 *
 * A Worker may fetch over HTTPS for free, so this stays inside the rules —
 * it costs one subrequest, not money.
 */

export const MTASTS_MAX_AGE_CEILING = 31_557_600;
/** Below a day, senders re-fetch constantly and cache too little to help. */
export const MTASTS_MAX_AGE_FLOOR = 86_400;

export type MtaStsMode = 'enforce' | 'testing' | 'none';

export interface MtaStsPolicy {
  version: string | null;
  mode: MtaStsMode | null;
  mx: string[];
  maxAge: number | null;
}

export interface MtaStsAnalysis {
  domain: string;
  /** The _mta-sts TXT record was found and announces a policy. */
  announced: boolean;
  /** The announcement as published. UNTRUSTED — escape before rendering. */
  record: string | null;
  id: string | null;
  policyFetched: boolean;
  policy: MtaStsPolicy | null;
  /** Raw policy text. UNTRUSTED — escape before rendering. */
  policyText: string | null;
  conditions: Condition[];
  status: RecordStatus;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface MtaStsOptions {
  /** Skip the HTTPS fetch (used when the subrequest budget is spent). */
  fetchPolicy?: boolean;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  /** Live MX hostnames, so the policy can be checked against reality. */
  mxHosts?: readonly string[];
}

interface Ctx {
  conditions: Condition[];
  notes: Set<ResolverNote>;
}

export async function analyzeMtaSts(
  domain: string,
  resolver: DohResolver,
  options: MtaStsOptions = {},
): Promise<MtaStsAnalysis> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const ctx: Ctx = { conditions: [], notes: new Set() };

  const txt = await resolver.query(`_mta-sts.${name}`, 'TXT');
  for (const note of txt.notes) ctx.notes.add(note);

  const records = txt.txt.map((record) => record.value).filter((value) => /^\s*v\s*=\s*STSv1/i.test(value));

  if (records.length === 0) {
    emit(ctx, 'MTASTS_MISSING', { domain: name });
    return finish(ctx, name, false, null, null, false, null, null, resolver, startQueries);
  }

  const record = records[0] as string;
  const tags = parseTags(record);
  const id = tags['id'] ?? null;

  // §3.1: v must be exactly STSv1 and id must be 1–32 alphanumerics.
  if (tags['v'] !== 'STSv1' || id === null || !/^[a-z0-9]{1,32}$/i.test(id)) {
    emit(ctx, 'MTASTS_TXT_INVALID', { domain: name }, record);
  }

  if (options.fetchPolicy === false) {
    return finish(ctx, name, true, record, id, false, null, null, resolver, startQueries);
  }

  const fetched = await fetchPolicy(name, options);
  if (!fetched.ok) {
    if (fetched.reason === 'REDIRECT') emit(ctx, 'MTASTS_POLICY_REDIRECT', { domain: name });
    else emit(ctx, 'MTASTS_POLICY_UNREACHABLE', { domain: name, offending_term: fetched.detail });
    return finish(ctx, name, true, record, id, false, null, null, resolver, startQueries);
  }

  const policy = parsePolicy(fetched.body);
  if (policy.version !== 'STSv1' || policy.mode === null || policy.mx.length === 0) {
    emit(ctx, 'MTASTS_POLICY_INVALID', {
      offending_term: describePolicyProblem(policy),
    });
    return finish(ctx, name, true, record, id, true, policy, fetched.body, resolver, startQueries);
  }

  if (policy.mode === 'testing') emit(ctx, 'MTASTS_MODE_TESTING', {});
  if (policy.mode === 'none') emit(ctx, 'MTASTS_MODE_NONE', { domain: name });

  if (policy.maxAge === null || policy.maxAge < MTASTS_MAX_AGE_FLOOR || policy.maxAge > MTASTS_MAX_AGE_CEILING) {
    emit(ctx, 'MTASTS_MAXAGE_INVALID', {
      offending_term: policy.maxAge === null ? 'missing' : String(policy.maxAge),
    });
  }

  // A policy that omits a live MX host rejects your own inbound mail under
  // enforce, so this is checked against what the domain really publishes.
  for (const host of options.mxHosts ?? []) {
    if (!policyCoversHost(policy.mx, host)) {
      emit(ctx, 'MTASTS_MX_MISMATCH', { domain: name, offending_term: host });
    }
  }

  return finish(ctx, name, true, record, id, true, policy, fetched.body, resolver, startQueries);
}

/** §4.1: a wildcard may only replace the entire leftmost label. */
export function policyCoversHost(patterns: readonly string[], host: string): boolean {
  const target = host.trim().replace(/\.$/, '').toLowerCase();
  return patterns.some((pattern) => {
    const candidate = pattern.trim().replace(/\.$/, '').toLowerCase();
    if (candidate === target) return true;
    if (!candidate.startsWith('*.')) return false;
    const suffix = candidate.slice(1); // ".mail.example.com"
    if (!target.endsWith(suffix)) return false;
    const label = target.slice(0, target.length - suffix.length);
    return label.length > 0 && !label.includes('.');
  });
}

export function parsePolicy(text: string): MtaStsPolicy {
  const policy: MtaStsPolicy = { version: null, mode: null, mx: [], maxAge: null };

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '') continue;
    const colon = line.indexOf(':');
    if (colon === -1) continue;

    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();

    if (key === 'version') policy.version = value;
    else if (key === 'mode') {
      if (value === 'enforce' || value === 'testing' || value === 'none') policy.mode = value;
    } else if (key === 'mx') policy.mx.push(value);
    else if (key === 'max_age') {
      const parsed = Number.parseInt(value, 10);
      if (Number.isFinite(parsed)) policy.maxAge = parsed;
    }
  }

  return policy;
}

type FetchOutcome =
  | { ok: true; body: string }
  | { ok: false; reason: 'REDIRECT' | 'STATUS' | 'NETWORK' | 'TYPE'; detail: string };

/**
 * A policy file is a handful of lines. Nothing that answers this URL has any
 * business sending more, and the host on the other end is chosen by whoever
 * typed the domain, so the body is read with a hard ceiling rather than
 * swallowed whole.
 */
const MAX_POLICY_BYTES = 64 * 1024;

async function readCapped(response: Response): Promise<string | null> {
  const declared = Number.parseInt(response.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(declared) && declared > MAX_POLICY_BYTES) return null;

  const body = response.body;
  if (!body) return response.text();

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.length;
      if (total > MAX_POLICY_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }

  const merged = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    merged.set(chunk, at);
    at += chunk.length;
  }
  return new TextDecoder('utf-8').decode(merged);
}

async function fetchPolicy(domain: string, options: MtaStsOptions): Promise<FetchOutcome> {
  const doFetch = options.fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  if (!doFetch) return { ok: false, reason: 'NETWORK', detail: 'no fetch available' };

  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5_000);

  try {
    const response = await doFetch(url, {
      // §3.3: redirects MUST NOT be followed. `manual` lets us see the 3xx
      // rather than silently ending up somewhere the spec forbids.
      redirect: 'manual',
      signal: controller.signal,
    });

    if (response.status >= 300 && response.status < 400) {
      return { ok: false, reason: 'REDIRECT', detail: `HTTP ${response.status}` };
    }
    if (response.status !== 200) {
      return { ok: false, reason: 'STATUS', detail: `HTTP ${response.status}` };
    }

    const body = await readCapped(response);
    if (body === null) {
      return { ok: false, reason: 'TYPE', detail: 'the response is larger than a policy file can be' };
    }
    if (!/version\s*:/i.test(body)) {
      return { ok: false, reason: 'TYPE', detail: 'the response is not a policy file' };
    }
    return { ok: true, body };
  } catch {
    // An invalid certificate lands here too, which is the correct outcome:
    // senders would refuse it as well.
    return { ok: false, reason: 'NETWORK', detail: 'the request failed or the certificate is invalid' };
  } finally {
    clearTimeout(timer);
  }
}

function describePolicyProblem(policy: MtaStsPolicy): string {
  if (policy.version !== 'STSv1') return 'the version line is missing or wrong';
  if (policy.mode === null) return 'the mode line is missing or not enforce/testing/none';
  return 'no mx lines';
}

function parseTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const segment of record.split(';')) {
    const equals = segment.indexOf('=');
    if (equals === -1) continue;
    const key = segment.slice(0, equals).trim().toLowerCase();
    if (key) tags[key] = segment.slice(equals + 1).trim();
  }
  return tags;
}

function finish(
  ctx: Ctx,
  domain: string,
  announced: boolean,
  record: string | null,
  id: string | null,
  policyFetched: boolean,
  policy: MtaStsPolicy | null,
  policyText: string | null,
  resolver: DohResolver,
  startQueries: number,
): MtaStsAnalysis {
  const conditions = sortConditions(dedupeConditions(ctx.conditions));
  return {
    domain,
    announced,
    record,
    id,
    policyFetched,
    policy,
    policyText,
    conditions,
    status: rollupRecord(conditions),
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...ctx.notes],
  };
}

function emit(ctx: Ctx, code: string, vars: IssueVars, evidence?: string): void {
  ctx.conditions.push(createCondition(code, vars, evidence === undefined ? {} : { evidence }));
}
