import {
  DEFAULT_DNS_QUERY_BUDGET,
  DEFAULT_QUERY_RETRIES,
  DEFAULT_QUERY_TIMEOUT_MS,
  type DohProvider,
} from '@maildoc/shared';
import { queryProvider, type DohAttempt, type FetchLike } from './doh.js';
import { toTxtRecord } from './txt.js';
import {
  DNS_TYPE_NUMBERS,
  type Agreement,
  type DnsAnswer,
  type DnsCache,
  type DnsQueryResult,
  type DnsStatus,
  type DnsType,
  type DohJson,
  type ResolverNote,
} from './types.js';

const RCODE: Record<number, DnsStatus> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

export interface ResolverOptions {
  /** Query order. Primary first — its answer is the one we report. */
  providers?: DohProvider[];
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  retries?: number;
  /**
   * Max upstream queries for this resolver instance. Cloudflare Workers allow
   * 50 subrequests per request; we stay well under and report when we stop.
   */
  budget?: number;
  /** Query every provider and compare, for every query. Off by default. */
  verifyByDefault?: boolean;
  /** Reuse identical (type, name) queries within this instance. */
  memoize?: boolean;
  cache?: DnsCache;
  cacheTtlSeconds?: number;
}

export interface QueryOptions {
  /**
   * Ask both resolvers and compare. Costs a second subrequest, so it is worth
   * it for the records a verdict hinges on (apex TXT, _dmarc) and wasteful for
   * chain-walk lookups.
   */
  verify?: boolean;
}

/**
 * DNS-over-HTTPS client for the clinic.
 *
 * - Google first, Cloudflare as fallback — a single provider having a bad
 *   minute must never become a diagnosis.
 * - `verify` queries both and, on disagreement, flags PROPAGATION_IN_PROGRESS
 *   rather than reporting one resolver's answer as fact.
 * - Multi-string TXT records are concatenated the way a receiver does.
 * - Every query is timed out, retried once, and counted against a budget.
 */
export class DohResolver {
  private readonly providers: DohProvider[];
  private readonly fetchImpl: FetchLike | undefined;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly budget: number;
  private readonly verifyByDefault: boolean;
  private readonly memoize: boolean;
  private readonly cache: DnsCache | undefined;
  private readonly cacheTtlSeconds: number;
  private readonly inFlight = new Map<string, Promise<DnsQueryResult>>();

  /** Upstream queries actually issued (cache and memo hits are free). */
  queriesIssued = 0;
  /** True once the budget stopped a query — engines report partial results. */
  budgetExhausted = false;

  constructor(options: ResolverOptions = {}) {
    this.providers = options.providers ?? ['google', 'cloudflare'];
    this.fetchImpl = options.fetchImpl;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS;
    this.retries = options.retries ?? DEFAULT_QUERY_RETRIES;
    this.budget = options.budget ?? DEFAULT_DNS_QUERY_BUDGET;
    this.verifyByDefault = options.verifyByDefault ?? false;
    this.memoize = options.memoize ?? true;
    this.cache = options.cache;
    this.cacheTtlSeconds = options.cacheTtlSeconds ?? 300;
  }

  /** Queries left before the budget stops us. */
  get remainingBudget(): number {
    return Math.max(0, this.budget - this.queriesIssued);
  }

  async query(name: string, type: DnsType, options: QueryOptions = {}): Promise<DnsQueryResult> {
    const qname = normalizeName(name);
    const key = `${type}:${qname}`;

    if (this.memoize) {
      const pending = this.inFlight.get(key);
      if (pending) return pending;
    }

    const promise = this.resolve(key, qname, type, options.verify ?? this.verifyByDefault);
    if (this.memoize) this.inFlight.set(key, promise);
    return promise;
  }

  /** Convenience: TXT values at a name, already concatenated. */
  async txtValues(name: string, options: QueryOptions = {}): Promise<string[]> {
    const result = await this.query(name, 'TXT', options);
    return result.txt.map((record) => record.value);
  }

  private async resolve(
    key: string,
    qname: string,
    type: DnsType,
    verify: boolean,
  ): Promise<DnsQueryResult> {
    const cached = await this.cache?.get(key);
    if (cached) return cached;

    const result = verify
      ? await this.resolveVerified(qname, type)
      : await this.resolveFailover(qname, type);

    if (this.cache && result.status !== 'ERROR' && result.status !== 'TIMEOUT') {
      const ttl = result.status === 'NXDOMAIN' ? Math.min(60, this.cacheTtlSeconds) : this.cacheTtlSeconds;
      await this.cache.set(key, result, ttl);
    }
    return result;
  }

  /** Primary, then fallback. Cheapest path — one subrequest when all is well. */
  private async resolveFailover(qname: string, type: DnsType): Promise<DnsQueryResult> {
    const failures: string[] = [];

    for (const provider of this.providers) {
      const attempt = await this.attempt(provider, qname, type);
      if (attempt === 'BUDGET') return budgetResult(qname, type);
      if (attempt.ok) return fromJson(qname, type, attempt.json, [provider], 'SINGLE');
      failures.push(attempt.reason);
    }
    return failureResult(qname, type, failures);
  }

  /** Both resolvers, in parallel, compared. Disagreement is never silent. */
  private async resolveVerified(qname: string, type: DnsType): Promise<DnsQueryResult> {
    if (this.providers.length < 2) return this.resolveFailover(qname, type);
    if (this.remainingBudget < this.providers.length) return this.resolveFailover(qname, type);

    const attempts = await Promise.all(
      this.providers.map(async (provider) => ({
        provider,
        attempt: await this.attempt(provider, qname, type),
      })),
    );

    const answered = attempts.filter(
      (entry): entry is { provider: DohProvider; attempt: Extract<DohAttempt, { ok: true }> } =>
        entry.attempt !== 'BUDGET' && entry.attempt.ok,
    );

    if (answered.length === 0) {
      const failures = attempts.map((entry) =>
        entry.attempt === 'BUDGET' ? 'BUDGET' : entry.attempt.ok ? 'OK' : entry.attempt.reason,
      );
      return failures.includes('BUDGET')
        ? budgetResult(qname, type)
        : failureResult(qname, type, failures);
    }

    const primary = answered[0] as { provider: DohProvider; attempt: { ok: true; json: DohJson } };
    if (answered.length === 1) {
      return fromJson(qname, type, primary.attempt.json, [primary.provider], 'SINGLE');
    }

    const providers = answered.map((entry) => entry.provider);
    const fingerprints = answered.map((entry) => fingerprint(qname, type, entry.attempt.json));
    const agreed = fingerprints.every((value) => value === fingerprints[0]);

    const result = fromJson(
      qname,
      type,
      primary.attempt.json,
      providers,
      agreed ? 'AGREED' : 'DISAGREED',
      agreed ? [] : ['PROPAGATION_IN_PROGRESS'],
    );

    // When the resolvers agree, prefer the answer that preserves TXT
    // character-strings — the values are identical, but only one of them can
    // tell us how the record is chunked on the wire.
    if (agreed && type === 'TXT' && result.txt.some((record) => !record.segmented)) {
      const segmented = answered
        .map((entry) => fromJson(qname, type, entry.attempt.json, providers, 'AGREED'))
        .find((candidate) => candidate.txt.every((record) => record.segmented));
      if (segmented) return { ...result, txt: segmented.txt };
    }

    return result;
  }

  private async attempt(
    provider: DohProvider,
    qname: string,
    type: DnsType,
  ): Promise<DohAttempt | 'BUDGET'> {
    if (this.queriesIssued >= this.budget) {
      this.budgetExhausted = true;
      return 'BUDGET';
    }

    // Every retry and every failover inside queryProvider is another
    // subrequest, so the counter lives here, called once per network attempt
    // rather than once per name we wanted to know about.
    const result = await queryProvider(provider, qname, type, {
      ...(this.fetchImpl ? { fetchImpl: this.fetchImpl } : {}),
      timeoutMs: this.timeoutMs,
      retries: this.retries,
      spend: () => {
        if (this.queriesIssued >= this.budget) {
          this.budgetExhausted = true;
          return false;
        }
        this.queriesIssued += 1;
        return true;
      },
    });

    if (!result.ok && result.reason === 'BUDGET') return 'BUDGET';
    return result;
  }
}

function normalizeName(name: string): string {
  return name.trim().replace(/\.$/, '').toLowerCase();
}

function fromJson(
  qname: string,
  type: DnsType,
  json: DohJson,
  providers: DohProvider[],
  agreement: Agreement,
  extraNotes: ResolverNote[] = [],
): DnsQueryResult {
  const wanted = DNS_TYPE_NUMBERS[type];
  const answers: DnsAnswer[] = (json.Answer ?? []).map((answer) => ({
    name: answer.name,
    type: answer.type,
    ttl: answer.TTL ?? 0,
    data: answer.data,
  }));
  const records = answers.filter((answer) => answer.type === wanted);
  const status = RCODE[json.Status] ?? 'ERROR';

  return {
    name: qname,
    type,
    status,
    answers,
    records,
    txt: type === 'TXT' ? records.map((record) => toTxtRecord(record.data)) : [],
    authenticated: json.AD === true,
    truncated: json.TC === true,
    // RFC 7208 §4.6.4: NXDOMAIN, or a positive answer with an empty RR set.
    isVoid: status === 'NXDOMAIN' || (status === 'NOERROR' && records.length === 0),
    providers,
    agreement,
    notes: extraNotes,
  };
}

/** Identity of an answer set, for cross-resolver comparison. */
function fingerprint(qname: string, type: DnsType, json: DohJson): string {
  const status = RCODE[json.Status] ?? 'ERROR';
  const wanted = DNS_TYPE_NUMBERS[type];
  const values = (json.Answer ?? [])
    .filter((answer) => answer.type === wanted)
    .map((answer) =>
      type === 'TXT'
        ? toTxtRecord(answer.data).value
        : answer.data.trim().replace(/\.$/, '').replace(/\s+/g, ' '),
    )
    .map((value) => value.toLowerCase())
    .sort();
  return `${qname}|${status}|${values.join('')}`;
}

function emptyResult(qname: string, type: DnsType, status: DnsStatus): DnsQueryResult {
  return {
    name: qname,
    type,
    status,
    answers: [],
    records: [],
    txt: [],
    authenticated: false,
    truncated: false,
    // A lookup we never completed is not a void lookup — claiming otherwise
    // would invent SPF PermErrors out of our own network trouble.
    isVoid: false,
    providers: [],
    agreement: 'SINGLE',
    notes: [],
  };
}

function failureResult(qname: string, type: DnsType, failures: string[]): DnsQueryResult {
  const timedOut = failures.includes('TIMEOUT');
  return {
    ...emptyResult(qname, type, timedOut ? 'TIMEOUT' : 'ERROR'),
    notes: [timedOut ? 'RESOLVER_TIMEOUT' : 'RESOLVER_ERROR'],
    error: timedOut ? 'The DNS lookup timed out.' : 'The DNS lookup failed.',
  };
}

function budgetResult(qname: string, type: DnsType): DnsQueryResult {
  return {
    ...emptyResult(qname, type, 'ERROR'),
    notes: ['BUDGET_EXCEEDED'],
    error: 'This checkup reached its DNS lookup budget.',
  };
}
