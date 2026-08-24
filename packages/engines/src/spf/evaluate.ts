import type { DohResolver, ResolverNote } from '@maildoc/resolver';
import { ipv4ToInt, ipv6ToBigInt } from './cidr.js';
import { isValidIpv4, isValidIpv6 } from './ip.js';
import { expandMacros, type MacroContext } from './macro.js';
import {
  isSpfRecord,
  parseSpf,
  type Qualifier,
  type SpfMechanism,
  type SpfTerm,
} from './parse.js';

/**
 * `check_host()` — RFC 7208 §4. What a receiver actually decides.
 *
 * Everything else the SPF engine does describes a record: how long the chain
 * is, whether it parses, how close it sits to the ten-lookup limit. This
 * answers the only question a person with a bounce message in front of them is
 * asking, which is whether *this* server may send as *this* domain, and it
 * answers it the way the receiver that bounced the mail did.
 *
 * The distinction matters more than it sounds. A record can be flawless and
 * still fail for the one sender somebody is trying to add, and a record over
 * the lookup limit fails for every sender including the domain's own mail
 * server. Neither is visible from a chain diagram.
 *
 * Faithfulness rules, because a wrong answer here is worse than no answer:
 *
 *   - Terms are evaluated left to right and the **first match wins**, carrying
 *     its own qualifier (§4.6.2). Later terms are never consulted, so the trace
 *     stops where a receiver stops.
 *   - `include:` matches only when the recursion returns **pass** (§5.2). An
 *     include that fails does not fail the outer record; evaluation moves on.
 *   - `redirect=` is consulted only when no mechanism matched and there is no
 *     `all` (§6.1), and its result becomes the whole answer.
 *   - The ten-lookup limit and the two-void-lookup limit are permanent errors
 *     (§4.6.4), which is the case most checkers get wrong by reporting the
 *     record as merely "long".
 *   - Nothing is guessed. A lookup we could not finish is `temperror`, never a
 *     no-match, because reporting "not authorised" for a name we failed to
 *     resolve would be a lie in the most expensive direction.
 */

/** The seven results check_host() can return (RFC 7208 §2.6). */
export type SpfResult =
  | 'pass'
  | 'fail'
  | 'softfail'
  | 'neutral'
  | 'none'
  | 'permerror'
  | 'temperror';

/**
 * Why an error result happened, because "permerror" covers two very different
 * situations and telling somebody the wrong one sends them to fix the wrong
 * thing.
 *
 * A record over the ten-lookup limit, or carrying two SPF records, or failing
 * to parse, is broken for **everybody**: the domain's own mail server fails
 * too, and the fix is urgent. A record that exceeded the void-lookup limit is
 * broken for **this sender**, and often only for this sender: records that use
 * `exists:` with macros perform a lookup per connecting address by design, and
 * three of those coming back empty is the expected outcome for an address the
 * domain has never authorised. zoom.us reads as a permanent error for a
 * TEST-NET address and delivers perfectly well for its real senders.
 *
 * Reporting both as "your record cannot be evaluated" would have somebody
 * rewriting a working record.
 */
export type SpfErrorCause =
  /** Over ten lookup terms (§4.6.4). Broken for every sender. */
  | 'LOOKUP_LIMIT'
  /** Three or more empty lookups (§4.6.4). Usually specific to this sender. */
  | 'VOID_LIMIT'
  /** Two SPF records at one name (§4.5). Broken for every sender. */
  | 'MULTIPLE_RECORDS'
  /** An include or redirect target publishes no SPF record (§5.2, §6.1). */
  | 'MISSING_TARGET'
  /** A mechanism a receiver cannot parse (§4.5). */
  | 'SYNTAX'
  /** The include chain refers back to itself. */
  | 'LOOP'
  /** A macro that cannot be expanded for this connection (§7). */
  | 'MACRO'
  /** DNS did not answer. Temporary, and not a verdict. */
  | 'DNS'
  /** What was typed is not an address. */
  | 'INVALID_IP';

const QUALIFIER_RESULT: Record<Qualifier, SpfResult> = {
  '+': 'pass',
  '-': 'fail',
  '~': 'softfail',
  '?': 'neutral',
};

/** One term, as the receiver considered it. */
export interface SpfEvalStep {
  /** The domain whose record this term came from. */
  domain: string;
  /** How deep in the include chain, 0 at the apex. */
  depth: number;
  /** The term exactly as published. UNTRUSTED — escape before rendering. */
  term: string;
  qualifier: Qualifier;
  outcome: 'match' | 'no-match' | 'error' | 'not-reached';
  /** What was looked up and what came back. */
  detail: string;
  /** DNS lookups this term charged against the limit of ten. */
  lookups: number;
}

export interface SpfEvaluation {
  domain: string;
  /** The address as evaluated, normalised. */
  ip: string;
  ipVersion: 4 | 6;
  sender: string;
  helo: string;
  result: SpfResult;
  /** The term that decided it, when a term did. */
  matched: { domain: string; term: string; qualifier: Qualifier } | null;
  /** Set for `permerror` and `temperror`, and null otherwise. */
  cause: SpfErrorCause | null;
  /**
   * True when the error condemns the record for every sender, rather than only
   * for this one. Read this before telling somebody to rewrite anything.
   */
  breaksEverySender: boolean;
  /** One sentence naming the cause. Safe to render. */
  summary: string;
  trace: SpfEvalStep[];
  /** Lookups charged against the limit of ten (§4.6.4). */
  lookups: number;
  voidLookups: number;
  /** True when the evaluation ran to a conclusion rather than being cut short. */
  complete: boolean;
  queriesUsed: number;
  notes: ResolverNote[];
}

export interface SpfEvaluateOptions {
  /** MAIL FROM. Defaults to `postmaster@<domain>` (§2.4). */
  sender?: string;
  /** HELO/EHLO name. Defaults to the domain. */
  helo?: string;
}

/** RFC 7208 §4.6.4. Both are permanent errors, not warnings. */
const MAX_LOOKUPS = 10;
const MAX_VOID_LOOKUPS = 2;
/** §4.6.4 again: `mx` and `ptr` may each examine at most ten names. */
const MAX_NAMES_PER_MECHANISM = 10;
/** A guard of ours, not the RFC's: nothing legitimate nests this far. */
const MAX_DEPTH = 10;

/**
 * The causes that condemn a record for every sender.
 *
 * Everything not in here is specific to the address being checked, and the
 * difference decides whether somebody should go and rewrite their DNS.
 */
const EVERY_SENDER: ReadonlySet<SpfErrorCause> = new Set<SpfErrorCause>([
  'LOOKUP_LIMIT',
  'MULTIPLE_RECORDS',
  'MISSING_TARGET',
  'SYNTAX',
  'LOOP',
]);

/** Record the cause once. The first one to fire is the one that decided it. */
function blame(context: Ctx, cause: SpfErrorCause): void {
  context.cause ??= cause;
}

interface Ctx {
  resolver: DohResolver;
  ip: string;
  ipVersion: 4 | 6;
  /** The address as a number, for prefix comparison. */
  ipValue: bigint;
  sender: string;
  helo: string;
  lookups: number;
  voidLookups: number;
  trace: SpfEvalStep[];
  notes: Set<ResolverNote>;
  complete: boolean;
  /** Names already being evaluated, so a loop is caught rather than walked. */
  stack: Set<string>;
  /** Why an error result happened. First cause wins; it is the one that fired. */
  cause: SpfErrorCause | null;
  /**
   * The term that produced the result, as the outermost frame saw it.
   *
   * Not simply the first match in the trace. An include that does not pass
   * still matched something inside itself on the way to not passing, and
   * reporting that inner term as the cause tells somebody their mail was
   * decided by a vendor's `-all` when it was decided by the next include along.
   * Each frame overwrites this as it returns, so the outermost decision is the
   * one left standing, and a redirect leaves its target's decision in place
   * because the outer frame hands the answer straight back.
   */
  decided: { domain: string; term: string; qualifier: Qualifier } | null;
}

export async function evaluateSpf(
  domain: string,
  ip: string,
  resolver: DohResolver,
  options: SpfEvaluateOptions = {},
): Promise<SpfEvaluation> {
  const startQueries = resolver.queriesIssued;
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const address = normalizeIp(ip);

  if (address === null) {
    return {
      domain: name,
      ip: ip.trim(),
      ipVersion: 4,
      sender: options.sender ?? `postmaster@${name}`,
      helo: options.helo ?? name,
      result: 'permerror',
      matched: null,
      cause: 'INVALID_IP',
      breaksEverySender: false,
      summary: 'That is not an IP address, so there is nothing to evaluate against.',
      trace: [],
      lookups: 0,
      voidLookups: 0,
      complete: true,
      queriesUsed: 0,
      notes: [],
    };
  }

  const sender = options.sender?.trim() || `postmaster@${name}`;
  const helo = options.helo?.trim() || name;

  const context: Ctx = {
    resolver,
    ip: address.ip,
    ipVersion: address.version,
    ipValue: address.value,
    sender,
    helo,
    lookups: 0,
    voidLookups: 0,
    trace: [],
    notes: new Set(),
    complete: true,
    stack: new Set(),
    decided: null,
    cause: null,
  };

  const result = await checkHost(context, name, 0);

  return {
    domain: name,
    ip: address.ip,
    ipVersion: address.version,
    sender,
    helo,
    result,
    // An error or a bare "no record" was not decided by a term, so naming one
    // would invent a cause.
    matched:
      result === 'permerror' || result === 'temperror' || result === 'none'
        ? null
        : context.decided,
    cause: result === 'permerror' || result === 'temperror' ? context.cause : null,
    breaksEverySender:
      result === 'permerror' && EVERY_SENDER.has(context.cause ?? 'VOID_LIMIT'),
    summary: summarize(result, context, name),
    trace: context.trace,
    lookups: context.lookups,
    voidLookups: context.voidLookups,
    complete: context.complete,
    queriesUsed: resolver.queriesIssued - startQueries,
    notes: [...context.notes],
  };
}

/**
 * One domain's record, evaluated against the connection.
 *
 * Returns the result for this domain alone. `include:` calls it again and reads
 * only whether the answer was `pass`; `redirect=` calls it and hands the answer
 * straight back.
 */
async function checkHost(context: Ctx, domain: string, depth: number): Promise<SpfResult> {
  if (depth > MAX_DEPTH) {
    context.complete = false;
    blame(context, 'LOOP');
    return 'permerror';
  }
  if (context.stack.has(domain)) {
    push(context, domain, depth, 'include', '+', 'error', 'This name is already being evaluated, so the chain loops.', 0);
    blame(context, 'LOOP');
    return 'permerror';
  }

  const record = await readSpfRecord(context, domain);
  if (record.status === 'temperror') return 'temperror';
  if (record.status === 'none') return 'none';
  if (record.status === 'permerror') return 'permerror';

  context.stack.add(domain);
  try {
    return await evaluateTerms(context, domain, depth, record.value);
  } finally {
    context.stack.delete(domain);
  }
}

async function evaluateTerms(
  context: Ctx,
  domain: string,
  depth: number,
  record: string,
): Promise<SpfResult> {
  const parsed = parseSpf(record);
  const mechanisms = parsed.terms.filter(
    (term): term is SpfMechanism => term.kind === 'mechanism',
  );
  const redirect = findRedirect(parsed.terms);
  const hasAll = mechanisms.some((term) => term.name === 'all');

  for (const term of mechanisms) {
    /**
     * The void-lookup limit is checked before the term is evaluated: a receiver
     * that has already had three lookups come back empty returns permerror
     * rather than reading on (§4.6.4). The ten-lookup limit needs no check
     * here, because `spendLookup` is the only thing that can reach it and it
     * refuses at the eleventh term.
     */
    if (context.voidLookups > MAX_VOID_LOOKUPS) {
      /*
       * Attributed to the limit rather than to the term that happened to be
       * next. `-all` did not cause this and saying so beside it reads as a
       * fault in a mechanism that is doing nothing wrong.
       */
      push(context, domain, depth, `${context.voidLookups} empty lookups`, '+', 'error',
        `More than ${MAX_VOID_LOOKUPS} lookups came back empty for this address, which a receiver treats as a permanent error.`, 0);
      blame(context, 'VOID_LIMIT');
      return 'permerror';
    }

    const outcome = await matchMechanism(context, domain, depth, term);

    if (outcome === 'error') return 'permerror';
    if (outcome === 'temperror') return 'temperror';
    if (outcome === 'match') {
      context.decided = { domain, term: term.raw, qualifier: term.qualifier };
      return QUALIFIER_RESULT[term.qualifier];
    }
  }

  /**
   * `redirect=` is consulted only when nothing matched *and* there is no `all`
   * (§6.1). A record carrying both ignores the redirect entirely, which is a
   * mistake worth seeing in the trace rather than silently skipping.
   */
  if (redirect !== null && !hasAll) {
    const target = expand(context, redirect, domain);
    if (target === null) {
      push(context, domain, depth, `redirect=${redirect}`, '+', 'error',
        'The redirect contains a macro that cannot be expanded here.', 0);
      blame(context, 'MACRO');
      return 'permerror';
    }
    if (!spendLookup(context)) {
      push(context, domain, depth, `redirect=${redirect}`, '+', 'error',
        `Over the limit of ${MAX_LOOKUPS} DNS lookups before the redirect could be followed.`, 0);
      return 'permerror';
    }

    push(context, domain, depth, `redirect=${target}`, '+', 'no-match',
      `Nothing matched here, so the answer comes from ${target}.`, 1);

    const result = await checkHost(context, target, depth + 1);
    // A redirect to a domain with no SPF record is a permanent error (§6.1),
    // which is the one place `none` does not travel up unchanged.
    if (result === 'none') {
      blame(context, 'MISSING_TARGET');
      return 'permerror';
    }
    return result;
  }

  if (redirect !== null && hasAll) {
    push(context, domain, depth, `redirect=${redirect}`, '+', 'not-reached',
      'Ignored: this record also has an `all` mechanism, which a receiver reaches first.', 0);
  }

  // No mechanism matched and no redirect: the default result (§4.7). No term
  // produced it, so there is no term to name.
  context.decided = null;
  return 'neutral';
}

type MechanismOutcome = 'match' | 'no-match' | 'error' | 'temperror';

async function matchMechanism(
  context: Ctx,
  domain: string,
  depth: number,
  term: SpfMechanism,
): Promise<MechanismOutcome> {
  switch (term.name) {
    case 'all':
      push(context, domain, depth, term.raw, term.qualifier, 'match',
        'Matches every sender, so evaluation stops here.', 0);
      return 'match';

    case 'ip4':
    case 'ip6':
      return matchIp(context, domain, depth, term);

    case 'a':
      return matchAddress(context, domain, depth, term, 'a');

    case 'mx':
      return matchAddress(context, domain, depth, term, 'mx');

    case 'exists':
      return matchExists(context, domain, depth, term);

    case 'ptr':
      return matchPtr(context, domain, depth, term);

    case 'include':
      return matchInclude(context, domain, depth, term);
  }
}

/** `ip4:` and `ip6:` cost no lookup and are pure arithmetic (§5.6). */
function matchIp(
  context: Ctx,
  domain: string,
  depth: number,
  term: SpfMechanism,
): MechanismOutcome {
  const wantsV4 = term.name === 'ip4';
  const value = term.value ?? '';
  const bits = wantsV4 ? 32 : 128;
  const prefix = term.cidr4 !== null ? Number(term.cidr4) : bits;

  const valid = wantsV4 ? isValidIpv4(value) : isValidIpv6(value);
  if (!valid || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'This mechanism is malformed, which makes the whole record a permanent error.', 0);
    blame(context, 'SYNTAX');
    return 'error';
  }

  // An IPv4 address is never inside an ip6: range, and the reverse.
  if ((context.ipVersion === 4) !== wantsV4) {
    push(context, domain, depth, term.raw, term.qualifier, 'no-match',
      `Not checked: this is an IPv${wantsV4 ? '4' : '6'} range and the address is IPv${context.ipVersion}.`, 0);
    return 'no-match';
  }

  const network = wantsV4 ? toBig(ipv4ToInt(value)) : ipv6ToBigInt(value);
  if (network === null) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'This mechanism is malformed, which makes the whole record a permanent error.', 0);
    blame(context, 'SYNTAX');
    return 'error';
  }

  const matched = inNetwork(context.ipValue, network, prefix, bits);
  push(context, domain, depth, term.raw, term.qualifier, matched ? 'match' : 'no-match',
    matched
      ? `${context.ip} is inside ${value}/${prefix}.`
      : `${context.ip} is not inside ${value}/${prefix}.`,
    0);
  return matched ? 'match' : 'no-match';
}

/**
 * `a` and `mx` (§5.3, §5.4). Both resolve names and compare the address with
 * the mechanism's prefix, which defaults to a single host.
 */
async function matchAddress(
  context: Ctx,
  domain: string,
  depth: number,
  term: SpfMechanism,
  kind: 'a' | 'mx',
): Promise<MechanismOutcome> {
  const target = term.value === null ? domain : expand(context, term.value, domain);
  if (target === null) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'This mechanism contains a macro that cannot be expanded here.', 0);
    blame(context, 'MACRO');
    return 'error';
  }

  if (!spendLookup(context)) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      `Over the limit of ${MAX_LOOKUPS} DNS lookups, so a receiver stops here with a permanent error.`, 0);
    return 'error';
  }

  const prefix = prefixFor(context, term);
  const bits = context.ipVersion === 4 ? 32 : 128;
  if (prefix === null || prefix < 0 || prefix > bits) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'The CIDR length on this mechanism is not valid, which is a permanent error.', 0);
    blame(context, 'SYNTAX');
    return 'error';
  }

  let hosts: string[] = [target];
  let spent = 1;

  if (kind === 'mx') {
    const mx = await context.resolver.query(target, 'MX');
    for (const note of mx.notes) context.notes.add(note);
    if (unresolved(mx.status)) {
      context.complete = false;
      blame(context, 'DNS');
      push(context, domain, depth, term.raw, term.qualifier, 'error',
        `DNS did not answer for the mail servers of ${target}, so the result cannot be decided.`, spent);
      return 'temperror';
    }
    if (mx.isVoid) context.voidLookups += 1;

    hosts = mx.records
      .map((record) => mxTarget(record.data))
      .filter((host): host is string => host !== null)
      .slice(0, MAX_NAMES_PER_MECHANISM);

    if (hosts.length === 0) {
      push(context, domain, depth, term.raw, term.qualifier, 'no-match',
        `${target} publishes no mail servers, so there is nothing here to match.`, spent);
      return 'no-match';
    }
  }

  const type = context.ipVersion === 4 ? 'A' : 'AAAA';
  const found: string[] = [];

  for (const host of hosts) {
    // Resolving MX targets costs queries but not lookups: §4.6.4 charges the
    // mechanism once and caps the names it may examine at ten.
    if (kind === 'mx' && context.resolver.remainingBudget <= 1) {
      context.complete = false;
      blame(context, 'DNS');
      push(context, domain, depth, term.raw, term.qualifier, 'error',
        'We ran out of query budget before every mail server could be checked.', spent);
      return 'temperror';
    }

    const answer = await context.resolver.query(host, type);
    for (const note of answer.notes) context.notes.add(note);
    if (kind === 'mx') spent += 0;

    if (unresolved(answer.status)) {
      context.complete = false;
      blame(context, 'DNS');
      push(context, domain, depth, term.raw, term.qualifier, 'error',
        `DNS did not answer for ${host}, so the result cannot be decided.`, spent);
      return 'temperror';
    }
    if (kind === 'a' && answer.isVoid) context.voidLookups += 1;

    for (const record of answer.records) found.push(record.data);
  }

  for (const candidate of found) {
    const value = context.ipVersion === 4 ? toBig(ipv4ToInt(candidate)) : ipv6ToBigInt(candidate);
    if (value === null) continue;
    if (inNetwork(context.ipValue, value, prefix, bits)) {
      push(context, domain, depth, term.raw, term.qualifier, 'match',
        prefix === bits
          ? `${target} resolves to ${candidate}, which is the address being checked.`
          : `${target} resolves to ${candidate}, and ${context.ip} is inside its /${prefix}.`,
        spent);
      return 'match';
    }
  }

  push(context, domain, depth, term.raw, term.qualifier, 'no-match',
    found.length === 0
      ? `${target} has no ${type} record, so nothing here can match.`
      : `${target} resolves to ${found.slice(0, 4).join(', ')}${found.length > 4 ? ` and ${found.length - 4} more` : ''}, none of which is ${context.ip}.`,
    spent);
  return 'no-match';
}

/**
 * `exists:` (§5.7) — an A lookup on an expanded name, matching if anything
 * answers. This is where knowing the IP earns its keep: the name usually
 * carries `%{i}`, so it is a different query for every sender and nothing that
 * merely reads a record can tell you what it does.
 */
async function matchExists(
  context: Ctx,
  domain: string,
  depth: number,
  term: SpfMechanism,
): Promise<MechanismOutcome> {
  const target = expand(context, term.value ?? '', domain);
  if (target === null) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'This mechanism contains a macro that cannot be expanded for this connection.', 0);
    blame(context, 'MACRO');
    return 'error';
  }
  if (!spendLookup(context)) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      `Over the limit of ${MAX_LOOKUPS} DNS lookups, so a receiver stops here with a permanent error.`, 0);
    return 'error';
  }

  // Always an A query, even for an IPv6 connection (§5.7).
  const answer = await context.resolver.query(target, 'A');
  for (const note of answer.notes) context.notes.add(note);

  if (unresolved(answer.status)) {
    context.complete = false;
    blame(context, 'DNS');
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      `DNS did not answer for ${target}, so the result cannot be decided.`, 1);
    return 'temperror';
  }
  if (answer.isVoid) context.voidLookups += 1;

  const matched = answer.records.length > 0;
  push(context, domain, depth, term.raw, term.qualifier, matched ? 'match' : 'no-match',
    matched
      ? `${target} exists, which this mechanism treats as a match.`
      : `${target} does not exist, so this does not match.`,
    1);
  return matched ? 'match' : 'no-match';
}

/**
 * `ptr` (§5.5). RFC 7208 tells senders not to publish it and receivers that it
 * is slow, and then requires it to work anyway. Evaluated properly: reverse the
 * address, forward-confirm every name that comes back, and match a name that is
 * the target or a subdomain of it.
 */
async function matchPtr(
  context: Ctx,
  domain: string,
  depth: number,
  term: SpfMechanism,
): Promise<MechanismOutcome> {
  const target = term.value === null ? domain : expand(context, term.value, domain);
  if (target === null) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'This mechanism contains a macro that cannot be expanded here.', 0);
    blame(context, 'MACRO');
    return 'error';
  }
  if (!spendLookup(context)) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      `Over the limit of ${MAX_LOOKUPS} DNS lookups, so a receiver stops here with a permanent error.`, 0);
    return 'error';
  }

  const reverse = await context.resolver.query(reverseName(context.ip, context.ipVersion), 'PTR');
  for (const note of reverse.notes) context.notes.add(note);
  if (unresolved(reverse.status)) {
    context.complete = false;
    blame(context, 'DNS');
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      `The reverse lookup for ${context.ip} did not answer, so the result cannot be decided.`, 1);
    return 'temperror';
  }

  const names = reverse.records
    .map((record) => record.data.replace(/\.$/, '').toLowerCase())
    .filter(Boolean)
    .slice(0, MAX_NAMES_PER_MECHANISM);

  if (names.length === 0) {
    push(context, domain, depth, term.raw, term.qualifier, 'no-match',
      `${context.ip} has no reverse DNS name, so this cannot match.`, 1);
    return 'no-match';
  }

  const suffix = target.toLowerCase();
  const type = context.ipVersion === 4 ? 'A' : 'AAAA';

  for (const candidate of names) {
    if (candidate !== suffix && !candidate.endsWith(`.${suffix}`)) continue;
    if (context.resolver.remainingBudget <= 1) {
      context.complete = false;
      blame(context, 'DNS');
      push(context, domain, depth, term.raw, term.qualifier, 'error',
        'We ran out of query budget before the reverse name could be confirmed.', 1);
      return 'temperror';
    }

    // Forward-confirm: the name must resolve back to the address (§5.5).
    const forward = await context.resolver.query(candidate, type);
    for (const note of forward.notes) context.notes.add(note);
    const confirmed = forward.records.some((record) => {
      const value = context.ipVersion === 4 ? toBig(ipv4ToInt(record.data)) : ipv6ToBigInt(record.data);
      return value !== null && value === context.ipValue;
    });

    if (confirmed) {
      push(context, domain, depth, term.raw, term.qualifier, 'match',
        `${context.ip} reverses to ${candidate}, which resolves back to it and is under ${target}.`, 1);
      return 'match';
    }
  }

  push(context, domain, depth, term.raw, term.qualifier, 'no-match',
    `${context.ip} reverses to ${names.slice(0, 3).join(', ')}, none of which forward-confirms under ${target}.`, 1);
  return 'no-match';
}

/**
 * `include:` (§5.2). The recursion's result is *not* the outer result: only a
 * pass counts as a match, and anything else moves evaluation on to the next
 * term. Getting this backwards is the single most common bug in SPF checkers,
 * and it turns every domain that includes a vendor into a fail.
 */
async function matchInclude(
  context: Ctx,
  domain: string,
  depth: number,
  term: SpfMechanism,
): Promise<MechanismOutcome> {
  const target = expand(context, term.value ?? '', domain);
  if (target === null) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      'This mechanism contains a macro that cannot be expanded here.', 0);
    blame(context, 'MACRO');
    return 'error';
  }
  if (!spendLookup(context)) {
    push(context, domain, depth, term.raw, term.qualifier, 'error',
      `Over the limit of ${MAX_LOOKUPS} DNS lookups, so a receiver stops here with a permanent error.`, 0);
    return 'error';
  }

  push(context, domain, depth, term.raw, term.qualifier, 'no-match',
    `Following the include into ${target}.`, 1);
  const inner = context.trace.length - 1;

  const result = await checkHost(context, target, depth + 1);
  const step = context.trace[inner] as SpfEvalStep;

  if (result === 'pass') {
    step.outcome = 'match';
    step.detail = `${target} authorises ${context.ip}, so this include matches.`;
    return 'match';
  }
  if (result === 'temperror') {
    step.outcome = 'error';
    step.detail = `${target} could not be resolved, so the result cannot be decided.`;
    return 'temperror';
  }
  // §5.2: none and permerror inside an include are a permanent error outside it.
  if (result === 'none' || result === 'permerror') {
    step.outcome = 'error';
    step.detail =
      result === 'none'
        ? `${target} publishes no SPF record, which makes this include a permanent error.`
        : `${target} has a permanent error, which this include inherits.`;
    if (result === 'none') blame(context, 'MISSING_TARGET');
    return 'error';
  }

  step.detail = `${target} does not authorise ${context.ip}, so evaluation moves on.`;
  return 'no-match';
}

/* Plumbing ----------------------------------------------------------------- */

interface RecordRead {
  status: 'ok' | 'none' | 'permerror' | 'temperror';
  value: string;
}

async function readSpfRecord(context: Ctx, domain: string): Promise<RecordRead> {
  const result = await context.resolver.query(domain, 'TXT');
  for (const note of result.notes) context.notes.add(note);

  if (unresolved(result.status)) {
    context.complete = false;
    blame(context, 'DNS');
    return { status: 'temperror', value: '' };
  }

  const records = result.txt.map((txt) => txt.value).filter(isSpfRecord);
  if (records.length === 0) return { status: 'none', value: '' };
  // More than one SPF record is a permanent error (§4.5), not a choice.
  if (records.length > 1) {
    blame(context, 'MULTIPLE_RECORDS');
    return { status: 'permerror', value: '' };
  }

  return { status: 'ok', value: records[0] as string };
}

function findRedirect(terms: readonly SpfTerm[]): string | null {
  for (const term of terms) {
    if (term.kind === 'modifier' && term.name === 'redirect') return term.value;
  }
  return null;
}

/**
 * Charge one lookup against the limit of ten. False once it is spent.
 *
 * The cause is recorded here rather than at each call site. Five mechanisms
 * spend lookups and every one of them has to report the same reason for the
 * same refusal; recording it once is what stops the fifth being forgotten.
 */
function spendLookup(context: Ctx): boolean {
  if (context.lookups >= MAX_LOOKUPS) {
    blame(context, 'LOOKUP_LIMIT');
    return false;
  }
  context.lookups += 1;
  return true;
}

function expand(context: Ctx, value: string, domain: string): string | null {
  if (!value.includes('%')) return value.trim().replace(/\.$/, '').toLowerCase();

  const macroContext: MacroContext = {
    ip: context.ip,
    ipVersion: context.ipVersion,
    domain,
    sender: context.sender,
    helo: context.helo,
  };
  const expanded = expandMacros(value, macroContext);
  if (!expanded.ok) return null;
  return expanded.value.trim().replace(/\.$/, '').toLowerCase();
}

/**
 * The prefix this mechanism applies, given the address family. A dual-CIDR
 * mechanism carries both, and only the one matching the connection is used.
 */
function prefixFor(context: Ctx, term: SpfMechanism): number | null {
  if (context.ipVersion === 4) {
    return term.cidr4 === null ? 32 : Number(term.cidr4);
  }
  return term.cidr6 === null ? 128 : Number(term.cidr6);
}

function inNetwork(address: bigint, network: bigint, prefix: number, bits: number): boolean {
  if (prefix === 0) return true;
  const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  return (address & mask) === (network & mask);
}

function unresolved(status: string): boolean {
  return status === 'TIMEOUT' || status === 'ERROR' || status === 'SERVFAIL' || status === 'REFUSED';
}

/** `10 mail.example.com` — an MX rdata is a priority and a name. */
function mxTarget(data: string): string | null {
  const parts = data.trim().split(/\s+/);
  const host = parts.length > 1 ? parts[parts.length - 1] : parts[0];
  if (!host) return null;
  const clean = host.replace(/\.$/, '').toLowerCase();
  return clean === '' || clean === '.' ? null : clean;
}

function toBig(value: number | null): bigint | null {
  return value === null ? null : BigInt(value);
}

/** The name under `in-addr.arpa` or `ip6.arpa` that reverses this address. */
function reverseName(ip: string, version: 4 | 6): string {
  if (version === 4) {
    return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  }
  const value = ipv6ToBigInt(ip);
  if (value === null) return `${ip}.ip6.arpa`;
  const nibbles = value.toString(16).padStart(32, '0').split('').reverse().join('.');
  return `${nibbles}.ip6.arpa`;
}

/**
 * An IPv4-mapped IPv6 address is an IPv4 sender.
 *
 * A dual-stack receiver reports `::ffff:203.0.113.9` for a client that
 * connected over IPv4, and SPF matches it against `ip4:` mechanisms. Treating
 * it as IPv6 would report "not authorised" for a sender that is plainly listed.
 */
function normalizeIp(raw: string): { ip: string; version: 4 | 6; value: bigint } | null {
  const trimmed = raw.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (trimmed === '') return null;

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(trimmed);
  const candidate = mapped ? (mapped[1] as string) : trimmed;

  if (isValidIpv4(candidate)) {
    const value = ipv4ToInt(candidate);
    return value === null ? null : { ip: candidate, version: 4, value: BigInt(value) };
  }
  if (isValidIpv6(trimmed)) {
    const value = ipv6ToBigInt(trimmed);
    return value === null ? null : { ip: trimmed, version: 6, value };
  }
  return null;
}

function push(
  context: Ctx,
  domain: string,
  depth: number,
  term: string,
  qualifier: Qualifier,
  outcome: SpfEvalStep['outcome'],
  detail: string,
  lookups: number,
): void {
  context.trace.push({ domain, depth, term, qualifier, outcome, detail, lookups });
}

/** One sentence naming the cause, in the voice the rest of the clinic uses. */
function summarize(result: SpfResult, context: Ctx, domain: string): string {
  // The deciding term, not the first match in the trace: an include that did
  // not pass still matched something on its way to not passing.
  const matched = context.decided;
  const where = matched && matched.domain !== domain ? ` (via ${matched.domain})` : '';

  switch (result) {
    case 'pass':
      return `${context.ip} is authorised to send as ${domain}. The mechanism that decided it was ${matched?.term ?? 'all'}${where}.`;
    case 'fail':
      return `${context.ip} is not authorised to send as ${domain}, and the record says to reject that mail. ${matched?.term ?? '-all'}${where} decided it.`;
    case 'softfail':
      return `${context.ip} is not authorised to send as ${domain}, and the record asks receivers to accept the mail and mark it. ${matched?.term ?? '~all'}${where} decided it.`;
    case 'neutral':
      return `${domain} says nothing either way about ${context.ip}. Receivers treat that as no policy at all.`;
    case 'none':
      return `${domain} publishes no SPF record, so there is nothing to authorise ${context.ip}.`;
    case 'permerror':
      return permerrorSummary(context, domain);
    case 'temperror':
      return `A DNS lookup did not answer, so the result for ${context.ip} cannot be decided right now. This is a temporary condition, not a verdict.`;
  }
}

/**
 * A permanent error, named precisely.
 *
 * The generic sentence — "your record cannot be evaluated" — is true of a
 * record over the lookup limit and false of a record that merely ran out of
 * void lookups for one address. Records built on `exists:` with macros perform
 * a lookup per connecting address by design, so three empty answers is the
 * expected outcome for an address the domain never authorised, and the record
 * delivers perfectly well for the senders it does authorise. Somebody told the
 * generic sentence would go and rewrite a working record.
 */
function permerrorSummary(context: Ctx, domain: string): string {
  switch (context.cause) {
    case 'LOOKUP_LIMIT':
      return `${domain} costs more than ${MAX_LOOKUPS} DNS lookups, so a receiver gives up before reaching an answer. SPF fails for every sender, including ${domain}'s own mail servers.`;
    case 'VOID_LIMIT':
      return `More than ${MAX_VOID_LOOKUPS} lookups came back empty while checking ${context.ip}, which a receiver treats as a permanent error. This one is about this address: ${domain} performs a lookup per sender, and an address it does not know produces empty answers by design.`;
    case 'MULTIPLE_RECORDS':
      return `${domain} publishes more than one SPF record, which receivers refuse to choose between. SPF fails for every sender until one of them is removed.`;
    case 'MISSING_TARGET':
      return `${domain} points at a name that publishes no SPF record, which is a permanent error however the rest of the record reads. SPF fails for every sender.`;
    case 'LOOP':
      return `${domain} refers back to itself, so a receiver would walk forever and stops instead. SPF fails for every sender.`;
    case 'MACRO':
      return `${domain} uses a macro a receiver cannot expand for this connection, so the record cannot be evaluated against ${context.ip}.`;
    case 'SYNTAX':
    default:
      return `${domain} has a mechanism a receiver cannot parse, which makes the whole record a permanent error. SPF fails for every sender.`;
  }
}
